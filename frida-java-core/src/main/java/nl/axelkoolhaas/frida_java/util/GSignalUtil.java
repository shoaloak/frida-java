/*
 * Copyright (C) 2026 Axel Koolhaas
 *
 * This file is part of frida-java.
 *
 * frida-java is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * frida-java is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with frida-java.  If not, see <https://www.gnu.org/licenses/>.
 */

package nl.axelkoolhaas.frida_java.util;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.frida.FridaException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

public class GSignalUtil {
    private static final Logger log = LoggerFactory.getLogger(GSignalUtil.class);

    private static final MethodHandle G_SIGNAL_LOOKUP;
    private static final MethodHandle G_SIGNAL_CONNECT_CLOSURE_BY_ID;
    private static final MethodHandle G_SIGNAL_CONNECT_DATA;
    private static final MethodHandle G_CLOSURE_NEW_SIMPLE;
    private static final MethodHandle G_CLOSURE_SET_MARSHAL;

    // sizeof(GClosure) - the struct size needed for g_closure_new_simple
    // GClosure contains bit fields and pointers, on 64-bit systems it's typically 32 bytes
    private static final int SIZEOF_GCLOSURE = 32;

    static {
        G_SIGNAL_LOOKUP = FridaLibraryLoader.findFunction("g_signal_lookup",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

        G_SIGNAL_CONNECT_CLOSURE_BY_ID = FridaLibraryLoader.findFunction("g_signal_connect_closure_by_id",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_BOOLEAN));

        G_SIGNAL_CONNECT_DATA = FridaLibraryLoader.findFunction("g_signal_connect_data",
                FunctionDescriptor.of(
                        ValueLayout.JAVA_LONG,     // returns gulong handler_id
                        ValueLayout.ADDRESS,       // instance (GObject*)
                        ValueLayout.ADDRESS,       // detailed_signal (const gchar*)
                        ValueLayout.ADDRESS,       // c_handler (GCallback)
                        ValueLayout.ADDRESS,       // data (gpointer)
                        ValueLayout.ADDRESS,       // destroy_data (GClosureNotify)
                        ValueLayout.JAVA_INT       // connect_flags (GConnectFlags)
                ));

        G_CLOSURE_NEW_SIMPLE = FridaLibraryLoader.findFunction("g_closure_new_simple",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

        G_CLOSURE_SET_MARSHAL = FridaLibraryLoader.findFunction("g_closure_set_marshal",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /**
     * Get the GType from a GObject.
     * Replaces the C macro: G_OBJECT_TYPE(obj) which accesses ((GTypeInstance*)obj)->g_class->g_type
     */
    public static long getObjectType(MemorySegment object) {
        FridaNativeUtils.requireValidPointer(object, "GObject");

        // Reinterpret the segment to have sufficient size for reading
        // GObject inherits from GTypeInstance
        // GTypeInstance has g_class as first field (pointer)
        // GTypeClass has g_type as first field (GType/size_t)
        MemorySegment objectSegment = object.reinterpret(ValueLayout.ADDRESS.byteSize());
        MemorySegment gClass = objectSegment.get(ValueLayout.ADDRESS, 0);
        FridaNativeUtils.requireValidPointer(gClass, "GTypeClass");

        MemorySegment gClassSegment = gClass.reinterpret(ValueLayout.JAVA_LONG.byteSize());
        return gClassSegment.get(ValueLayout.JAVA_LONG, 0);
    }

    /**
     * Lookup a signal ID by name and object type.
     *
     * @param object The GObject instance
     * @param signalName The signal name
     * @return Signal ID, or 0 if not found
     */
    public static int lookupSignal(MemorySegment object, String signalName) {
        FridaNativeUtils.requireValidPointer(object, "object");
        if (signalName == null || signalName.trim().isEmpty()) {
            throw new IllegalArgumentException("Signal name cannot be null or empty");
        }

        try (Arena arena = Arena.ofConfined()) {
            long objectType = getObjectType(object);
            MemorySegment signalNamePtr = arena.allocateFrom(signalName);
            int signalId = (int) G_SIGNAL_LOOKUP.invoke(signalNamePtr, objectType);
            log.debug("Signal lookup '{}' on type {} returned ID {}", signalName, objectType, signalId);
            return signalId;
        } catch (Throwable e) {
            log.error("Failed to lookup signal '{}': {}", signalName, e.getMessage());
            throw new FridaException("Failed to lookup signal: " + signalName, e);
        }
    }

    /**
     * Create a new GClosure with a custom marshal function.
     * This is equivalent to Go's newClosure() which calls:
     *   g_closure_new_simple(sizeof(GClosure), NULL)
     *   g_closure_set_marshal(closure, marshal)
     *
     * @param marshalFunc The marshal function pointer (upcall stub)
     * @return The GClosure pointer
     */
    public static MemorySegment createClosureWithMarshal(MemorySegment marshalFunc) {
        FridaNativeUtils.requireValidPointer(marshalFunc, "marshalFunc");

        try {
            // Create simple closure: g_closure_new_simple(sizeof_closure, data)
            MemorySegment closure = (MemorySegment) G_CLOSURE_NEW_SIMPLE.invoke(
                    SIZEOF_GCLOSURE,
                    MemorySegment.NULL  // user_data
            );

            if (closure == null || closure.equals(MemorySegment.NULL)) {
                throw new FridaException("g_closure_new_simple returned NULL");
            }

            log.trace("Created GClosure at {}", closure);

            // Set the marshal function: g_closure_set_marshal(closure, marshal)
            G_CLOSURE_SET_MARSHAL.invoke(closure, marshalFunc);

            log.trace("Set marshal function {} on GClosure {}", marshalFunc, closure);

            return closure;
        } catch (FridaException e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to create GClosure with marshal", e);
        }
    }

    /**
     * Connect a GClosure to a signal by ID.
     *
     * @param object The GObject instance
     * @param signalId The signal ID (from lookupSignal)
     * @param closure The GClosure to connect
     * @param after Whether to connect after the default handler
     * @return Handler ID for the connection
     */
    public static long connectClosureById(MemorySegment object, int signalId, MemorySegment closure, boolean after) {
        FridaNativeUtils.requireValidPointer(object, "object");
        FridaNativeUtils.requireValidPointer(closure, "closure");

        if (signalId == 0) {
            log.debug("Signal ID is 0, not connecting");
            return 0;
        }

        try {
            long handlerId = (long) G_SIGNAL_CONNECT_CLOSURE_BY_ID.invoke(
                    object,
                    signalId,
                    0,        // detail (GQuark, 0 for none)
                    closure,
                    after     // after flag
            );

            log.debug("g_signal_connect_closure_by_id returned handler ID: {}", handlerId);
            return handlerId;
        } catch (Throwable e) {
            log.error("Failed to connect closure by ID: {}", e.getMessage());
            throw new FridaException("Failed to connect closure by ID", e);
        }
    }

//    /**
//     * Connect a closure to a GObject signal
//     */
//    public static long connectSignal(MemorySegment object, String signalName, MemorySegment closure) {
//        FridaNativeUtils.requireValidPointer(object, "object");
//        FridaNativeUtils.requireValidPointer(closure, "closure");
//        if (signalName == null || signalName.trim().isEmpty()) {
//            throw new IllegalArgumentException("Signal name cannot be null or empty");
//        }
//
//        try (Arena arena = Arena.ofConfined()) {
//            // Get GObject type using struct field access
//            long objectType = getObjectType(object);
//
//            // Step 2: Lookup signal ID
//            MemorySegment signalNamePtr = arena.allocateFrom(signalName);
//            int signalId = (int) G_SIGNAL_LOOKUP.invoke(signalNamePtr, objectType);
//
//            if (signalId == 0) {
//                log.debug("Signal '{}' not found on object", signalName);
//                return 0;
//            }
//
//            // Step 3: Connect by ID
//            return (long) G_SIGNAL_CONNECT_CLOSURE_BY_ID.invoke(
//                    object,           // instance
//                    signalId,         // signal_id
//                    0,               // detail (0 for no detail)
//                    closure,          // closure
//                    true             // after (connect after default handler)
//            );
//        } catch (Throwable e) {
//            log.error("Failed to connect signal '{}': {}", signalName, e.getMessage());
//            throw new FridaException("Failed to connect signal: " + signalName, e);
//        }
//    }

    /**
     * Connect a callback to a GObject signal using g_signal_connect_data
     */
    public static long connectSignal(MemorySegment instance, String signalName, MemorySegment callback) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment signalNameNative = arena.allocateFrom(signalName);

            long handlerId = (long) G_SIGNAL_CONNECT_DATA.invoke(
                    instance,
                    signalNameNative,
                    callback,              // GCallback (function pointer)
                    MemorySegment.NULL,    // user_data
                    MemorySegment.NULL,    // destroy_data
                    0                      // flags (0 = G_CONNECT_DEFAULT)
            );

            log.debug("g_signal_connect_data returned handler ID: {}", handlerId);
            return handlerId;
        } catch (Throwable e) {
            log.error("Failed to connect signal '{}': {}", signalName, e.getMessage());
            throw new FridaException("Failed to connect signal: " + signalName, e);
        }
    }
}
