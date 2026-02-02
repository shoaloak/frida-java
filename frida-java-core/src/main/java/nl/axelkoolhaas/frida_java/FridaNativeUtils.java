/*
 * Copyright (C) 2025 Axel Koolhaas
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

package nl.axelkoolhaas.frida_java;

import nl.axelkoolhaas.frida_java.frida.Closure;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.foreign.Arena;
import java.lang.invoke.MethodHandle;
import java.util.Objects;

public class FridaNativeUtils {

    private static final MethodHandle FRIDA_UNREF;
    private static final MethodHandle G_SIGNAL_LOOKUP;
    private static final MethodHandle G_SIGNAL_CONNECT_DATA;
    private static final MethodHandle FRIDA_SCRIPT_GET_TYPE;

    static {
        FRIDA_UNREF = FridaLibraryLoader.findFunction("frida_unref",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        G_SIGNAL_LOOKUP = FridaLibraryLoader.findFunction("g_signal_lookup",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
        G_SIGNAL_CONNECT_DATA = FridaLibraryLoader.findFunction("g_signal_connect_data",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_SCRIPT_GET_TYPE = FridaLibraryLoader.findFunction("frida_script_get_type",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG));
    }

    /**
     * Validate that a native pointer is not null or NULL
     * @param ptr The memory segment to validate
     * @param name The name for error messages
     * @return The validated pointer
     * @throws IllegalArgumentException if pointer is null or NULL
     */
    public static MemorySegment requireValidPointer(MemorySegment ptr, String name) {
        Objects.requireNonNull(ptr, name + " cannot be null");
        if (ptr.equals(MemorySegment.NULL)) {
            throw new IllegalArgumentException(name + " cannot be NULL");
        }
        return ptr;
    }

    /**
     * Helper method to safely convert a MemorySegment to a UTF-8 string
     * @param segment the memory segment to convert
     * @return the string value, or empty string if segment is NULL
     */
    public static String memorySegmentToString(MemorySegment segment) {
        if (segment.equals(MemorySegment.NULL)) {
            return "";
        }
        // Read the C string using UTF-8 encoding, searching for null terminator
        return segment.reinterpret(Long.MAX_VALUE)
                .getString(0, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Call frida_unref on a pointer
     * Note that this will call g_object_unref under the hood
     * @param object the GObject memory segment
     */
    public static void fridaUnref(MemorySegment object) {
        try {
            FRIDA_UNREF.invoke(object);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to unref pointer", e);
        }
    }

    /**
     * Connect a Java callback to a GObject signal
     * This is the Java equivalent of the Go connectClosure function
     *
     * @param object GObject pointer to connect to
     * @param signalName Name of the signal to connect to
     * @param callback Java callback object
     */
    public static void connectSignal(MemorySegment object, String signalName, Object callback) {
        try (Arena arena = Arena.ofConfined()) {
            Closure closure = Closure.create(callback, signalName);
            MemorySegment signalNamePtr = arena.allocateFrom(signalName);

            long objectType = (Long) FRIDA_SCRIPT_GET_TYPE.invoke();
            int signalId = (Integer) G_SIGNAL_LOOKUP.invoke(signalNamePtr, objectType);

            if (signalId == 0) {
                throw new RuntimeException("Signal '" + signalName + "' not found on object type " + objectType);
            }

            G_SIGNAL_CONNECT_DATA.invoke(
                    object,                          // instance
                    signalNamePtr,                   // detailed_signal
                    closure.getNativeCallback(),     // c_handler
                    MemorySegment.NULL,              // data
                    MemorySegment.NULL,              // destroy_data
                    0                                // connect_flags (0 = G_CONNECT_DEFAULT)
            );
        } catch (Throwable e) {
            throw new RuntimeException("Failed to connect signal: " + signalName, e);
        }
    }
}
