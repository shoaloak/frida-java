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

    static {
        G_SIGNAL_LOOKUP = FridaLibraryLoader.findFunction("g_signal_lookup",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

        G_SIGNAL_CONNECT_CLOSURE_BY_ID = FridaLibraryLoader.findFunction("g_signal_connect_closure_by_id",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_BOOLEAN));
    }

    /**
     * Get the GType from a GObject.
     * Replaces the C macro: G_OBJECT_TYPE(obj) which accesses ((GTypeInstance*)obj)->g_class->g_type
     */
    private static long getObjectType(MemorySegment object) {
        FridaNativeUtils.requireValidPointer(object, "GObject");

        // GObject inherits from GTypeInstance
        // GTypeInstance has g_class as first field (pointer)
        // GTypeClass has g_type as first field (GType/size_t)
        MemorySegment gClass = object.get(ValueLayout.ADDRESS, 0);
        FridaNativeUtils.requireValidPointer(gClass, "GTypeClass");

        return gClass.get(ValueLayout.JAVA_LONG, 0);
    }

    /**
     * Connect a closure to a GObject signal
     */
    public static long connectSignal(MemorySegment object, String signalName, MemorySegment closure) {
        FridaNativeUtils.requireValidPointer(object, "object");
        FridaNativeUtils.requireValidPointer(closure, "closure");
        if (signalName == null || signalName.trim().isEmpty()) {
            throw new IllegalArgumentException("Signal name cannot be null or empty");
        }

        try (Arena arena = Arena.ofConfined()) {
            // Get GObject type using struct field access
            long objectType = getObjectType(object);

            // Step 2: Lookup signal ID
            MemorySegment signalNamePtr = arena.allocateFrom(signalName);
            int signalId = (int) G_SIGNAL_LOOKUP.invoke(signalNamePtr, objectType);

            if (signalId == 0) {
                log.debug("Signal '{}' not found on object", signalName);
                return 0;
            }

            // Step 3: Connect by ID
            return (long) G_SIGNAL_CONNECT_CLOSURE_BY_ID.invoke(
                    object,           // instance
                    signalId,         // signal_id
                    0,               // detail (0 for no detail)
                    closure,          // closure
                    true             // after (connect after default handler)
            );
        } catch (Throwable e) {
            log.error("Failed to connect signal '{}': {}", signalName, e.getMessage());
            throw new FridaException("Failed to connect signal: " + signalName, e);
        }
    }
}
