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

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.Objects;

public class FridaNativeUtils {

    private static final MethodHandle FRIDA_UNREF;

    static {
        FRIDA_UNREF = FridaLibraryLoader.findFunction("frida_unref",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
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
}
