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
import java.lang.foreign.Arena;
import java.lang.invoke.MethodHandle;
import java.util.Objects;

public class FridaNativeUtils {

    private static final MethodHandle FRIDA_UNREF;
    private static final MethodHandle G_BYTES_NEW;
    private static final MethodHandle G_OBJECT_UNREF;
    private static final MethodHandle G_OBJECT_REF;

    static {
        FRIDA_UNREF = FridaLibraryLoader.findFunction("frida_unref",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        G_BYTES_NEW = FridaLibraryLoader.findFunction("g_bytes_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
        G_OBJECT_UNREF = FridaLibraryLoader.findFunction("g_object_unref",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        G_OBJECT_REF = FridaLibraryLoader.findFunction("g_object_ref",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
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
     * Convert byte array to GBytes
     * @param data byte array to convert
     * @param arena Arena for memory allocation
     * @return GBytes pointer
     */
    public static MemorySegment bytesToGBytes(byte[] data, Arena arena) {
        try {
            MemorySegment dataPtr = arena.allocate(data.length);
            dataPtr.copyFrom(MemorySegment.ofArray(data));
            return (MemorySegment) G_BYTES_NEW.invoke(dataPtr, data.length);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to convert bytes to GBytes", e);
        }
    }

    /**
     * Reference a GObject (increase reference count)
     * @param object GObject pointer
     * @return The same pointer (for convenience)
     */
    public static MemorySegment gObjectRef(MemorySegment object) {
        try {
            return (MemorySegment) G_OBJECT_REF.invoke(object);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to ref GObject", e);
        }
    }

    /**
     * Unreference a GObject (decrease reference count)
     * @param object GObject pointer
     */
    public static void gObjectUnref(MemorySegment object) {
        try {
            G_OBJECT_UNREF.invoke(object);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to unref GObject", e);
        }
    }
}
