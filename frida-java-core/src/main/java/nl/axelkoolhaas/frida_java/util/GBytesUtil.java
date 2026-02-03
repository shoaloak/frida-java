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

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * Utility methods for working with GLib GBytes structures.
 */
public class GBytesUtil {

    private static final MethodHandle G_BYTES_NEW;
    private static final MethodHandle G_BYTES_GET_SIZE;
    private static final MethodHandle G_BYTES_GET_DATA;
    // THESE SHOULD NOT BE USED
    //private static final MethodHandle G_BYTES_UNREF;
    //private static final MethodHandle G_BYTES_REF;

    static {
        G_BYTES_NEW = FridaLibraryLoader.findFunction("g_bytes_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
        G_BYTES_GET_SIZE = FridaLibraryLoader.findFunction("g_bytes_get_size",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        G_BYTES_GET_DATA = FridaLibraryLoader.findFunction("g_bytes_get_data",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    private GBytesUtil() {
        // Utility class - prevent instantiation
    }

    /**
     * Convert byte array to GBytes
     * @param data byte array to convert
     * @param arena Arena for memory allocation
     * @return GBytes pointer
     */
    public static MemorySegment fromByteArray(byte[] data, Arena arena) {
        try {
            MemorySegment dataPtr = arena.allocate(data.length);
            dataPtr.copyFrom(MemorySegment.ofArray(data));
            // Cast to long for FFM binding (Java arrays are limited to int length anyway)
            return (MemorySegment) G_BYTES_NEW.invoke(dataPtr, (long) data.length);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new nl.axelkoolhaas.frida_java.frida.FridaException("Failed to convert bytes to GBytes", e);
        }
    }

    /**
     * Extract byte array from GBytes pointer.
     *
     * @param gBytesPtr Pointer to GBytes structure (may be null)
     * @return Byte array containing the data, or empty array if null/empty
     */
    public static byte[] toByteArray(MemorySegment gBytesPtr) {
        if (gBytesPtr == null || gBytesPtr.equals(MemorySegment.NULL)) {
            return new byte[0];
        }

        try {
            // Get the size of the GBytes data
            long size = (long) G_BYTES_GET_SIZE.invoke(gBytesPtr);
            if (size == 0) {
                return new byte[0];
            }

            // Get the data pointer (second parameter is optional size output, we pass NULL)
            MemorySegment dataPtr = (MemorySegment) G_BYTES_GET_DATA.invoke(gBytesPtr, MemorySegment.NULL);
            if (dataPtr == null || dataPtr.equals(MemorySegment.NULL)) {
                return new byte[0];
            }

            // Read the bytes from the native memory
            return dataPtr.reinterpret(size).toArray(ValueLayout.JAVA_BYTE);
        } catch (Throwable e) {
            System.err.println("Failed to extract GBytes data: " + e.getMessage());
            return new byte[0];
        }
    }
}
