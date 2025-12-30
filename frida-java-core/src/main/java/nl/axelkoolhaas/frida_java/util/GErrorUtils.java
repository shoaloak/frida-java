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

package nl.axelkoolhaas.frida_java.util;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * Utility class for handling GError objects from GLib/Frida
 */
public class GErrorUtils {

    private static final MethodHandle G_ERROR_GET_MESSAGE;
    private static final MethodHandle G_ERROR_FREE;

    static {
        G_ERROR_GET_MESSAGE = FridaLibraryLoader.findFunction("g_error_get_message",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        G_ERROR_FREE = FridaLibraryLoader.findFunction("g_error_free",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    }

    /**
     * Get the error message from a GError
     * @param error GError pointer
     * @return Error message string
     */
    public static String getMessage(MemorySegment error) {
        try {
            MemorySegment messagePtr = (MemorySegment) G_ERROR_GET_MESSAGE.invoke(error);
            return FridaNativeUtils.memorySegmentToString(messagePtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get error message", e);
        }
    }

    /**
     * Free a GError
     * @param error GError pointer to free
     */
    public static void free(MemorySegment error) {
        try {
            G_ERROR_FREE.invoke(error);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to free GError", e);
        }
    }

    /**
     * Check if error is not NULL, get message, free it, and throw RuntimeException
     * @param error GError pointer to check
     * @param operation Description of the operation that failed
     * @throws RuntimeException if error is not NULL
     */
    public static void checkAndThrow(MemorySegment error, String operation) {
        if (!error.equals(MemorySegment.NULL)) {
            String errorMsg = getMessage(error);
            free(error);
            throw new RuntimeException("Failed to " + operation + ": " + errorMsg);
        }
    }

    /**
     * Check if error is not NULL, get message, free it, and return the message
     * @param error GError pointer to check
     * @return Error message string, or null if no error
     */
    public static String checkAndGetMessage(MemorySegment error) {
        if (!error.equals(MemorySegment.NULL)) {
            String errorMsg = getMessage(error);
            free(error);
            return errorMsg;
        }
        return null;
    }

    private GErrorUtils() {
        // Utility class - prevent instantiation
    }
}
