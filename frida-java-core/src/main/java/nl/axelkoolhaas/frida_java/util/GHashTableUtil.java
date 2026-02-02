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

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for converting GLib GHashTable instances to Java Maps
 */
public class GHashTableUtil {

    private static final MethodHandle G_HASH_TABLE_GET_KEYS;
    private static final MethodHandle G_HASH_TABLE_LOOKUP;
    private static final MethodHandle G_LIST_LENGTH;
    private static final MethodHandle G_LIST_NTH_DATA;
    private static final MethodHandle G_VALUE_TYPE;
    private static final MethodHandle G_VALUE_GET_STRING;
    private static final MethodHandle G_VALUE_GET_INT;
    private static final MethodHandle G_VALUE_GET_BOOLEAN;
    private static final MethodHandle G_VALUE_GET_POINTER;

    // GType constants (from GLib)
    private static final long G_TYPE_STRING = 64;   // G_TYPE_MAKE_FUNDAMENTAL(16)
    private static final long G_TYPE_INT = 24;      // G_TYPE_MAKE_FUNDAMENTAL(6)
    private static final long G_TYPE_BOOLEAN = 20;  // G_TYPE_MAKE_FUNDAMENTAL(5)
    private static final long G_TYPE_POINTER = 68;  // G_TYPE_MAKE_FUNDAMENTAL(17)

    static {
        // GHashTable and GList functions
        G_HASH_TABLE_GET_KEYS = FridaLibraryLoader.findFunction("g_hash_table_get_keys",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        G_HASH_TABLE_LOOKUP = FridaLibraryLoader.findFunction("g_hash_table_lookup",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        G_LIST_LENGTH = FridaLibraryLoader.findFunction("g_list_length",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        G_LIST_NTH_DATA = FridaLibraryLoader.findFunction("g_list_nth_data",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        // GValue type checking and extraction functions
        G_VALUE_TYPE = FridaLibraryLoader.findFunction("g_value_type",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        G_VALUE_GET_STRING = FridaLibraryLoader.findFunction("g_value_get_string",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        G_VALUE_GET_INT = FridaLibraryLoader.findFunction("g_value_get_int",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        G_VALUE_GET_BOOLEAN = FridaLibraryLoader.findFunction("g_value_get_boolean",
                FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
        G_VALUE_GET_POINTER = FridaLibraryLoader.findFunction("g_value_get_pointer",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    private GHashTableUtil() {
        // Utility class - prevent instantiation
    }

    /**
     * Convert a GHashTable to a Java Map
     * @param hashTable the GHashTable memory segment
     * @return Map containing the key-value pairs
     */
    public static Map<String, Object> toMap(MemorySegment hashTable) {
        if (hashTable.equals(MemorySegment.NULL)) {
            return new HashMap<>();
        }

        try {
            // Get the list of keys
            MemorySegment keysList = (MemorySegment) G_HASH_TABLE_GET_KEYS.invoke(hashTable);
            if (keysList.equals(MemorySegment.NULL)) {
                return new HashMap<>();
            }

            // Get the number of keys
            int length = (int) G_LIST_LENGTH.invoke(keysList);
            Map<String, Object> result = new HashMap<>(length);

            // Iterate through the keys
            for (int i = 0; i < length; i++) {
                // Get the key
                MemorySegment keyPtr = (MemorySegment) G_LIST_NTH_DATA.invoke(keysList, i);
                if (keyPtr.equals(MemorySegment.NULL)) {
                    continue;
                }

                String key = FridaNativeUtils.memorySegmentToString(keyPtr);

                // Get the value for this key
                MemorySegment valuePtr = (MemorySegment) G_HASH_TABLE_LOOKUP.invoke(hashTable, keyPtr);

                // Convert value to appropriate Java type
                Object value = convertValueToJavaObject(valuePtr);
                result.put(key, value);
            }

            return result;
        } catch (Throwable e) {
            throw new RuntimeException("Failed to convert GHashTable to Map", e);
        }
    }

    /**
     * Convert a value pointer to a Java object
     * This handles both GValue and direct value cases
     * @param valuePtr the value memory segment
     * @return the converted Java object
     */
    private static Object convertValueToJavaObject(MemorySegment valuePtr) {
        if (valuePtr.equals(MemorySegment.NULL)) {
            return null;
        }

        try {
            // First, try to interpret as a GValue
            Object gValueResult = convertGValue(valuePtr);
            if (gValueResult != null) {
                return gValueResult;
            }

            // If not a GValue, try direct interpretation
            return convertDirectValue(valuePtr);

        } catch (Throwable e) {
            // If all else fails, return the raw memory address as a string
            return "0x" + Long.toHexString(valuePtr.address());
        }
    }

    /**
     * Try to convert a GValue to a Java object
     * @param gValuePtr the GValue memory segment
     * @return the converted object, or null if not a valid GValue
     */
    private static Object convertGValue(MemorySegment gValuePtr) {
        try {
            // Get the type of the GValue
            long gType = (long) G_VALUE_TYPE.invoke(gValuePtr);

            switch ((int) gType) {
                case (int) G_TYPE_STRING:
                    MemorySegment strPtr = (MemorySegment) G_VALUE_GET_STRING.invoke(gValuePtr);
                    return FridaNativeUtils.memorySegmentToString(strPtr);

                case (int) G_TYPE_INT:
                    return (int) G_VALUE_GET_INT.invoke(gValuePtr);

                case (int) G_TYPE_BOOLEAN:
                    return (boolean) G_VALUE_GET_BOOLEAN.invoke(gValuePtr);

                case (int) G_TYPE_POINTER:
                    MemorySegment ptrValue = (MemorySegment) G_VALUE_GET_POINTER.invoke(gValuePtr);
                    if (ptrValue.equals(MemorySegment.NULL)) {
                        return null;
                    }
                    return "0x" + Long.toHexString(ptrValue.address());

                default:
                    // Unknown GValue type, return null to try direct interpretation
                    return null;
            }
        } catch (Throwable e) {
            // Not a valid GValue or error accessing it
            return null;
        }
    }

    /**
     * Try to interpret a memory segment as a direct value (not wrapped in GValue)
     * @param valuePtr the memory segment
     * @return the converted Java object
     */
    private static Object convertDirectValue(MemorySegment valuePtr) {
        try {
            // Try to interpret as a string first (most common case)
            String strValue = FridaNativeUtils.memorySegmentToString(valuePtr);
            if (strValue != null && !strValue.isEmpty()) {
                // Check if it looks like a number
                try {
                    // Try parsing as integer
                    if (strValue.matches("-?\\d+")) {
                        return Integer.parseInt(strValue);
                    }
                    // Try parsing as boolean
                    if (strValue.equalsIgnoreCase("true") || strValue.equalsIgnoreCase("false")) {
                        return Boolean.parseBoolean(strValue);
                    }
                } catch (NumberFormatException ignored) {
                    // Not a number, keep as string
                }
                return strValue;
            }

            // Try as integer (4 bytes)
            try {
                int intValue = valuePtr.get(ValueLayout.JAVA_INT, 0);
                // Simple heuristic: if it's a reasonable integer value, return it
                if (intValue >= -1000000 && intValue <= 1000000) {
                    return intValue;
                }
            } catch (Exception ignored) {
                // Not an integer
            }

            // Try as boolean (1 byte)
            try {
                byte boolValue = valuePtr.get(ValueLayout.JAVA_BYTE, 0);
                if (boolValue == 0 || boolValue == 1) {
                    return boolValue == 1;
                }
            } catch (Exception ignored) {
                // Not a boolean
            }

            // If all else fails, return the raw memory address as a string
            return "0x" + Long.toHexString(valuePtr.address());

        } catch (Throwable e) {
            // Return a representation of the memory address if we can't interpret the value
            return "0x" + Long.toHexString(valuePtr.address());
        }
    }

    /**
     * Check if a memory segment appears to be a valid GValue
     * @param valuePtr the memory segment to check
     * @return true if it appears to be a GValue
     */
    public static boolean isGValue(MemorySegment valuePtr) {
        if (valuePtr.equals(MemorySegment.NULL)) {
            return false;
        }

        try {
            long gType = (long) G_VALUE_TYPE.invoke(valuePtr);
            return gType > 0 && gType < 1000; // Reasonable range for GType values
        } catch (Throwable e) {
            return false;
        }
    }
}
