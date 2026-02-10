package nl.axelkoolhaas.frida_java.util;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.frida.FridaException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * Utility class for working with GLib GValue structures.
 * Encapsulates type checking and value extraction.
 */
public class GValueUtil {

    private static final Logger log = LoggerFactory.getLogger(GValueUtil.class);

    // private static final MethodHandle G_VALUE_TYPE; // This is a macro, not a function!
    private static final MethodHandle G_VALUE_GET_STRING;
    private static final MethodHandle G_VALUE_GET_INT;
    private static final MethodHandle G_VALUE_GET_UINT;
    private static final MethodHandle G_VALUE_GET_BOOLEAN;
    private static final MethodHandle G_VALUE_GET_POINTER;

    static {
        G_VALUE_GET_STRING = FridaLibraryLoader.findFunction("g_value_get_string",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        G_VALUE_GET_INT = FridaLibraryLoader.findFunction("g_value_get_int",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        G_VALUE_GET_UINT = FridaLibraryLoader.findFunction("g_value_get_uint",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        G_VALUE_GET_BOOLEAN = FridaLibraryLoader.findFunction("g_value_get_boolean",
                FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
        G_VALUE_GET_POINTER = FridaLibraryLoader.findFunction("g_value_get_pointer",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    private GValueUtil() {
        // Utility class
    }

    /**
     * Get the GType from a GValue struct.
     * Replaces the C macro: G_VALUE_TYPE(val) which accesses ((val)->g_type)
     *
     * @param gvalue the GValue memory segment
     * @return the GType value
     */
    public static GType getType(MemorySegment gvalue) {
        FridaNativeUtils.requireValidPointer(gvalue, "GValue");
        try {
            // GValue struct has g_type as the first field (size_t/ulong)
            long typeValue = gvalue.get(ValueLayout.JAVA_LONG, 0);
            return GType.fromValue(typeValue);
        } catch (Throwable e) {
            log.debug("Failed to read GType from GValue", e);
            throw new FridaException("Failed to read GType from GValue", e);
        }
    }

    /**
     * Convert a GValue to a Java object based on its type.
     *
     * @param gvalue the GValue memory segment
     * @return the converted object, or null if unable to convert
     */
    public static Object toJavaObject(MemorySegment gvalue) {
        FridaNativeUtils.requireValidPointer(gvalue, "GValue");

        try {
            GType gtype = getType(gvalue);

            return switch (gtype) {
                case GType.STRING -> extractStringTyped(gvalue);
                case GType.INT -> extractIntTyped(gvalue);
                case GType.UINT -> extractUintTyped(gvalue);
                case GType.BOOLEAN -> extractBoolean(gvalue);
                case GType.POINTER -> extractPointer(gvalue);
                default -> {
                    log.debug("Unknown GValue type: {} (0x{})", gtype, Long.toHexString(gtype.getValue()));
                    yield null;
                }
            };
        } catch (Throwable e) {
            log.debug("Failed to convert GValue to Java object", e);
            return null;
        }
    }

    private static String extractStringTyped(MemorySegment gvalue) throws Throwable {
        MemorySegment strPtr = (MemorySegment) G_VALUE_GET_STRING.invoke(gvalue);
        return FridaNativeUtils.memorySegmentToString(strPtr);
    }

    private static Integer extractIntTyped(MemorySegment gvalue) throws Throwable {
        return (int) G_VALUE_GET_INT.invoke(gvalue);
    }

    private static Integer extractUintTyped(MemorySegment gvalue) throws Throwable {
        return (int) G_VALUE_GET_UINT.invoke(gvalue);
    }

    private static Boolean extractBoolean(MemorySegment gvalue) throws Throwable {
        return (boolean) G_VALUE_GET_BOOLEAN.invoke(gvalue);
    }

    private static String extractPointer(MemorySegment gvalue) throws Throwable {
        MemorySegment ptrValue = (MemorySegment) G_VALUE_GET_POINTER.invoke(gvalue);
        if (ptrValue.equals(MemorySegment.NULL)) {
            return null;
        }
        return FridaNativeUtils.formatAddress(ptrValue);
    }

    /**
     * Extract a string from a GValue.
     * Handles both typed G_TYPE_STRING and fallback to reading pointer directly if type is unrecognized.
     * Used in signal marshaling where GValue types may not be reliably set.
     *
     * @param gvalue the GValue memory segment
     * @return the string value, or null if unable to extract
     */
    public static String extractString(MemorySegment gvalue) {
        FridaNativeUtils.requireValidPointer(gvalue, "GValue");
        Object value = toJavaObject(gvalue);
        if (value instanceof String str) {
            return str;
        }
        throw new IllegalArgumentException("Expected string in GValue, got " + (value != null ? value.getClass().getSimpleName() : "null"));
    }

    /**
     * Extract an integer from a GValue.
     * Handles both G_TYPE_INT and G_TYPE_UINT.
     *
     * @param gvalue the GValue memory segment
     * @return the integer value
     * @throws IllegalArgumentException if the GValue does not contain an integer type
     */
    public static int extractInt(MemorySegment gvalue) {
        FridaNativeUtils.requireValidPointer(gvalue, "GValue");

        Object value = toJavaObject(gvalue);
        if (value instanceof Integer intValue) {
            return intValue;
        }
        throw new IllegalArgumentException("Expected integer in GValue, got " + (value != null ? value.getClass().getSimpleName() : "null"));
    }

    /**
     * Extract bytes from a GValue containing a GBytes pointer.
     * GBytes pointer is typically stored in the GValue data union at offset 8.
     *
     * @param gvalue the GValue memory segment
     * @return byte array extracted from GBytes, or empty array if unable to extract
     */
    public static byte[] extractBytes(MemorySegment gvalue) {
        FridaNativeUtils.requireValidPointer(gvalue, "GValue");

        try {
            // GValue data starts at offset 8 (after GType)
            MemorySegment gBytesPtr = gvalue.get(ValueLayout.ADDRESS, 8);
            if (gBytesPtr == null || gBytesPtr.equals(MemorySegment.NULL)) {
                return new byte[0];
            }
            return GBytesUtil.toByteArray(gBytesPtr);
        } catch (Throwable e) {
            log.trace("Failed to extract bytes from GValue: {}", e.getMessage());
            return new byte[0];
        }
    }
}
