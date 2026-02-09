package nl.axelkoolhaas.frida_java.util;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
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
    private static final MethodHandle G_VALUE_GET_BOOLEAN;
    private static final MethodHandle G_VALUE_GET_POINTER;

    // GType constants (from GLib)
    public static final long G_TYPE_STRING = 64;   // G_TYPE_MAKE_FUNDAMENTAL(16)
    public static final long G_TYPE_INT = 24;      // G_TYPE_MAKE_FUNDAMENTAL(6)
    public static final long G_TYPE_BOOLEAN = 20;  // G_TYPE_MAKE_FUNDAMENTAL(5)
    public static final long G_TYPE_POINTER = 68;  // G_TYPE_MAKE_FUNDAMENTAL(17)

    static {
        G_VALUE_GET_STRING = FridaLibraryLoader.findFunction("g_value_get_string",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        G_VALUE_GET_INT = FridaLibraryLoader.findFunction("g_value_get_int",
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
    public static long getType(MemorySegment gvalue) {
        FridaNativeUtils.requireValidPointer(gvalue, "GValue");
        try {
            // GValue struct has g_type as the first field (size_t/ulong)
            return gvalue.get(ValueLayout.JAVA_LONG, 0);
        } catch (Throwable e) {
            log.debug("Failed to read GType from GValue", e);
            return 0;
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
            long gtype = getType(gvalue);

            return switch ((int) gtype) {
                case (int) G_TYPE_STRING -> extractString(gvalue);
                case (int) G_TYPE_INT -> extractInt(gvalue);
                case (int) G_TYPE_BOOLEAN -> extractBoolean(gvalue);
                case (int) G_TYPE_POINTER -> extractPointer(gvalue);
                default -> {
                    log.debug("Unknown GValue type: {} (0x{})", gtype, Long.toHexString(gtype));
                    yield null;
                }
            };
        } catch (Throwable e) {
            log.debug("Failed to convert GValue to Java object", e);
            return null;
        }
    }


    private static String extractString(MemorySegment gvalue) throws Throwable {
        MemorySegment strPtr = (MemorySegment) G_VALUE_GET_STRING.invoke(gvalue);
        return FridaNativeUtils.memorySegmentToString(strPtr);
    }

    private static Integer extractInt(MemorySegment gvalue) throws Throwable {
        return (int) G_VALUE_GET_INT.invoke(gvalue);
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
}
