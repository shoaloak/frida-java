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

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.frida.FridaException;

/** Utility class for working with GLib GValue structures. */
public class GValueUtil {
  private static final Logger log = LoggerFactory.getLogger(GValueUtil.class);

  /**
   * The GValue struct is defined as: typedef gsize GType; struct _GValue { GType g_type; union {
   * ... } data[2]; }; <br>
   * We use ValueLayout.ADDRESS for GType because gsize is platform-dependent (matching the pointer
   * size), and sequenceLayout(2, JAVA_LONG) for the 16-byte data union.
   */
  public static final StructLayout LAYOUT =
      MemoryLayout.structLayout(
              // GType is an alias for gsize (size_t).
              // ValueLayout.ADDRESS correctly represents a platform-native word size.
              ValueLayout.ADDRESS.withName("g_type"),

              // The data union array. In C, it's defined as data[2].
              // We model this as a sequence of two 8-byte values (on 64-bit).
              MemoryLayout.sequenceLayout(2, ValueLayout.JAVA_LONG).withName("data"))
          .withByteAlignment(ValueLayout.ADDRESS.byteSize());

  // private static final MethodHandle G_VALUE_TYPE; // This is a macro, not a function!
  private static final MethodHandle G_VALUE_GET_STRING;
  private static final MethodHandle G_VALUE_GET_INT;
  private static final MethodHandle G_VALUE_GET_UINT;
  private static final MethodHandle G_VALUE_GET_ENUM;
  private static final MethodHandle G_VALUE_GET_FLAGS;
  private static final MethodHandle G_VALUE_GET_BOOLEAN;
  private static final MethodHandle G_VALUE_GET_POINTER;
  private static final MethodHandle G_VALUE_GET_VARIANT;
  private static final MethodHandle G_VARIANT_PRINT;
  private static final MethodHandle G_FREE; // needed?

  static {
    G_VALUE_GET_STRING =
        FridaLibraryLoader.findFunction(
            "g_value_get_string", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_VALUE_GET_INT =
        FridaLibraryLoader.findFunction(
            "g_value_get_int", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    G_VALUE_GET_UINT =
        FridaLibraryLoader.findFunction(
            "g_value_get_uint", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    G_VALUE_GET_ENUM =
        FridaLibraryLoader.findFunction(
            "g_value_get_enum", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    G_VALUE_GET_FLAGS =
        FridaLibraryLoader.findFunction(
            "g_value_get_flags", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    G_VALUE_GET_BOOLEAN =
        FridaLibraryLoader.findFunction(
            "g_value_get_boolean",
            FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
    G_VALUE_GET_POINTER =
        FridaLibraryLoader.findFunction(
            "g_value_get_pointer", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_VALUE_GET_VARIANT =
        FridaLibraryLoader.findFunction(
            "g_value_get_variant", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_VARIANT_PRINT =
        FridaLibraryLoader.findFunction(
            "g_variant_print",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_BOOLEAN));
    G_FREE =
        FridaLibraryLoader.findFunction("g_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
  }

  private GValueUtil() {
    // Utility class
  }

  /**
   * GLib passes signal parameters as an array of GValues. This method skips to the correct GValue
   * in that array using the calculated layout size.
   */
  public static MemorySegment getAt(MemorySegment paramsArray, int index) {
    return paramsArray.asSlice(index * LAYOUT.byteSize(), LAYOUT.byteSize());
  }

  /**
   * Get the GType from a GValue struct. Replaces the C macro: G_VALUE_TYPE(val) which accesses
   * ((val)->g_type)
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
        // TODO properly name methods...
        case GType.STRING -> extractStringTyped(gvalue);
        case GType.INT -> extractIntTyped(gvalue);
        case GType.UINT -> extractUintTyped(gvalue);
        case GType.ENUM -> extractEnumTyped(gvalue);
        case GType.FLAGS -> extractFlagsTyped(gvalue);
        case GType.BOOLEAN -> extractBoolean(gvalue);
        case GType.POINTER -> extractPointer(gvalue);
        case GType.VARIANT -> extractVariant(gvalue);
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

  private static Integer extractEnumTyped(MemorySegment gvalue) throws Throwable {
    return (int) G_VALUE_GET_ENUM.invoke(gvalue);
  }

  private static Integer extractFlagsTyped(MemorySegment gvalue) throws Throwable {
    return (int) G_VALUE_GET_FLAGS.invoke(gvalue);
  }

  private static Boolean extractBoolean(MemorySegment gvalue) throws Throwable {
    return (boolean) G_VALUE_GET_BOOLEAN.invoke(gvalue);
  }

  public static MemorySegment extractPointer(MemorySegment gvalue) {
    try {
      return (MemorySegment) G_VALUE_GET_POINTER.invoke(gvalue);
    } catch (Throwable t) {
      return MemorySegment.NULL;
    }
  }

  public static String extractVariant(MemorySegment gvalue) {
    try {
      MemorySegment variantPtr = (MemorySegment) G_VALUE_GET_VARIANT.invoke(gvalue);
      if (variantPtr == null || variantPtr.equals(MemorySegment.NULL)) {
        return null;
      }
      MemorySegment strPtr = (MemorySegment) G_VARIANT_PRINT.invoke(variantPtr, false);
      String result = FridaNativeUtils.memorySegmentToString(strPtr);
      G_FREE.invoke(strPtr); // Free the string returned by g_variant_print
      // TODO: is a Variant always JSON? would it be smart to cast it to a jackson type and return
      // that?
      return result;
    } catch (Throwable t) {
      log.debug("Failed to extract GVariant from GValue", t);
      return null;
    }
  }

  /**
   * Extract a string from a GValue. Handles both typed G_TYPE_STRING and fallback to reading
   * pointer directly if type is unrecognized. Used in signal marshaling where GValue types may not
   * be reliably set.
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
    throw new IllegalArgumentException(
        "Expected string in GValue, got "
            + (value != null ? value.getClass().getSimpleName() : "null"));
  }

  /**
   * Extract an integer from a GValue. Handles both G_TYPE_INT and G_TYPE_UINT.
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
    throw new IllegalArgumentException(
        "Expected integer in GValue, got "
            + (value != null ? value.getClass().getSimpleName() : "null"));
  }

  /**
   * Extract an enum integer value from a GValue.
   *
   * @param gvalue the GValue memory segment
   * @return enum integer value
   * @throws FridaException if enum extraction fails
   */
  public static int extractEnum(MemorySegment gvalue) {
    FridaNativeUtils.requireValidPointer(gvalue, "GValue");
    try {
      return (int) G_VALUE_GET_ENUM.invoke(gvalue);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to extract enum value from GValue", e);
    }
  }

  /**
   * Extract bytes from a GValue containing a GBytes pointer. GBytes pointer is typically stored in
   * the GValue data union at offset 8.
   *
   * @param gvalue the GValue memory segment
   * @return byte array extracted from GBytes, or empty array if unable to extract
   */
  public static byte[] extractBytes(MemorySegment gvalue) {
    FridaNativeUtils.requireValidPointer(gvalue, "GValue");

    try {
      // Skip the GType field to get to the union data
      MemorySegment gBytesPtr = gvalue.get(ValueLayout.ADDRESS, ValueLayout.ADDRESS.byteSize());
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
