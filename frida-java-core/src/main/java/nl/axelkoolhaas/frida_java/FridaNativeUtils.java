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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.frida.FridaException;

public class FridaNativeUtils {
  private static final Logger log = LoggerFactory.getLogger(FridaNativeUtils.class);

  private static final MethodHandle FRIDA_UNREF;
  private static final MethodHandle G_OBJECT_REF;

  static {
    FRIDA_UNREF =
        FridaLibraryLoader.findFunction(
            "frida_unref", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    G_OBJECT_REF =
        FridaLibraryLoader.findFunction(
            "g_object_ref", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  /**
   * Call g_object_ref on a pointer to increment its reference count
   *
   * @param object the GObject memory segment
   * @return the same object (for convenience)
   */
  public static MemorySegment fridaRef(MemorySegment object) {
    try {
      return (MemorySegment) G_OBJECT_REF.invoke(object);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to ref pointer", e);
    }
  }

  /**
   * Call frida_unref on a pointer Note that this will call g_object_unref under the hood
   *
   * @param object the GObject memory segment
   */
  public static void fridaUnref(MemorySegment object) {
    try {
      FRIDA_UNREF.invoke(object);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to unref pointer", e);
    }
  }

  /**
   * Validate that a native pointer is not null or NULL
   *
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
   * Format a memory address as a hex string
   *
   * @param address the memory address
   * @return formatted hex string like "0x1234abcd"
   */
  public static String formatAddress(long address) {
    return "0x" + Long.toHexString(address);
  }

  /**
   * Format a MemorySegment address as a hex string
   *
   * @param segment the memory segment
   * @return formatted hex string like "0x1234abcd", or "null" if segment is NULL
   */
  public static String formatAddress(MemorySegment segment) {
    if (segment == null || segment.equals(MemorySegment.NULL)) {
      return "null";
    }
    return formatAddress(segment.address());
  }

  /**
   * Helper method to safely convert a MemorySegment to a UTF-8 string
   *
   * @param segment the memory segment to convert
   * @return the string value, or empty string if segment is NULL
   */
  public static String memorySegmentToString(MemorySegment segment) {
    if (segment.equals(MemorySegment.NULL)) {
      return "";
    }
    // Read the C string using UTF-8 encoding, searching for null terminator
    return segment
        .reinterpret(Long.MAX_VALUE)
        .getString(0, java.nio.charset.StandardCharsets.UTF_8);
  }

  /**
   * Helper method to convert a MemorySegment to a string and then unref the segment
   *
   * @param segment the memory segment to convert and unref
   * @return the string value, or empty string if segment is NULL
   */
  public static String memorySegmentToStringAndFree(MemorySegment segment) {
    String result = memorySegmentToString(segment);
    fridaUnref(segment);
    return result;
  }

  /**
   * Convert a C string array to a Java List
   *
   * @param arrayPtr Pointer to array of C strings (gchar**)
   * @param length Number of strings in the array
   * @return List of strings
   */
  public static java.util.List<String> cStringArrayToJavaList(MemorySegment arrayPtr, int length) {
    if (arrayPtr.equals(MemorySegment.NULL) || length == 0) {
      return java.util.List.of();
    }

    java.util.List<String> result = new java.util.ArrayList<>(length);
    MemorySegment array = arrayPtr.reinterpret(ValueLayout.ADDRESS.byteSize() * length);

    for (int i = 0; i < length; i++) {
      MemorySegment strPtr = array.getAtIndex(ValueLayout.ADDRESS, i);
      if (!strPtr.equals(MemorySegment.NULL)) {
        result.add(memorySegmentToString(strPtr));
      }
    }

    return result;
  }
}
