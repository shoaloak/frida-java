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

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.frida.FridaException;

public class GSignalUtil {
  private static final Logger log = LoggerFactory.getLogger(GSignalUtil.class);

  private static final MethodHandle G_SIGNAL_LOOKUP;
  private static final MethodHandle G_SIGNAL_CONNECT_CLOSURE_BY_ID;
  private static final MethodHandle G_SIGNAL_CONNECT_DATA;
  private static final MethodHandle G_CLOSURE_NEW_SIMPLE;
  private static final MethodHandle G_CLOSURE_SET_MARSHAL;

  /**
   * sizeof(GClosure) - derived from the GLib struct layout.
   *
   * <p>GClosure contains:
   *
   * <ul>
   *   <li>Bitfield-packed guint (4 bytes on all platforms)
   *   <li>Padding to align the first pointer (pointer_size - 4 bytes on 64-bit, 0 on 32-bit)
   *   <li>marshal function pointer (pointer_size bytes)
   *   <li>data pointer (pointer_size bytes)
   *   <li>notifiers pointer (pointer_size bytes)
   * </ul>
   *
   * <p>This value is computed at class load time based on the target ABI's pointer width.
   */
  private static final int SIZEOF_GCLOSURE;

  static {
    // Derive SIZEOF_GCLOSURE from pointer width to match target ABI
    long pointerSize = ValueLayout.ADDRESS.byteSize();
    int bitfieldSize = 4; // guint bitfields are always 4 bytes

    if (pointerSize == 8) {
      // 64-bit: 4 (bitfields) + 4 (padding) + 8*3 (pointers) = 32
      SIZEOF_GCLOSURE = bitfieldSize + 4 + (3 * 8);
    } else if (pointerSize == 4) {
      // 32-bit: 4 (bitfields) + 0 (no padding) + 4*3 (pointers) = 16
      SIZEOF_GCLOSURE = bitfieldSize + (3 * 4);
    } else {
      throw new FridaException(
          "Cannot determine sizeof(GClosure): unsupported pointer size " + pointerSize + " bytes");
    }

    log.debug(
        "Derived SIZEOF_GCLOSURE = {} bytes (pointer size = {} bytes)",
        SIZEOF_GCLOSURE,
        pointerSize);
    G_SIGNAL_LOOKUP =
        FridaLibraryLoader.findFunction(
            "g_signal_lookup",
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    G_SIGNAL_CONNECT_CLOSURE_BY_ID =
        FridaLibraryLoader.findFunction(
            "g_signal_connect_closure_by_id",
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_BOOLEAN));

    G_SIGNAL_CONNECT_DATA =
        FridaLibraryLoader.findFunction(
            "g_signal_connect_data",
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG, // returns gulong handler_id
                ValueLayout.ADDRESS, // instance (GObject*)
                ValueLayout.ADDRESS, // detailed_signal (const gchar*)
                ValueLayout.ADDRESS, // c_handler (GCallback)
                ValueLayout.ADDRESS, // data (gpointer)
                ValueLayout.ADDRESS, // destroy_data (GClosureNotify)
                ValueLayout.JAVA_INT // connect_flags (GConnectFlags)
                ));

    G_CLOSURE_NEW_SIMPLE =
        FridaLibraryLoader.findFunction(
            "g_closure_new_simple",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

    G_CLOSURE_SET_MARSHAL =
        FridaLibraryLoader.findFunction(
            "g_closure_set_marshal",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  /**
   * Get the GType from a GObject. Replaces the C macro: G_OBJECT_TYPE(obj) which accesses
   * ((GTypeInstance*)obj)->g_class->g_type
   */
  public static long getObjectType(MemorySegment object) {
    FridaNativeUtils.requireValidPointer(object, "GObject");

    // Reinterpret the segment to have sufficient size for reading
    // GObject inherits from GTypeInstance
    // GTypeInstance has g_class as first field (pointer)
    // GTypeClass has g_type as first field (GType/size_t)
    MemorySegment objectSegment = object.reinterpret(ValueLayout.ADDRESS.byteSize());
    MemorySegment gClass = objectSegment.get(ValueLayout.ADDRESS, 0);
    FridaNativeUtils.requireValidPointer(gClass, "GTypeClass");

    MemorySegment gClassSegment = gClass.reinterpret(ValueLayout.JAVA_LONG.byteSize());
    return gClassSegment.get(ValueLayout.JAVA_LONG, 0);
  }

  /**
   * Lookup a signal ID by name and object type.
   *
   * @param object The GObject instance
   * @param signalName The signal name
   * @return Signal ID, or 0 if not found
   */
  public static int lookupSignal(MemorySegment object, String signalName) {
    FridaNativeUtils.requireValidPointer(object, "object");
    if (signalName == null || signalName.trim().isEmpty()) {
      throw new IllegalArgumentException("Signal name cannot be null or empty");
    }

    try (Arena arena = Arena.ofConfined()) {
      long objectType = getObjectType(object);
      MemorySegment signalNamePtr = arena.allocateFrom(signalName);
      int signalId = (int) G_SIGNAL_LOOKUP.invoke(signalNamePtr, objectType);
      log.debug("Signal lookup '{}' on type {} returned ID {}", signalName, objectType, signalId);
      return signalId;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to lookup signal '{}': {}", signalName, e.getMessage(), e);
      throw new FridaException("Failed to lookup signal: " + signalName, e);
    }
  }

  /**
   * Create a new GClosure with a custom marshal function. This is equivalent to Go's newClosure()
   * which calls: g_closure_new_simple(sizeof(GClosure), NULL) g_closure_set_marshal(closure,
   * marshal)
   *
   * <p>The closure is created with a floating reference. When connected to a signal via
   * g_signal_connect_closure_by_id, GLib will automatically sink the floating reference and take
   * ownership of the closure. We must NOT manually ref or sink the closure here.
   *
   * @param marshalFunc The marshal function pointer (upcall stub)
   * @return The GClosure pointer
   */
  public static MemorySegment createClosureWithMarshal(MemorySegment marshalFunc) {
    FridaNativeUtils.requireValidPointer(marshalFunc, "marshalFunc");

    try {
      // Create simple closure: g_closure_new_simple(sizeof_closure, data)
      // This creates a closure with ref_count = 1 and floating = TRUE
      MemorySegment closure =
          (MemorySegment)
              G_CLOSURE_NEW_SIMPLE.invoke(
                  SIZEOF_GCLOSURE, MemorySegment.NULL // user_data
                  );

      if (closure == null || closure.equals(MemorySegment.NULL)) {
        throw new FridaException("g_closure_new_simple returned NULL");
      }

      log.trace("Created GClosure at {}", closure);

      // Set the marshal function: g_closure_set_marshal(closure, marshal)
      G_CLOSURE_SET_MARSHAL.invoke(closure, marshalFunc);

      log.trace("Set marshal function {} on GClosure {}", marshalFunc, closure);

      // DO NOT manually ref or sink the closure here!
      // g_signal_connect_closure_by_id will handle the reference counting:
      // - It will call g_closure_ref (ref_count becomes 2)
      // - It will call g_closure_sink (removes floating flag, ref_count becomes 1)
      // This gives GLib ownership of the closure

      return closure;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      if (e instanceof FridaException) {
        throw (FridaException) e;
      }
      throw new FridaException("Failed to create GClosure with marshal", e);
    }
  }

  /**
   * Connect a GClosure to a signal by ID.
   *
   * @param object The GObject instance
   * @param signalId The signal ID (from lookupSignal)
   * @param closure The GClosure to connect
   * @param after Whether to connect after the default handler
   * @return Handler ID for the connection
   */
  public static long connectClosureById(
      MemorySegment object, int signalId, MemorySegment closure, boolean after) {
    FridaNativeUtils.requireValidPointer(object, "object");
    FridaNativeUtils.requireValidPointer(closure, "closure");

    if (signalId == 0) {
      log.debug("Signal ID is 0, not connecting");
      return 0;
    }

    try {
      long handlerId =
          (long)
              G_SIGNAL_CONNECT_CLOSURE_BY_ID.invoke(
                  object,
                  signalId,
                  0, // detail (GQuark, 0 for none)
                  closure,
                  after // after flag
                  );

      log.debug("g_signal_connect_closure_by_id returned handler ID: {}", handlerId);
      return handlerId;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to connect closure by ID: {}", e.getMessage(), e);
      throw new FridaException("Failed to connect closure by ID", e);
    }
  }

  /** Connect a callback to a GObject signal using g_signal_connect_data */
  @SuppressWarnings("unused")
  public static long connectSignal(
      MemorySegment instance, String signalName, MemorySegment callback) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment signalNameNative = arena.allocateFrom(signalName);

      long handlerId =
          (long)
              G_SIGNAL_CONNECT_DATA.invoke(
                  instance, // GObject instance
                  signalNameNative, // detailed_signal (signal name)
                  callback, // GCallback (function pointer)
                  MemorySegment.NULL, // user_data
                  MemorySegment.NULL, // destroy_data
                  0 // flags (0 = G_CONNECT_DEFAULT)
                  );

      log.debug("g_signal_connect_data returned handler ID: {}", handlerId);
      return handlerId;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to connect signal '{}': {}", signalName, e.getMessage(), e);
      throw new FridaException("Failed to connect signal: " + signalName, e);
    }
  }
}
