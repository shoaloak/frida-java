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

package nl.axelkoolhaas.frida_java.frida;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GBytesUtil;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;

/**
 * Bus represents a communication channel with Frida devices. Claude warning: "Appears to be
 * unused/legacy code in both Go and Java reference implementations"
 */
public class Bus implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(Bus.class);
  private final MemorySegment busPtr;
  private final Map<String, Long> signalHandlerIds = new ConcurrentHashMap<>();
  private volatile boolean cleaned = false;

  // Native method handles
  private static final MethodHandle FRIDA_BUS_IS_DETACHED;
  private static final MethodHandle FRIDA_BUS_ATTACH_SYNC;
  private static final MethodHandle FRIDA_BUS_POST;
  private static final MethodHandle G_SIGNAL_HANDLER_DISCONNECT;

  static {
    Frida.ensureInitialized();
    FRIDA_BUS_IS_DETACHED =
        FridaLibraryLoader.findFunction(
            "frida_bus_is_detached",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_BUS_ATTACH_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_bus_attach_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_BUS_POST =
        FridaLibraryLoader.findFunction(
            "frida_bus_post",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_SIGNAL_HANDLER_DISCONNECT =
        FridaLibraryLoader.findFunction(
            "g_signal_handler_disconnect",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
  }

  /**
   * Create a Bus wrapper around a native bus pointer
   *
   * @param busPtr Native FridaBus pointer
   */
  public Bus(MemorySegment busPtr) {
    this.busPtr = FridaNativeUtils.requireValidPointer(busPtr, "Bus pointer");
    log.debug("Bus created");
  }

  /**
   * Check if the bus is detached from the device
   *
   * @return true if detached, false otherwise
   */
  public boolean isDetached() {
    checkNotCleaned();
    try {
      // frida_bus_is_detached returns gboolean (typedef gint, i.e., int)
      // gboolean: FALSE = 0, TRUE = non-zero (typically 1)
      int result = (int) FRIDA_BUS_IS_DETACHED.invokeExact(busPtr);
      log.trace("Checked bus detached state: {}", result != 0);
      return result != 0;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to check if bus is detached: {}", e.getMessage());
      throw new FridaException("Failed to check if bus is detached", e);
    }
  }

  /**
   * Attach to the device bus
   *
   * @throws FridaException if attachment fails
   */
  public void attach() {
    checkNotCleaned();
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);
      log.debug("Attaching to bus");
      FRIDA_BUS_ATTACH_SYNC.invokeExact(busPtr, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "attach to bus");
      log.debug("Bus attached successfully");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to attach to bus: {}", e.getMessage());
      throw new FridaException("Failed to attach to bus", e);
    }
  }

  /**
   * Post a message to the device
   *
   * @param message Message string to send
   * @param data Binary data to send (can be null)
   */
  public void post(String message, byte[] data) {
    checkNotCleaned();
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment messagePtr = arena.allocateFrom(message);

      MemorySegment gBytesData = MemorySegment.NULL;
      if (data != null && data.length > 0) {
        gBytesData = GBytesUtil.fromByteArray(data, arena);
      }

      FRIDA_BUS_POST.invokeExact(busPtr, messagePtr, gBytesData);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to post message to bus: {}", e.getMessage());
      throw new FridaException("Failed to post message to bus", e);
    }
  }

  /**
   * Post a message to the device without binary data
   *
   * @param message Message string to send
   */
  public void post(String message) {
    post(message, null);
  }

  /**
   * Register callbacks for bus events
   *
   * <p>Available signals:
   *
   * <ul>
   *   <li>"detached": Emitted when the bus is detached from the device. Callback should be Runnable
   *       or VoidCallback
   *   <li>"message": Emitted when a message is received from the device. Callback should be
   *       SignalCallbacks.MessageCallback accepting (String message, byte[] data)
   * </ul>
   *
   * @param signalName Signal name to connect to
   * @param callback Callback function
   * @throws IllegalArgumentException if signal name is unknown or callback type is invalid
   */
  public void on(String signalName, Object callback) {
    checkNotCleaned();
    if (callback == null) {
      throw new IllegalArgumentException("Callback cannot be null");
    }

    log.debug("Registering callback for bus signal: {}", signalName);

    // Validate callback type based on signal name
    switch (signalName) {
      case "detached":
        if (!(callback instanceof Runnable)
            && !(callback instanceof SignalCallbacks.VoidCallback)) {
          throw new IllegalArgumentException(
              "Detached signal callback must be Runnable or VoidCallback");
        }
        break;
      case "message":
        if (!(callback instanceof SignalCallbacks.MessageCallback)) {
          throw new IllegalArgumentException("Message signal callback must be MessageCallback");
        }
        break;
      default:
        throw new IllegalArgumentException("Unknown signal: " + signalName);
    }

    // Disconnect existing handler for this signal if any
    Long existingHandlerId = signalHandlerIds.get(signalName);
    if (existingHandlerId != null) {
      disconnectSignal(existingHandlerId);
      signalHandlerIds.remove(signalName);
      log.debug("Replaced existing handler for bus signal: {}", signalName);
    }

    // Connect the closure to the GLib signal
    try {
      long handlerId = Closure.connectClosure(busPtr, signalName, callback);

      if (handlerId > 0) {
        signalHandlerIds.put(signalName, handlerId);
        log.trace("Connected bus signal '{}' with handler ID {}", signalName, handlerId);
      } else {
        log.warn("Failed to connect bus signal '{}' - no handler ID returned", signalName);
        throw new FridaException("Failed to connect bus signal '" + signalName + "'");
      }
    } catch (FridaException e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to connect bus signal '{}': {}", signalName, e.getMessage());
      throw new FridaException("Failed to connect bus signal '" + signalName + "'", e);
    }

    log.trace("Registered callback for bus signal '{}'", signalName);
  }

  /**
   * Remove callback for a signal
   *
   * @param signalName Signal name to remove callback for
   */
  public void off(String signalName) {
    if (cleaned) {
      return; // Already cleaned, nothing to do
    }

    Long handlerId = signalHandlerIds.remove(signalName);
    if (handlerId != null) {
      disconnectSignal(handlerId);
      log.debug("Removed callback for bus signal: {}", signalName);
    }
  }

  /** Clean up resources held by the bus */
  public void clean() {
    if (cleaned) {
      return;
    }

    // Disconnect all signals
    signalHandlerIds.forEach(
        (signalName, handlerId) -> {
          disconnectSignal(handlerId);
          log.trace("Disconnected signal '{}' with handler ID {}", signalName, handlerId);
        });
    signalHandlerIds.clear();

    FridaNativeUtils.fridaUnref(busPtr);
    cleaned = true;
    log.debug("Bus cleaned");
  }

  @Override
  public void close() {
    clean();
  }

  @Override
  public String toString() {
    if (cleaned) {
      return "Bus{cleaned}";
    }
    return "Bus{detached=" + isDetached() + "}";
  }

  /**
   * Get the native pointer to the FridaBus object (for internal use only)
   *
   * @return Native pointer
   */
  @SuppressWarnings("unused")
  MemorySegment getPointer() {
    checkNotCleaned();
    return busPtr;
  }

  private void checkNotCleaned() {
    if (cleaned) {
      throw new IllegalStateException("Bus has been cleaned");
    }
  }

  private void disconnectSignal(long handlerId) {
    try {
      G_SIGNAL_HANDLER_DISCONNECT.invokeExact(busPtr, handlerId);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.warn("Failed to disconnect signal handler {}: {}", handlerId, e.getMessage());
    }
  }
}
