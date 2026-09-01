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

package nl.axelkoolhaas.frida_java.frida;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;

/**
 * Service represents a service connection to a Frida device.
 *
 * <p>This class provides methods for activating, canceling, and checking the status of service
 * connections.
 *
 * <p><b>Note:</b> This is an advanced feature. Request functionality requires GVariant handling
 * which is not yet fully implemented.
 */
public class Service implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(Service.class);

  private final MemorySegment servicePtr;

  private static final MethodHandle FRIDA_SERVICE_IS_CLOSED;
  private static final MethodHandle FRIDA_SERVICE_ACTIVATE_SYNC;
  private static final MethodHandle FRIDA_SERVICE_CANCEL_SYNC;

  static {
    FRIDA_SERVICE_IS_CLOSED =
        FridaLibraryLoader.findFunction(
            "frida_service_is_closed",
            FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
    FRIDA_SERVICE_ACTIVATE_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_service_activate_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_SERVICE_CANCEL_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_service_cancel_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  public Service(MemorySegment servicePtr) {
    this.servicePtr = FridaNativeUtils.requireValidPointer(servicePtr, "Service pointer");
  }

  /**
   * Check if the service connection is closed.
   *
   * @return true if closed, false otherwise
   */
  public boolean isClosed() {
    try {
      return (boolean) FRIDA_SERVICE_IS_CLOSED.invoke(servicePtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to check if service is closed", e);
    }
  }

  /**
   * Activate the service connection.
   *
   * @throws FridaException if activation fails
   */
  public void activate() {
    log.debug("Activating service");
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      FRIDA_SERVICE_ACTIVATE_SYNC.invoke(servicePtr, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "activate service");

      log.debug("Service activated successfully");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to activate service", e);
    }
  }

  /**
   * Cancel the service connection.
   *
   * @throws FridaException if cancellation fails
   */
  public void cancel() {
    log.debug("Canceling service");
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      FRIDA_SERVICE_CANCEL_SYNC.invoke(servicePtr, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "cancel service");

      log.debug("Service canceled successfully");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to cancel service", e);
    }
  }

  /** Clean up native resources held by this Service. */
  public void clean() {
    log.trace("Cleaning Service resources");
    try {
      FridaNativeUtils.fridaUnref(servicePtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to clean Service", e);
    }
  }

  @Override
  public void close() {
    clean();
  }
}
