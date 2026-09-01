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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;

/** Options for adding remote devices */
public class RemoteDeviceOptions implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(RemoteDeviceOptions.class);
  private final MemorySegment optionsPtr;

  private static final MethodHandle FRIDA_REMOTE_DEVICE_OPTIONS_NEW;
  private static final MethodHandle FRIDA_REMOTE_DEVICE_OPTIONS_SET_CERTIFICATE;
  private static final MethodHandle FRIDA_REMOTE_DEVICE_OPTIONS_SET_ORIGIN;
  private static final MethodHandle FRIDA_REMOTE_DEVICE_OPTIONS_SET_TOKEN;
  private static final MethodHandle FRIDA_REMOTE_DEVICE_OPTIONS_SET_KEEPALIVE_INTERVAL;
  private static final MethodHandle FRIDA_REMOTE_DEVICE_OPTIONS_GET_CERTIFICATE;
  private static final MethodHandle FRIDA_REMOTE_DEVICE_OPTIONS_GET_ORIGIN;
  private static final MethodHandle FRIDA_REMOTE_DEVICE_OPTIONS_GET_TOKEN;
  private static final MethodHandle FRIDA_REMOTE_DEVICE_OPTIONS_GET_KEEPALIVE_INTERVAL;

  static {
    Frida.ensureInitialized();

    FRIDA_REMOTE_DEVICE_OPTIONS_NEW =
        FridaLibraryLoader.findFunction(
            "frida_remote_device_options_new", FunctionDescriptor.of(ValueLayout.ADDRESS));
    FRIDA_REMOTE_DEVICE_OPTIONS_SET_CERTIFICATE =
        FridaLibraryLoader.findFunction(
            "frida_remote_device_options_set_certificate",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_REMOTE_DEVICE_OPTIONS_SET_ORIGIN =
        FridaLibraryLoader.findFunction(
            "frida_remote_device_options_set_origin",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_REMOTE_DEVICE_OPTIONS_SET_TOKEN =
        FridaLibraryLoader.findFunction(
            "frida_remote_device_options_set_token",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_REMOTE_DEVICE_OPTIONS_SET_KEEPALIVE_INTERVAL =
        FridaLibraryLoader.findFunction(
            "frida_remote_device_options_set_keepalive_interval",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_REMOTE_DEVICE_OPTIONS_GET_CERTIFICATE =
        FridaLibraryLoader.findFunction(
            "frida_remote_device_options_get_certificate",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_REMOTE_DEVICE_OPTIONS_GET_ORIGIN =
        FridaLibraryLoader.findFunction(
            "frida_remote_device_options_get_origin",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_REMOTE_DEVICE_OPTIONS_GET_TOKEN =
        FridaLibraryLoader.findFunction(
            "frida_remote_device_options_get_token",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_REMOTE_DEVICE_OPTIONS_GET_KEEPALIVE_INTERVAL =
        FridaLibraryLoader.findFunction(
            "frida_remote_device_options_get_keepalive_interval",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
  }

  /** Create new remote device options with default settings */
  public RemoteDeviceOptions() {
    try {
      this.optionsPtr = (MemorySegment) FRIDA_REMOTE_DEVICE_OPTIONS_NEW.invoke();
      log.debug("RemoteDeviceOptions created");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to create RemoteDeviceOptions: {}", e.getMessage());
      throw new FridaException("Failed to create RemoteDeviceOptions", e);
    }
  }

  /**
   * Set the TLS certificate for authentication
   *
   * @param certificate Certificate object
   */
  public void setCertificate(Certificate certificate) {
    try {
      FRIDA_REMOTE_DEVICE_OPTIONS_SET_CERTIFICATE.invoke(optionsPtr, certificate.getPointer());
      log.trace("Set remote device certificate");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set certificate: {}", e.getMessage());
      throw new FridaException("Failed to set certificate", e);
    }
  }

  /**
   * Set the origin for CORS
   *
   * @param origin Origin string
   */
  public void setOrigin(String origin) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment originPtr = arena.allocateFrom(origin);
      FRIDA_REMOTE_DEVICE_OPTIONS_SET_ORIGIN.invoke(optionsPtr, originPtr);
      log.trace("Set remote device origin: {}", origin);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set origin: {}", e.getMessage());
      throw new FridaException("Failed to set origin", e);
    }
  }

  /**
   * Set the authentication token
   *
   * @param token Authentication token
   */
  public void setToken(String token) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment tokenPtr = arena.allocateFrom(token);
      FRIDA_REMOTE_DEVICE_OPTIONS_SET_TOKEN.invoke(optionsPtr, tokenPtr);
      log.trace("Set remote device token");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set token: {}", e.getMessage());
      throw new FridaException("Failed to set token", e);
    }
  }

  /**
   * Set the keepalive interval in seconds
   *
   * @param intervalSeconds Keepalive interval in seconds
   */
  public void setKeepaliveInterval(int intervalSeconds) {
    try {
      FRIDA_REMOTE_DEVICE_OPTIONS_SET_KEEPALIVE_INTERVAL.invoke(optionsPtr, intervalSeconds);
      log.trace("Set keepalive interval: {} seconds", intervalSeconds);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set keepalive interval: {}", e.getMessage());
      throw new FridaException("Failed to set keepalive interval", e);
    }
  }

  /**
   * Get the certificate
   *
   * @return Certificate object
   */
  public Certificate getCertificate() {
    try {
      MemorySegment certPtr =
          (MemorySegment) FRIDA_REMOTE_DEVICE_OPTIONS_GET_CERTIFICATE.invoke(optionsPtr);
      if (certPtr.equals(MemorySegment.NULL)) {
        return null;
      }
      return new Certificate(certPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get certificate: {}", e.getMessage());
      throw new FridaException("Failed to get certificate", e);
    }
  }

  /**
   * Get the origin
   *
   * @return Origin string
   */
  public String getOrigin() {
    try {
      MemorySegment originPtr =
          (MemorySegment) FRIDA_REMOTE_DEVICE_OPTIONS_GET_ORIGIN.invoke(optionsPtr);
      String origin = FridaNativeUtils.memorySegmentToString(originPtr);
      log.trace("Got remote device origin: {}", origin);
      return origin;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get origin: {}", e.getMessage());
      throw new FridaException("Failed to get origin", e);
    }
  }

  /**
   * Get the authentication token
   *
   * @return Token string
   */
  public String getToken() {
    try {
      MemorySegment tokenPtr =
          (MemorySegment) FRIDA_REMOTE_DEVICE_OPTIONS_GET_TOKEN.invoke(optionsPtr);
      String token = FridaNativeUtils.memorySegmentToString(tokenPtr);
      log.trace("Got remote device token");
      return token;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get token: {}", e.getMessage());
      throw new FridaException("Failed to get token", e);
    }
  }

  /**
   * Get the keepalive interval
   *
   * @return Interval in seconds
   */
  public int getKeepaliveInterval() {
    try {
      int interval = (int) FRIDA_REMOTE_DEVICE_OPTIONS_GET_KEEPALIVE_INTERVAL.invoke(optionsPtr);
      log.trace("Got keepalive interval: {} seconds", interval);
      return interval;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get keepalive interval: {}", e.getMessage());
      throw new FridaException("Failed to get keepalive interval", e);
    }
  }

  /**
   * Get the native pointer to the options struct Used internally when passing options to device
   * manager methods
   */
  MemorySegment getPointer() {
    return optionsPtr;
  }

  @Override
  public void close() {
    try {
      FridaNativeUtils.fridaUnref(optionsPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to cleanup RemoteDeviceOptions", e);
    }
  }
}
