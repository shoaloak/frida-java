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

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GHashTableUtil;

public class Application implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(Application.class);
  private final MemorySegment applicationPtr;
  private volatile boolean closed = false;

  private static final MethodHandle FRIDA_APPLICATION_GET_IDENTIFIER;
  private static final MethodHandle FRIDA_APPLICATION_GET_NAME;
  private static final MethodHandle FRIDA_APPLICATION_GET_PID;
  private static final MethodHandle FRIDA_APPLICATION_GET_PARAMETERS;

  static {
    Frida.ensureInitialized();
    FRIDA_APPLICATION_GET_IDENTIFIER =
        FridaLibraryLoader.findFunction(
            "frida_application_get_identifier",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_APPLICATION_GET_NAME =
        FridaLibraryLoader.findFunction(
            "frida_application_get_name",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_APPLICATION_GET_PID =
        FridaLibraryLoader.findFunction(
            "frida_application_get_pid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_APPLICATION_GET_PARAMETERS =
        FridaLibraryLoader.findFunction(
            "frida_application_get_parameters",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  /**
   * Create an Application wrapper around a native application pointer
   *
   * @param applicationPtr Native application pointer
   */
  public Application(MemorySegment applicationPtr) {
    this.applicationPtr =
        FridaNativeUtils.requireValidPointer(applicationPtr, "Application pointer");
    log.debug("Application created");
  }

  public String getIdentifier() {
    ensureNotClosed();
    try {
      MemorySegment result =
          (MemorySegment) FRIDA_APPLICATION_GET_IDENTIFIER.invoke(applicationPtr);
      String identifier = FridaNativeUtils.memorySegmentToString(result);
      log.trace("Got application identifier: {}", identifier);
      return identifier;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get application identifier: {}", e.getMessage());
      throw new FridaException("Failed to get application identifier", e);
    }
  }

  public String getName() {
    ensureNotClosed();
    try {
      MemorySegment result = (MemorySegment) FRIDA_APPLICATION_GET_NAME.invoke(applicationPtr);
      String name = FridaNativeUtils.memorySegmentToString(result);
      log.trace("Got application name: {}", name);
      return name;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get application name: {}", e.getMessage());
      throw new FridaException("Failed to get application name", e);
    }
  }

  public int getPid() {
    ensureNotClosed();
    try {
      int pid = (int) FRIDA_APPLICATION_GET_PID.invoke(applicationPtr);
      log.trace("Got application PID: {}", pid);
      return pid;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get application PID: {}", e.getMessage());
      throw new FridaException("Failed to get application PID", e);
    }
  }

  /**
   * Get application parameters such as version, path, etc.
   *
   * @return Map of parameter names to values
   */
  public Map<String, Object> getParams() {
    ensureNotClosed();
    try {
      MemorySegment hashTablePtr =
          (MemorySegment) FRIDA_APPLICATION_GET_PARAMETERS.invoke(applicationPtr);
      Map<String, Object> params = GHashTableUtil.toMap(hashTablePtr);
      log.trace("Got application parameters: {}", params);
      return params;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get application parameters: {}", e.getMessage());
      throw new FridaException("Failed to get application parameters", e);
    }
  }

  @Override
  public String toString() {
    return String.format(
        "Application{identifier='%s', name='%s', pid=%d}", getIdentifier(), getName(), getPid());
  }

  @Override
  public void close() {
    if (!closed) {
      closed = true;
      FridaNativeUtils.fridaUnref(applicationPtr);
      log.trace("Application closed");
    }
  }

  private void ensureNotClosed() {
    if (closed) {
      throw new IllegalStateException("Application has been closed");
    }
  }
}
