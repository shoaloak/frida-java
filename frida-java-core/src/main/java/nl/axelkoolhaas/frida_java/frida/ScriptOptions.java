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
import nl.axelkoolhaas.frida_java.util.GBytesUtil;

/** Options for script creation */
public class ScriptOptions implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(ScriptOptions.class);
  private final MemorySegment optionsPtr;

  private static final MethodHandle FRIDA_SCRIPT_OPTIONS_NEW;
  private static final MethodHandle FRIDA_SCRIPT_OPTIONS_SET_NAME;
  private static final MethodHandle FRIDA_SCRIPT_OPTIONS_SET_SNAPSHOT;
  private static final MethodHandle FRIDA_SCRIPT_OPTIONS_SET_SNAPSHOT_TRANSPORT;
  private static final MethodHandle FRIDA_SCRIPT_OPTIONS_SET_RUNTIME;
  private static final MethodHandle FRIDA_SCRIPT_OPTIONS_GET_NAME;
  private static final MethodHandle FRIDA_SCRIPT_OPTIONS_GET_SNAPSHOT;
  private static final MethodHandle FRIDA_SCRIPT_OPTIONS_GET_SNAPSHOT_TRANSPORT;
  private static final MethodHandle FRIDA_SCRIPT_OPTIONS_GET_RUNTIME;

  static {
    Frida.ensureInitialized();

    FRIDA_SCRIPT_OPTIONS_NEW =
        FridaLibraryLoader.findFunction(
            "frida_script_options_new", FunctionDescriptor.of(ValueLayout.ADDRESS));
    FRIDA_SCRIPT_OPTIONS_SET_NAME =
        FridaLibraryLoader.findFunction(
            "frida_script_options_set_name",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_SCRIPT_OPTIONS_SET_SNAPSHOT =
        FridaLibraryLoader.findFunction(
            "frida_script_options_set_snapshot",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_SCRIPT_OPTIONS_SET_SNAPSHOT_TRANSPORT =
        FridaLibraryLoader.findFunction(
            "frida_script_options_set_snapshot_transport",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_SCRIPT_OPTIONS_SET_RUNTIME =
        FridaLibraryLoader.findFunction(
            "frida_script_options_set_runtime",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_SCRIPT_OPTIONS_GET_NAME =
        FridaLibraryLoader.findFunction(
            "frida_script_options_get_name",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_SCRIPT_OPTIONS_GET_SNAPSHOT =
        FridaLibraryLoader.findFunction(
            "frida_script_options_get_snapshot",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_SCRIPT_OPTIONS_GET_SNAPSHOT_TRANSPORT =
        FridaLibraryLoader.findFunction(
            "frida_script_options_get_snapshot_transport",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_SCRIPT_OPTIONS_GET_RUNTIME =
        FridaLibraryLoader.findFunction(
            "frida_script_options_get_runtime",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
  }

  /** Create new script options with default settings */
  public ScriptOptions() {
    try {
      this.optionsPtr = (MemorySegment) FRIDA_SCRIPT_OPTIONS_NEW.invoke();
      log.debug("ScriptOptions created");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to create ScriptOptions: {}", e.getMessage());
      throw new FridaException("Failed to create ScriptOptions", e);
    }
  }

  /**
   * Set the name of the script
   *
   * @param name Script name
   */
  public void setName(String name) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment namePtr = arena.allocateFrom(name);
      FRIDA_SCRIPT_OPTIONS_SET_NAME.invoke(optionsPtr, namePtr);
      log.trace("Set script name: {}", name);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set script name: {}", e.getMessage());
      throw new FridaException("Failed to set script name", e);
    }
  }

  /**
   * Set the snapshot data for the script
   *
   * @param snapshot Snapshot bytes
   */
  public void setSnapshot(byte[] snapshot) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment gBytesData = GBytesUtil.fromByteArray(snapshot, arena);
      FRIDA_SCRIPT_OPTIONS_SET_SNAPSHOT.invoke(optionsPtr, gBytesData);
      log.trace("Set script snapshot ({} bytes)", snapshot.length);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set script snapshot: {}", e.getMessage());
      throw new FridaException("Failed to set script snapshot", e);
    }
  }

  /**
   * Set the snapshot transport mechanism
   *
   * @param transport Transport mechanism
   */
  public void setSnapshotTransport(SnapshotTransport transport) {
    try {
      FRIDA_SCRIPT_OPTIONS_SET_SNAPSHOT_TRANSPORT.invoke(optionsPtr, transport.getValue());
      log.trace("Set snapshot transport: {}", transport);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set snapshot transport: {}", e.getMessage());
      throw new FridaException("Failed to set snapshot transport", e);
    }
  }

  /**
   * Set the runtime engine for the script
   *
   * @param runtime Runtime engine
   */
  public void setRuntime(ScriptRuntime runtime) {
    try {
      FRIDA_SCRIPT_OPTIONS_SET_RUNTIME.invoke(optionsPtr, runtime.getValue());
      log.trace("Set script runtime: {}", runtime);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set script runtime: {}", e.getMessage());
      throw new FridaException("Failed to set script runtime", e);
    }
  }

  /**
   * Get the name of the script
   *
   * @return Script name
   */
  public String getName() {
    try {
      MemorySegment namePtr = (MemorySegment) FRIDA_SCRIPT_OPTIONS_GET_NAME.invoke(optionsPtr);
      String name = FridaNativeUtils.memorySegmentToString(namePtr);
      log.trace("Got script name: {}", name);
      return name;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get script name: {}", e.getMessage());
      throw new FridaException("Failed to get script name", e);
    }
  }

  /**
   * Get the snapshot data
   *
   * @return Snapshot bytes
   */
  public byte[] getSnapshot() {
    try {
      MemorySegment gBytesPtr =
          (MemorySegment) FRIDA_SCRIPT_OPTIONS_GET_SNAPSHOT.invoke(optionsPtr);
      byte[] snapshot = GBytesUtil.toByteArray(gBytesPtr);
      log.trace("Got script snapshot ({} bytes)", snapshot.length);
      return snapshot;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get script snapshot: {}", e.getMessage());
      throw new FridaException("Failed to get script snapshot", e);
    }
  }

  /**
   * Get the snapshot transport mechanism
   *
   * @return Transport mechanism
   */
  public SnapshotTransport getSnapshotTransport() {
    try {
      int value = (int) FRIDA_SCRIPT_OPTIONS_GET_SNAPSHOT_TRANSPORT.invoke(optionsPtr);
      SnapshotTransport transport = SnapshotTransport.fromValue(value);
      log.trace("Got snapshot transport: {}", transport);
      return transport;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get snapshot transport: {}", e.getMessage());
      throw new FridaException("Failed to get snapshot transport", e);
    }
  }

  /**
   * Get the runtime engine
   *
   * @return Runtime engine
   */
  public ScriptRuntime getRuntime() {
    try {
      int value = (int) FRIDA_SCRIPT_OPTIONS_GET_RUNTIME.invoke(optionsPtr);
      ScriptRuntime runtime = ScriptRuntime.fromValue(value);
      log.trace("Got script runtime: {}", runtime);
      return runtime;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get script runtime: {}", e.getMessage());
      throw new FridaException("Failed to get script runtime", e);
    }
  }

  /**
   * Get the native pointer to the options struct Used internally when passing options to session
   * methods
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
      throw new FridaException("Failed to cleanup ScriptOptions", e);
    }
  }
}
