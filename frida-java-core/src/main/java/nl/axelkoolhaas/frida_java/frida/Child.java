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
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;

/** Represents a child process when child gating is enabled */
public class Child {
  private static final Logger log = LoggerFactory.getLogger(Child.class);
  private final MemorySegment childPtr;

  private static final MethodHandle FRIDA_CHILD_GET_PID;
  private static final MethodHandle FRIDA_CHILD_GET_PARENT_PID;
  private static final MethodHandle FRIDA_CHILD_GET_ORIGIN;
  private static final MethodHandle FRIDA_CHILD_GET_IDENTIFIER;
  private static final MethodHandle FRIDA_CHILD_GET_PATH;
  private static final MethodHandle FRIDA_CHILD_GET_ARGV;
  private static final MethodHandle FRIDA_CHILD_GET_ENVP;

  static {
    Frida.ensureInitialized();

    FRIDA_CHILD_GET_PID =
        FridaLibraryLoader.findFunction(
            "frida_child_get_pid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_CHILD_GET_PARENT_PID =
        FridaLibraryLoader.findFunction(
            "frida_child_get_parent_pid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_CHILD_GET_ORIGIN =
        FridaLibraryLoader.findFunction(
            "frida_child_get_origin",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_CHILD_GET_IDENTIFIER =
        FridaLibraryLoader.findFunction(
            "frida_child_get_identifier",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_CHILD_GET_PATH =
        FridaLibraryLoader.findFunction(
            "frida_child_get_path",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_CHILD_GET_ARGV =
        FridaLibraryLoader.findFunction(
            "frida_child_get_argv",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_CHILD_GET_ENVP =
        FridaLibraryLoader.findFunction(
            "frida_child_get_envp",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  /**
   * Create a Child wrapper around a native child pointer
   *
   * @param childPtr Native child pointer
   */
  public Child(MemorySegment childPtr) {
    this.childPtr = FridaNativeUtils.requireValidPointer(childPtr, "Child pointer");
    log.debug("Child created");
  }

  /**
   * Get the process ID of the child
   *
   * @return Process ID (PID)
   */
  public int getPid() {
    try {
      int pid = (int) FRIDA_CHILD_GET_PID.invoke(childPtr);
      log.trace("Got child PID: {}", pid);
      return pid;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get child PID: {}", e.getMessage());
      throw new FridaException("Failed to get child PID", e);
    }
  }

  /**
   * Get the parent process ID of the child
   *
   * @return Parent process ID (PPID)
   */
  public int getParentPid() {
    try {
      int ppid = (int) FRIDA_CHILD_GET_PARENT_PID.invoke(childPtr);
      log.trace("Got parent PID: {}", ppid);
      return ppid;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get parent PID: {}", e.getMessage());
      throw new FridaException("Failed to get child parent PID", e);
    }
  }

  /**
   * Get the origin of the child
   *
   * @return Child origin
   */
  public ChildOrigin getOrigin() {
    try {
      int origin = (int) FRIDA_CHILD_GET_ORIGIN.invoke(childPtr);
      log.trace("Got child origin: {}", origin);
      return ChildOrigin.fromValue(origin);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get child origin: {}", e.getMessage());
      throw new FridaException("Failed to get child origin", e);
    }
  }

  /**
   * Get the string identifier of the child
   *
   * @return Process identifier string
   */
  public String getIdentifier() {
    try {
      MemorySegment result = (MemorySegment) FRIDA_CHILD_GET_IDENTIFIER.invoke(childPtr);
      String identifier = FridaNativeUtils.memorySegmentToString(result);
      log.trace("Got child identifier: {}", identifier);
      return identifier;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get child identifier: {}", e.getMessage());
      throw new FridaException("Failed to get child identifier", e);
    }
  }

  /**
   * Get the path of the child
   *
   * @return Process path
   */
  public String getPath() {
    try {
      MemorySegment result = (MemorySegment) FRIDA_CHILD_GET_PATH.invoke(childPtr);
      String path = FridaNativeUtils.memorySegmentToString(result);
      log.trace("Got child path: {}", path);
      return path;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get child path: {}", e.getMessage());
      throw new FridaException("Failed to get child path", e);
    }
  }

  /**
   * Get the argv passed to the child
   *
   * @return List of command line arguments
   */
  public List<String> getArgv() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment lengthPtr = arena.allocate(ValueLayout.JAVA_INT);
      MemorySegment argvPtr = (MemorySegment) FRIDA_CHILD_GET_ARGV.invoke(childPtr, lengthPtr);

      if (argvPtr.equals(MemorySegment.NULL)) {
        log.trace("Child argv is empty");
        return new ArrayList<>();
      }

      int length = lengthPtr.get(ValueLayout.JAVA_INT, 0);
      List<String> argv = new ArrayList<>(length);

      for (int i = 0; i < length; i++) {
        MemorySegment strPtr = argvPtr.getAtIndex(ValueLayout.ADDRESS, i);
        if (!strPtr.equals(MemorySegment.NULL)) {
          String arg = FridaNativeUtils.memorySegmentToString(strPtr);
          argv.add(arg);
          log.trace("Child argv[{}]: {}", i, arg);
        }
      }

      return argv;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get child argv: {}", e.getMessage());
      throw new FridaException("Failed to get child argv", e);
    }
  }

  /**
   * Get the envp passed to the child
   *
   * @return List of environment variables
   */
  public List<String> getEnvp() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment lengthPtr = arena.allocate(ValueLayout.JAVA_INT);
      MemorySegment envpPtr = (MemorySegment) FRIDA_CHILD_GET_ENVP.invoke(childPtr, lengthPtr);

      if (envpPtr.equals(MemorySegment.NULL)) {
        log.trace("Child envp is empty");
        return new ArrayList<>();
      }

      int length = lengthPtr.get(ValueLayout.JAVA_INT, 0);
      List<String> envp = new ArrayList<>(length);

      for (int i = 0; i < length; i++) {
        MemorySegment strPtr = envpPtr.getAtIndex(ValueLayout.ADDRESS, i);
        if (!strPtr.equals(MemorySegment.NULL)) {
          String env = FridaNativeUtils.memorySegmentToString(strPtr);
          envp.add(env);
          log.trace("Child envp[{}]: {}", i, env);
        }
      }

      return envp;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get child envp: {}", e.getMessage());
      throw new FridaException("Failed to get child envp", e);
    }
  }

  @Override
  public String toString() {
    return String.format(
        "Child{pid=%d, parentPid=%d, origin=%s, identifier='%s', path='%s'}",
        getPid(), getParentPid(), getOrigin(), getIdentifier(), getPath());
  }
}
