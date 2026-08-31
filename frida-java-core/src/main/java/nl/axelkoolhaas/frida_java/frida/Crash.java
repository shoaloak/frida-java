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

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GHashTableUtil;

/** Represents a crash of Frida. */
public final class Crash implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(Crash.class);
  private final MemorySegment crashPtr;
  private final boolean owned;
  private volatile boolean closed = false;

  // Native method handles
  private static final MethodHandle FRIDA_CRASH_GET_PID;
  private static final MethodHandle FRIDA_CRASH_GET_PROCESS_NAME;
  private static final MethodHandle FRIDA_CRASH_GET_SUMMARY;
  private static final MethodHandle FRIDA_CRASH_GET_REPORT;
  private static final MethodHandle FRIDA_CRASH_GET_PARAMETERS;

  static {
    Frida.ensureInitialized();
    FRIDA_CRASH_GET_PID =
        FridaLibraryLoader.findFunction(
            "frida_crash_get_pid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_CRASH_GET_PROCESS_NAME =
        FridaLibraryLoader.findFunction(
            "frida_crash_get_process_name",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_CRASH_GET_SUMMARY =
        FridaLibraryLoader.findFunction(
            "frida_crash_get_summary",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_CRASH_GET_REPORT =
        FridaLibraryLoader.findFunction(
            "frida_crash_get_report",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_CRASH_GET_PARAMETERS =
        FridaLibraryLoader.findFunction(
            "frida_crash_get_parameters",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  public Crash(final MemorySegment ptr) {
    this(ptr, true);
  }

  /**
   * Create a Crash wrapper with explicit ownership.
   *
   * @param ptr Native crash pointer
   * @param owned Whether this wrapper owns the reference
   */
  public Crash(final MemorySegment ptr, boolean owned) {
    this.crashPtr = FridaNativeUtils.requireValidPointer(ptr, "Crash pointer");
    this.owned = owned;
    log.debug("Crash created (owned={})", owned);
  }

  /** Returns the process identifier of the crashed application. */
  public int getPid() {
    try {
      return (int) FRIDA_CRASH_GET_PID.invokeExact(crashPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError t) {
      throw t;
    } catch (Throwable t) {
      log.debug("Failed to get PID from FridaCrash", t);
      throw new FridaException("Failed to get PID from crash", t);
    }
  }

  /** Returns the name of the process that crashed. */
  @SuppressWarnings("unused")
  public String getProcessName() {
    try {
      MemorySegment namePtr = (MemorySegment) FRIDA_CRASH_GET_PROCESS_NAME.invokeExact(crashPtr);
      return FridaNativeUtils.memorySegmentToString(namePtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError t) {
      throw t;
    } catch (Throwable t) {
      log.debug("Failed to get process name from FridaCrash", t);
      throw new FridaException("Failed to get process name from crash", t);
    }
  }

  /** Returns the summary of the crash. */
  public String getSummary() {
    try {
      MemorySegment summaryPtr = (MemorySegment) FRIDA_CRASH_GET_SUMMARY.invokeExact(crashPtr);
      return FridaNativeUtils.memorySegmentToString(summaryPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError t) {
      throw t;
    } catch (Throwable t) {
      log.debug("Failed to get summary from FridaCrash", t);
      throw new FridaException("Failed to get summary from crash", t);
    }
  }

  /** Returns the report of the crash. */
  public String getReport() {
    try {
      MemorySegment reportPtr = (MemorySegment) FRIDA_CRASH_GET_REPORT.invokeExact(crashPtr);
      return FridaNativeUtils.memorySegmentToString(reportPtr);

    } catch (NullPointerException | IllegalArgumentException | AssertionError t) {
      throw t;
    } catch (Throwable t) {
      log.debug("Failed to get report from FridaCrash", t);
      throw new FridaException("Failed to get report from crash", t);
    }
  }

  /** Returns the parameters of the crash as a map. */
  public Map<String, Object> getParameters() {
    try {
      MemorySegment hashTablePtr = (MemorySegment) FRIDA_CRASH_GET_PARAMETERS.invokeExact(crashPtr);
      if (hashTablePtr == null || hashTablePtr.address() == 0) {
        return Collections.emptyMap();
      }
      return GHashTableUtil.toMap(hashTablePtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError t) {
      throw t;
    } catch (Throwable t) {
      log.debug("Failed to get parameters from FridaCrash", t);
      throw new FridaException("Failed to get parameters from crash", t);
    }
  }

  /** Cleans resources held by the crash. */
  public void clean() {
    if (owned) {
      FridaNativeUtils.fridaUnref(crashPtr);
    }
  }

  @Override
  public void close() {
    if (!closed) {
      closed = true;
      clean();
      log.trace("Crash closed (owned={})", owned);
    }
  }

  @Override
  public String toString() {
    return String.format("<FridaCrash>: <%s>", Objects.toIdentityString(crashPtr));
  }
}
