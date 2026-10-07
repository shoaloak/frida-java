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
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;

/** Main Frida class with safe initialization/deinitialization */
public class Frida {
  private static final Logger log = LoggerFactory.getLogger(Frida.class);
  private static final MethodHandle FRIDA_VERSION_STRING;
  private static final MethodHandle FRIDA_INIT;

  // Atomic state management to prevent init/deinit race conditions
  private static final AtomicBoolean isInitialized = new AtomicBoolean(false);
  private static final Object initLock = new Object();

  static {
    FRIDA_VERSION_STRING =
        FridaLibraryLoader.findFunction(
            "frida_version_string", FunctionDescriptor.of(ValueLayout.ADDRESS));
    FRIDA_INIT = FridaLibraryLoader.findFunction("frida_init", FunctionDescriptor.ofVoid());

    // Initialize Frida immediately when the class is loaded
    ensureInitialized();
  }

  /**
   * Ensure Frida is initialized. This method is thread-safe and idempotent. Called automatically
   * when the class is loaded and by other Frida classes.
   */
  static void ensureInitialized() {
    if (!isInitialized.get()) {
      synchronized (initLock) {
        if (!isInitialized.get()) {
          log.debug("Initializing Frida library");
          try {
            FRIDA_INIT.invoke();
            isInitialized.set(true);
            log.debug("Frida library initialized successfully");

          } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
          } catch (Throwable e) {
            throw new FridaException("Failed to initialize Frida", e);
          }
        }
      }
    }
  }

  /**
   * Get the Frida version components.
   *
   * @return A String representing the Frida version.
   */
  public static String getVersion() {
    try {
      log.trace("Getting Frida version");
      MemorySegment versionPtr = (MemorySegment) FRIDA_VERSION_STRING.invoke();
      String version = FridaNativeUtils.memorySegmentToString(versionPtr);
      log.debug("Frida version: {}", version);
      return version;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get Frida version: {}", e.getMessage(), e);
      throw new FridaException("Failed to get Frida version", e);
    }
  }

  /*
   * Explicitly deinitialize Frida. This is mainly for testing purposes. This method is thread-safe
   * and idempotent.
   */
  //    public static void deinit() {
  //        if (isInitialized.compareAndSet(true, false)) {
  //            synchronized (initLock) {
  //                try {
  //                    FRIDA_DEINIT.invoke();
  //                    // Note that frida_deinit calls frida_shutdown internally
  //                    System.err.println("");
  //                } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
  //                    throw e;
  //                } catch (Throwable e) {
  //                    // Reset the flag if deinit failed
  //                    isInitialized.set(true);
  //                    throw new RuntimeException("Failed to deinitialize Frida", e);
  //                }
  //            }
  //        }
  //    }
}
