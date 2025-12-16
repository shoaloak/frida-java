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

import nl.axelkoolhaas.frida_java.FridaJava;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static nl.axelkoolhaas.frida_java.FridaJava.memorySegmentToString;

/**
 * Main Frida class with safe initialization/deinitialization
 */
public class Frida {
    private static final MethodHandle FRIDA_VERSION_STRING;
    private static final MethodHandle FRIDA_INIT;
    private static final MethodHandle FRIDA_DEINIT;

    // Reference counting and synchronization to prevent race conditions
    private static int fridaRefCount = 0;
    private static final Object fridaRefMutex = new Object();

    static {
        FRIDA_VERSION_STRING = FridaJava.findFunction("frida_version_string",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_INIT = FridaJava.findFunction("frida_init",
                FunctionDescriptor.ofVoid());
        FRIDA_DEINIT = FridaJava.findFunction("frida_deinit",
                FunctionDescriptor.ofVoid());
    }

    /**
     * Initialize Frida. Must be called before using any other Frida functionality.
     * This method is thread-safe and uses reference counting to ensure frida_init()
     * is only called once.
     */
    public static void init() {
        synchronized (fridaRefMutex) {
            // Only call frida_init() on the first initialization
            if (fridaRefCount == 0) {
                try {
                    FRIDA_INIT.invoke();
                } catch (Throwable e) {
                    throw new RuntimeException("Failed to initialize Frida", e);
                }
            }
            fridaRefCount++;
        }
    }

    /**
     * Deinitialize Frida. Should be called when done using Frida.
     * This method is thread-safe and uses reference counting.
     * Note: frida_deinit() is not called during normal execution to avoid crashes
     * when multiple test classes or components try to deinitialize Frida.
     * The Frida library will clean up automatically when the JVM shuts down.
     */
    public static void deinit() {
        synchronized (fridaRefMutex) {
            if (fridaRefCount > 0) {
                fridaRefCount--;
                // Don't call frida_deinit() during normal execution to avoid crashes
                // when multiple test classes or components try to deinitialize Frida.
                // The Frida library will clean up automatically when the JVM shuts down.
            }
        }
    }

    /**
     * Get the Frida version components.
     * @return A String representing the Frida version.
     */
    public static String getVersion() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_VERSION_STRING.invoke();
            return memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get Frida version", e);
        }
    }

    /**
     * Get the current reference count (for debugging purposes).
     * @return The current Frida reference count
     */
    public static int getRefCount() {
        synchronized (fridaRefMutex) {
            return fridaRefCount;
        }
    }
}
