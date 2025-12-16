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
import java.util.concurrent.atomic.AtomicBoolean;

import static nl.axelkoolhaas.frida_java.FridaJava.memorySegmentToString;

/**
 * Main Frida class with safe initialization/deinitialization
 */
public class Frida {
    private static final MethodHandle FRIDA_VERSION_STRING;
    private static final MethodHandle FRIDA_INIT;
    private static final MethodHandle FRIDA_DEINIT;

    // Atomic state management to prevent init/deinit race conditions
    private static final AtomicBoolean isInitialized = new AtomicBoolean(false);
    private static final Object initLock = new Object();

    static {
        FRIDA_VERSION_STRING = FridaJava.findFunction("frida_version_string",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_INIT = FridaJava.findFunction("frida_init",
                FunctionDescriptor.ofVoid());
        FRIDA_DEINIT = FridaJava.findFunction("frida_deinit",
                FunctionDescriptor.ofVoid());

        // Register shutdown hook for automatic cleanup
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (isInitialized.compareAndSet(true, false)) {
                try {
                    FRIDA_DEINIT.invoke();
                } catch (Throwable e) {
                    // Silently ignore errors during shutdown as the native library
                    // may already be in the process of being unloaded
                }
            }
        }));
    }

    /**
     * Ensure Frida is initialized. This method is thread-safe and idempotent.
     * Called automatically by other methods, but can also be called explicitly.
     */
    public static void ensureInitialized() {
        if (!isInitialized.get()) {
            synchronized (initLock) {
                if (!isInitialized.get()) {
                    try {
                        FRIDA_INIT.invoke();
                        isInitialized.set(true);
                    } catch (Throwable e) {
                        throw new RuntimeException("Failed to initialize Frida", e);
                    }
                }
            }
        }
    }

    /**
     * Get the Frida version components.
     * @return A String representing the Frida version.
     */
    public static String getVersion() {
        ensureInitialized();
        try {
            MemorySegment result = (MemorySegment) FRIDA_VERSION_STRING.invoke();
            return memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get Frida version", e);
        }
    }
}
