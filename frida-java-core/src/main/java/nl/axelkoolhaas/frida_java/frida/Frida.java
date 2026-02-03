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

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.concurrent.atomic.AtomicBoolean;

import static nl.axelkoolhaas.frida_java.FridaNativeUtils.memorySegmentToString;

/**
 * Main Frida class with safe initialization/deinitialization
 */
public class Frida {
    private static final MethodHandle FRIDA_VERSION_STRING;
    private static final MethodHandle FRIDA_INIT;
    private static final MethodHandle FRIDA_DEINIT; // Not used

    // Atomic state management to prevent init/deinit race conditions
    private static final AtomicBoolean isInitialized = new AtomicBoolean(false);
    private static final Object initLock = new Object();

    static {
        FRIDA_VERSION_STRING = FridaLibraryLoader.findFunction("frida_version_string",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_INIT = FridaLibraryLoader.findFunction("frida_init",
                FunctionDescriptor.ofVoid());
        FRIDA_DEINIT = FridaLibraryLoader.findFunction("frida_deinit",
                FunctionDescriptor.ofVoid());

        // Initialize Frida immediately when the class is loaded
        ensureInitialized();
    }

    /**
     * Ensure Frida is initialized. This method is thread-safe and idempotent.
     * Called automatically when the class is loaded and by other Frida classes.
     */
    static void ensureInitialized() {
        if (!isInitialized.get()) {
            synchronized (initLock) {
                if (!isInitialized.get()) {
                    try {
                        FRIDA_INIT.invoke();
                        isInitialized.set(true);
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
     * @return A String representing the Frida version.
     */
    public static String getVersion() {
        try {
            MemorySegment versionPtr = (MemorySegment) FRIDA_VERSION_STRING.invoke();
            return FridaNativeUtils.memorySegmentToString(versionPtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get Frida version", e);
        }
    }

    /**
     * Explicitly deinitialize Frida. This is mainly for testing purposes.
     * This method is thread-safe and idempotent.
     */
//    public static void deinit() {
//        if (isInitialized.compareAndSet(true, false)) {
//            synchronized (initLock) {
//                try {
//                    FRIDA_DEINIT.invoke();
//                    // Note that frida_deinit calls frida_shutdown internally
//                    System.err.println("");
//                } catch (Throwable e) {
//                    // Reset the flag if deinit failed
//                    isInitialized.set(true);
//                    throw new RuntimeException("Failed to deinitialize Frida", e);
//                }
//            }
//        }
//    }
}
