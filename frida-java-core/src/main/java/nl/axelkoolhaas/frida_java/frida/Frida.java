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
 * Main Frida class
 */
public class Frida {
    private static final MethodHandle FRIDA_VERSION_STRING;
    private static final MethodHandle FRIDA_INIT;
    private static final MethodHandle FRIDA_DEINIT;

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
     */
    public static void init() {
        try {
            FRIDA_INIT.invoke();
        } catch (Throwable e) {
            throw new RuntimeException("Failed to initialize Frida", e);
        }
    }

    /**
     * Deinitialize Frida. Should be called when done using Frida.
     */
    public static void deinit() {
        try {
            FRIDA_DEINIT.invoke();
        } catch (Throwable e) {
            throw new RuntimeException("Failed to deinitialize Frida", e);
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
}
