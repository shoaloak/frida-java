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

/**
 * Represents a spawned process that can be attached to
 */
public class Spawn {
    private final MemorySegment spawnPtr;

    private static final MethodHandle FRIDA_SPAWN_GET_PID;
    private static final MethodHandle FRIDA_SPAWN_GET_IDENTIFIER;

    static {
        Frida.ensureInitialized();

        FRIDA_SPAWN_GET_PID = FridaLibraryLoader.findFunction("frida_spawn_get_pid",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_SPAWN_GET_IDENTIFIER = FridaLibraryLoader.findFunction("frida_spawn_get_identifier",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    public Spawn(MemorySegment spawnPtr) {
        this.spawnPtr = FridaNativeUtils.requireValidPointer(spawnPtr, "Spawn pointer");
    }

    /**
     * Get the process ID of the spawned process
     * @return process ID
     */
    public int getPid() {
        try {
            return (int) FRIDA_SPAWN_GET_PID.invoke(spawnPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get spawn PID", e);
        }
    }

    /**
     * Get the identifier of the spawned process
     * @return process identifier string
     */
    public String getIdentifier() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_SPAWN_GET_IDENTIFIER.invoke(spawnPtr);
            return FridaNativeUtils.memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get spawn identifier", e);
        }
    }
}
