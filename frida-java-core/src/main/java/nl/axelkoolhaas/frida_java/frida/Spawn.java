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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a spawned process that can be attached to
 */
public class Spawn {
    private static final Logger log = LoggerFactory.getLogger(Spawn.class);
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
        log.debug("Spawn created");
    }

    /**
     * Get the process ID of the spawned process
     * @return process ID
     */
    public int getPid() {
        try {
            int pid = (int) FRIDA_SPAWN_GET_PID.invoke(spawnPtr);
            log.trace("Got spawn PID: {}", pid);
            return pid;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to get spawn PID: {}", e.getMessage());
            throw new FridaException("Failed to get spawn PID", e);
        }
    }

    /**
     * Get the identifier of the spawned process
     * @return process identifier string
     */
    public String getIdentifier() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_SPAWN_GET_IDENTIFIER.invoke(spawnPtr);
            String identifier = FridaNativeUtils.memorySegmentToString(result);
            log.trace("Got spawn identifier: {}", identifier);
            return identifier;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to get spawn identifier: {}", e.getMessage());
            throw new FridaException("Failed to get spawn identifier", e);
        }
    }
}
