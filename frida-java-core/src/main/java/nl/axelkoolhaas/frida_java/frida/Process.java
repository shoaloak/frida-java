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

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * Represents a process on a Frida device
 */
public class Process {
    private final MemorySegment processPtr;

    private static final MethodHandle FRIDA_PROCESS_GET_PID;
    private static final MethodHandle FRIDA_PROCESS_GET_NAME;
    // Unsure???
//    private static final MethodHandle FRIDA_PROCESS_MATCH_OPTIONS_NEW;
//    private static final MethodHandle FRIDA_PROCESS_MATCH_OPTIONS_SET_TIMEOUT;
//    private static final MethodHandle FRIDA_PROCESS_MATCH_OPTIONS_SET_SCOPE;
//    private static final MethodHandle FRIDA_DEVICE_GET_PROCESS_BY_PID_SYNC;
//    private static final MethodHandle FRIDA_DEVICE_GET_PROCESS_BY_NAME_SYNC;
//    private static final MethodHandle FRIDA_DEVICE_FIND_PROCESS_BY_PID_SYNC;
//    private static final MethodHandle FRIDA_DEVICE_FIND_PROCESS_BY_NAME_SYNC;

    static {
        Frida.ensureInitialized();

        FRIDA_PROCESS_GET_PID = FridaLibraryLoader.findFunction("frida_process_get_pid",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_PROCESS_GET_NAME = FridaLibraryLoader.findFunction("frida_process_get_name",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /**
     * Create a Process wrapper around a native process pointer
     * @param processPtr Native process pointer
     */
    public Process(MemorySegment processPtr) {
        this.processPtr = FridaNativeUtils.requireValidPointer(processPtr, "Process pointer");
    }

    /**
     * Get the process ID
     * @return Process ID (PID)
     */
    public int getPid() {
        try {
            return (int) FRIDA_PROCESS_GET_PID.invoke(processPtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get process PID", e);
        }
    }

    /**
     * Get the process name
     * @return Process name
     */
    public String getName() {
        try {
            MemorySegment namePtr = (MemorySegment) FRIDA_PROCESS_GET_NAME.invoke(processPtr);
            return FridaNativeUtils.memorySegmentToString(namePtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get process name", e);
        }
    }

    @Override
    public String toString() {
        return String.format("Process{pid=%d, name='%s'}", getPid(), getName());
    }
}
