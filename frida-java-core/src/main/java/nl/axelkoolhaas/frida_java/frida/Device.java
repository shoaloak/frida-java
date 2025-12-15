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
import java.util.ArrayList;
import java.util.List;

import static nl.axelkoolhaas.frida_java.FridaJava.memorySegmentToString;

/**
 * Represents a device that Frida connects to
 */
public class Device {
    private static final MethodHandle FRIDA_DEVICE_GET_DTYPE;
    private static final MethodHandle FRIDA_DEVICE_GET_ID;
    private static final MethodHandle FRIDA_DEVICE_GET_NAME;
    private static final MethodHandle FRIDA_DEVICE_IS_LOST;
    private static final MethodHandle FRIDA_DEVICE_ENUMERATE_PROCESSES;
    private static final MethodHandle FRIDA_PROCESS_LIST_SIZE;
    private static final MethodHandle FRIDA_PROCESS_LIST_GET;

    private final MemorySegment devicePtr;

    static {
        FRIDA_DEVICE_GET_DTYPE = FridaJava.findFunction("frida_device_get_dtype",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_DEVICE_GET_ID = FridaJava.findFunction("frida_device_get_id",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_GET_NAME = FridaJava.findFunction("frida_device_get_name",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_IS_LOST = FridaJava.findFunction("frida_device_is_lost",
                FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
        FRIDA_DEVICE_ENUMERATE_PROCESSES = FridaJava.findFunction("frida_device_enumerate_processes_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_PROCESS_LIST_SIZE = FridaJava.findFunction("frida_process_list_size",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_PROCESS_LIST_GET = FridaJava.findFunction("frida_process_list_get",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    }

    public Device(MemorySegment devicePtr) {
        this.devicePtr = FridaJava.requireValidPointer(devicePtr, "Device pointer");
    }

    /**
     * Get the device ID
     * @return device ID string, or empty string if device is null
     */
    public String getId() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_DEVICE_GET_ID.invoke(devicePtr);
            return memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get device ID", e);
        }
    }

    /**
     * Get the device name
     * @return device name string, or empty string if device is null
     */
    public String getName() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_DEVICE_GET_NAME.invoke(devicePtr);
            return memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get device name", e);
        }
    }

    /**
     * Get the device type
     * @return device type
     */
    public DeviceType getType() {
        try {
            int typeValue = (int) FRIDA_DEVICE_GET_DTYPE.invoke(devicePtr);
            return DeviceType.fromValue(typeValue);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get device type", e);
        }
    }

    /**
     * Check if the device is lost
     * @return true if the device is lost, false otherwise
     */
    public boolean isLost() {
        try {
            return (boolean) FRIDA_DEVICE_IS_LOST.invoke(devicePtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to check if device is lost", e);
        }
    }

    /**
     * Enumerate processes running on this device
     * @return List of Process objects
     */
    public List<Process> enumerateProcesses() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment processList = (MemorySegment) FRIDA_DEVICE_ENUMERATE_PROCESSES
                    .invoke(devicePtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                throw new RuntimeException("Failed to enumerate processes");
            }

            if (processList.equals(MemorySegment.NULL)) {
                return new ArrayList<>();
            }

            return extractProcessesFromList(processList);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to enumerate processes", e);
        }
    }

    /**
     * Extract Process objects from the native process list
     */
    private List<Process> extractProcessesFromList(MemorySegment processList) throws Throwable {
        int processCount = (int) FRIDA_PROCESS_LIST_SIZE.invoke(processList);
        List<Process> processes = new ArrayList<>(processCount);

        for (int i = 0; i < processCount; i++) {
            MemorySegment processPtr = (MemorySegment) FRIDA_PROCESS_LIST_GET.invoke(processList, i);
            if (!processPtr.equals(MemorySegment.NULL)) {
                processes.add(new Process(processPtr));
            }
        }

        return processes;
    }
}
