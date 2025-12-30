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
import java.util.ArrayList;
import java.util.List;

/**
 * Device manager for enumerating and managing Frida devices
 */
public class DeviceManager implements AutoCloseable {
    private final MemorySegment managerPtr;

    private static final MethodHandle FRIDA_DEVICE_MANAGER_NEW;
    private static final MethodHandle FRIDA_DEVICE_MANAGER_ENUMERATE_DEVICES_SYNC;
    private static final MethodHandle FRIDA_DEVICE_LIST_SIZE;
    private static final MethodHandle FRIDA_DEVICE_LIST_GET;
    private static final MethodHandle FRIDA_DEVICE_MANAGER_CLOSE_SYNC;

    // Using pure Java filtering, as the native method seems to have issues in some environments
//    private static final MethodHandle FRIDA_DEVICE_MANAGER_GET_DEVICE_BY_ID_SYNC;

    static {
        Frida.ensureInitialized();

        FRIDA_DEVICE_MANAGER_NEW = FridaLibraryLoader.findFunction("frida_device_manager_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_DEVICE_MANAGER_ENUMERATE_DEVICES_SYNC = FridaLibraryLoader.findFunction("frida_device_manager_enumerate_devices_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_LIST_SIZE = FridaLibraryLoader.findFunction("frida_device_list_size",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_DEVICE_LIST_GET = FridaLibraryLoader.findFunction("frida_device_list_get",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_DEVICE_MANAGER_CLOSE_SYNC = FridaLibraryLoader.findFunction("frida_device_manager_close_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    public DeviceManager() {
        try {
            MemorySegment managerPtr = (MemorySegment) FRIDA_DEVICE_MANAGER_NEW.invoke();
            this.managerPtr = FridaNativeUtils.requireValidPointer(managerPtr, "Device manager pointer");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to initialize device manager", e);
        }
    }

    /**
     * Enumerate all available devices
     * @return List of Device objects
     */
    public List<Device> enumerateDevices() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment deviceList = (MemorySegment) FRIDA_DEVICE_MANAGER_ENUMERATE_DEVICES_SYNC
                    .invoke(managerPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                throw new RuntimeException("Failed to enumerate devices");
            }

            if (deviceList.equals(MemorySegment.NULL)) {
                return new ArrayList<>();
            }

            return extractDevicesFromList(deviceList);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to enumerate devices", e);
        }
    }

    /**
     * Get the local device
     * @return Local Device object or null if not found
     */
    public Device getLocalDevice() {
        List<Device> devices = enumerateDevices();
        return devices.stream()
                .filter(device -> device.getId().equals("local"))
                .findFirst()
                .orElse(null);
    }

    /**
     * Get a device by its ID
     * @param deviceId The device ID to look for
     * @return Device object or null if not found
     */
    public Device getDeviceById(String deviceId) {
        List<Device> devices = enumerateDevices();
        return devices.stream()
                .filter(device -> deviceId.equals(device.getId()))
                .findFirst()
                .orElse(null);
    }

    /**
     * Get a device by its name
     * @param deviceName The device name to look for
     * @return Device object or null if not found
     */
    public Device getDeviceByName(String deviceName) {
        List<Device> devices = enumerateDevices();
        return devices.stream()
                .filter(device -> deviceName.equals(device.getName()))
                .findFirst()
                .orElse(null);
    }

    public void clean() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            FRIDA_DEVICE_MANAGER_CLOSE_SYNC.invoke(managerPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                System.err.println("Warning: Error during device manager close");
            }
        } catch (Throwable e) {
            // Log error but don't throw, cleanup should be safe
            System.err.println("Warning: Failed to cleanup DeviceManager: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        clean();
    }

    /**
     * Extract Device objects from the native device list
     */
    private List<Device> extractDevicesFromList(MemorySegment deviceList) throws Throwable {
        int deviceCount = (int) FRIDA_DEVICE_LIST_SIZE.invoke(deviceList);
        List<Device> devices = new ArrayList<>(deviceCount);

        for (int i = 0; i < deviceCount; i++) {
            MemorySegment devicePtr = (MemorySegment) FRIDA_DEVICE_LIST_GET.invoke(deviceList, i);
            if (!devicePtr.equals(MemorySegment.NULL)) {
                devices.add(new Device(devicePtr));
            }
        }

        return devices;
    }
}
