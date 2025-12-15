package nl.axelkoolhaas.frida_java.frida;

import nl.axelkoolhaas.frida_java.FridaJava;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.List;

/**
 * Device manager for enumerating and managing Frida devices
 */
public class DeviceManager {
    private static final MethodHandle FRIDA_DEVICE_MANAGER_NEW;
    private static final MethodHandle FRIDA_DEVICE_MANAGER_ENUMERATE_DEVICES_SYNC;
    private static final MethodHandle FRIDA_DEVICE_LIST_SIZE;
    private static final MethodHandle FRIDA_DEVICE_LIST_GET;

    // Using pure Java filtering, as the native method seems to have issues in some environments
//    private static final MethodHandle FRIDA_DEVICE_MANAGER_GET_DEVICE_BY_ID_SYNC;

    private final MemorySegment managerPtr;

    static {
        FRIDA_DEVICE_MANAGER_NEW = FridaJava.findFunction("frida_device_manager_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_DEVICE_MANAGER_ENUMERATE_DEVICES_SYNC = FridaJava.findFunction("frida_device_manager_enumerate_devices_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_LIST_SIZE = FridaJava.findFunction("frida_device_list_size",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_DEVICE_LIST_GET = FridaJava.findFunction("frida_device_list_get",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    }

    public DeviceManager() {
        try {
            MemorySegment managerPtr = (MemorySegment) FRIDA_DEVICE_MANAGER_NEW.invoke();
            this.managerPtr = FridaJava.requireValidPointer(managerPtr, "Device manager pointer");
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
