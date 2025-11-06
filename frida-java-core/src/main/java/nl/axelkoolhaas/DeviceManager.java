package nl.axelkoolhaas;

/**
 * Manages Frida devices and provides device enumeration capabilities.
 * This is the main entry point for discovering and accessing Frida devices.
 *
 * <p>This class implements {@link AutoCloseable} to ensure proper cleanup
 * of native resources. Use with try-with-resources or call {@link #close()}
 * explicitly when done.</p>
 */
public class DeviceManager implements AutoCloseable {

    /** Native pointer to the FridaDeviceManager object */
    private final long nativePtr;

    /**
     * Create a new DeviceManager instance.
     */
    public DeviceManager() {
        this.nativePtr = createNative();
    }

    /**
     * Enumerate all available devices.
     * @return Array of available devices
     * @throws RuntimeException if enumeration fails
     */
    public native Device[] enumerateDevices();

    /**
     * Get the local device.
     * This is a convenience method for getting the local system device.
     * @return Local device instance
     * @throws RuntimeException if local device is not available
     */
    public Device getLocalDevice() {
        Device[] devices = enumerateDevices();
        for (Device device : devices) {
            if (device.getType() == Device.Type.LOCAL) {
                return device;
            }
        }
        throw new RuntimeException("Local device not found");
    }

    /**
     * Get device by ID.
     * @param deviceId Device identifier
     * @return Device with the specified ID
     * @throws RuntimeException if device is not found
     */
    public Device getDeviceById(String deviceId) {
        Device[] devices = enumerateDevices();
        for (Device device : devices) {
            if (deviceId.equals(device.getId())) {
                return device;
            }
        }
        throw new RuntimeException("Device not found: " + deviceId);
    }

    /**
     * Get device by name.
     * @param deviceName Device name
     * @return First device with the specified name
     * @throws RuntimeException if device is not found
     */
    public Device getDeviceByName(String deviceName) {
        Device[] devices = enumerateDevices();
        for (Device device : devices) {
            if (deviceName.equals(device.getName())) {
                return device;
            }
        }
        throw new RuntimeException("Device not found: " + deviceName);
    }

    /**
     * Close the device manager and release resources.
     * @throws RuntimeException if close fails
     */
    public native void close();

    /**
     * Get the native pointer (for internal use).
     * @return Native pointer value
     */
    long getNativePtr() {
        return nativePtr;
    }

    /**
     * Create native DeviceManager instance.
     * @return Native pointer
     */
    private native long createNative();



    @Override
    public String toString() {
        return "DeviceManager{}";
    }
}
