package nl.axelkoolhaas.frida_java;

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
    private volatile boolean closed = false;

    /**
     * Create a new DeviceManager instance.
     */
    public DeviceManager() {
        this.nativePtr = createNative();
    }

    // Additional constructors for other backends
    /**
     * Create a DeviceManager with only non-local backends.
     * @return DeviceManager instance
     */
    public static native DeviceManager withNonlocalBackendsOnly();
    /**
     * Create a DeviceManager with only the socket backend.
     * @return DeviceManager instance
     */
    public static native DeviceManager withSocketBackendOnly();

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

    // Async/sync close
    /**
     * Complete an asynchronous close operation.
     * @param asyncResult Result object from the async call
     */
    public native void closeFinish(Object asyncResult); // Placeholder for Gio.AsyncResult

    /**
     * Close the device manager synchronously.
     * @param cancellable Optional cancellable object
     */
    public native void closeSync(Object cancellable); // Placeholder for Gio.Cancellable

    // Device lookup by ID
    /**
     * Asynchronously look up a device by ID.
     * @param id Device identifier
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getDeviceById(String id, int timeout, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous device lookup by ID.
     * @param asyncResult Result object from the async call
     * @return Device with the specified ID
     */
    public native Device getDeviceByIdFinish(Object asyncResult);
    /**
     * Synchronously look up a device by ID.
     * @param id Device identifier
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @return Device with the specified ID
     */
    public native Device getDeviceByIdSync(String id, int timeout, Object cancellable);

    // Device lookup by type
    /**
     * Asynchronously look up a device by type.
     * @param type Device type
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getDeviceByType(int type, int timeout, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous device lookup by type.
     * @param asyncResult Result object from the async call
     * @return Device with the specified type
     */
    public native Device getDeviceByTypeFinish(Object asyncResult);
    /**
     * Synchronously look up a device by type.
     * @param type Device type
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @return Device with the specified type
     */
    public native Device getDeviceByTypeSync(int type, int timeout, Object cancellable);

    // Device lookup by predicate
    /**
     * Asynchronously look up a device by predicate.
     * @param predicate Predicate object
     * @param predicateTarget Target object for the predicate
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getDevice(Object predicate, Object predicateTarget, int timeout, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous device lookup by predicate.
     * @param asyncResult Result object from the async call
     * @return Device matching the predicate
     */
    public native Device getDeviceFinish(Object asyncResult);
    /**
     * Synchronously look up a device by predicate.
     * @param predicate Predicate object
     * @param predicateTarget Target object for the predicate
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @return Device matching the predicate
     */
    public native Device getDeviceSync(Object predicate, Object predicateTarget, int timeout, Object cancellable);

    // Find device by ID
    /**
     * Asynchronously find a device by ID.
     * @param id Device identifier
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void findDeviceById(String id, int timeout, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous find device by ID operation.
     * @param asyncResult Result object from the async call
     * @return Device with the specified ID, or null if not found
     */
    public native Device findDeviceByIdFinish(Object asyncResult);
    /**
     * Synchronously find a device by ID.
     * @param id Device identifier
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @return Device with the specified ID, or null if not found
     */
    public native Device findDeviceByIdSync(String id, int timeout, Object cancellable);

    /**
     * Asynchronously find a device by type.
     * @param type Device type
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void findDeviceByType(int type, int timeout, Object cancellable, Object callback, Object callbackTarget);

    /**
     * Complete an asynchronous find device by type operation.
     * @param asyncResult Result object from the async call
     * @return Device with the specified type, or null if not found
     */
    public native Device findDeviceByTypeFinish(Object asyncResult);

    /**
     * Synchronously find a device by type.
     * @param type Device type
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @return Device with the specified type, or null if not found
     */
    public native Device findDeviceByTypeSync(int type, int timeout, Object cancellable);

    /**
     * Asynchronously find a device by predicate.
     * @param predicate Predicate object
     * @param predicateTarget Target object for the predicate
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void findDevice(Object predicate, Object predicateTarget, int timeout, Object cancellable, Object callback, Object callbackTarget);

    /**
     * Complete an asynchronous find device by predicate operation.
     * @param asyncResult Result object from the async call
     * @return Device matching the predicate, or null if not found
     */
    public native Device findDeviceFinish(Object asyncResult);

    /**
     * Synchronously find a device by predicate.
     * @param predicate Predicate object
     * @param predicateTarget Target object for the predicate
     * @param timeout Timeout in milliseconds
     * @param cancellable Optional cancellable object
     * @return Device matching the predicate, or null if not found
     */
    public native Device findDeviceSync(Object predicate, Object predicateTarget, int timeout, Object cancellable);

    /**
     * Close the device manager and release resources.
     * This method is idempotent and safe to call multiple times.
     * <b>Warning:</b> Always call close() explicitly or use try-with-resources. Do not rely on finalization.
     * @throws RuntimeException if close fails
     */
    @Override
    public void close() {
        if (!closed) {
            closeNative();
            closed = true;
        }
    }

    /**
     * Native method to close and release native resources.
     */
    private native void closeNative();

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
