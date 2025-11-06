package nl.axelkoolhaas.frida_java;

/**
 * Represents a list of Frida Devices.
 */
public class DeviceList implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    DeviceList(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the number of devices in the list.
     * @return Number of devices
     */
    public native int size();

    /**
     * Get the device at the specified index.
     * @param index Index of the device
     * @return Device object
     */
    public native Device get(int index);

    /**
     * Convert the device list to an array.
     * @return Array of Device objects
     */
    public native Device[] toArray();

    // Async/sync/finish variants for size
    public native void sizeAsync(Object cancellable, Object callback, Object callbackTarget);
    public native int sizeFinish(Object asyncResult);
    public native int sizeSync(Object cancellable);

    // Async/sync/finish variants for get
    public native void getAsync(int index, Object cancellable, Object callback, Object callbackTarget);
    public native Device getFinish(Object asyncResult);
    public native Device getSync(int index, Object cancellable);

    /**
     * Close this device list and release native resources.
     * This method is idempotent and safe to call multiple times.
     * <b>Warning:</b> Always call close() explicitly or use try-with-resources.
     */
    @Override
    public void close() {
        if (!closed && nativePtr != 0) {
            disposeNative(nativePtr);
            closed = true;
        }
    }

    /**
     * Native method to release native resources.
     */
    private native void disposeNative(long nativePtr);
}
