package nl.axelkoolhaas.frida_java;

public class SpawnList implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    SpawnList(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the number of spawns in the list.
     * @return Number of spawns
     */
    public native int size();

    /**
     * Get the spawn at the specified index.
     * @param index Index of the spawn
     * @return Spawn object
     */
    public native Spawn get(int index);

    /**
     * Convert the spawn list to an array.
     * @return Array of Spawn objects
     */
    public native Spawn[] toArray();

    // Async/sync/finish variants for size
    public native void sizeAsync(Object cancellable, Object callback, Object callbackTarget);
    public native int sizeFinish(Object asyncResult);
    public native int sizeSync(Object cancellable);

    // Async/sync/finish variants for get
    public native void getAsync(int index, Object cancellable, Object callback, Object callbackTarget);
    public native Spawn getFinish(Object asyncResult);
    public native Spawn getSync(int index, Object cancellable);

    /**
     * Close this spawn list and release native resources.
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
