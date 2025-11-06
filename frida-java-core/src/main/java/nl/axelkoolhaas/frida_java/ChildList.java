package nl.axelkoolhaas.frida_java;

public class ChildList implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    ChildList(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the number of children in the list.
     * @return Number of children
     */
    public native int size();

    /**
     * Get the child at the specified index.
     * @param index Index of the child
     * @return Child object
     */
    public native Child get(int index);

    /**
     * Convert the child list to an array.
     * @return Array of Child objects
     */
    public native Child[] toArray();

    // Async/sync/finish variants for size
    public native void sizeAsync(Object cancellable, Object callback, Object callbackTarget);
    public native int sizeFinish(Object asyncResult);
    public native int sizeSync(Object cancellable);

    // Async/sync/finish variants for get
    public native void getAsync(int index, Object cancellable, Object callback, Object callbackTarget);
    public native Child getFinish(Object asyncResult);
    public native Child getSync(int index, Object cancellable);

    /**
     * Close this child list and release native resources.
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
