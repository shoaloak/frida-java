package nl.axelkoolhaas.frida_java;

/**
 * Represents a list of Frida Processes.
 */
public class ProcessList implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    /**
     * Internal constructor for native use only.
     * @param nativePtr Native pointer to the process list
     */
    ProcessList(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Returns the number of processes in this list.
     * <b>Note:</b> This does not close the list; you must still call {@link #close()} when done.
     * @return Number of processes
     */
    public native int size();

    /**
     * Returns the process at the specified index.
     * <b>Note:</b> The returned {@link Process} must be closed by the caller to avoid leaking resources.
     * @param index Index of the process
     * @return Process object at the given index
     */
    public native Process get(int index);

    /**
     * Converts this list to a Java array of {@link Process} objects.
     * <b>Note:</b> Each {@link Process} in the array must be closed by the caller.
     * @return Array of Process objects
     */
    public native Process[] toArray();

    /**
     * Asynchronously gets the number of processes in this list.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void sizeAsync(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Completes an asynchronous size operation.
     * @param asyncResult Result object from the async call
     * @return Number of processes
     */
    public native int sizeFinish(Object asyncResult);
    /**
     * Synchronously gets the number of processes in this list.
     * @param cancellable Optional cancellable object
     * @return Number of processes
     */
    public native int sizeSync(Object cancellable);

    /**
     * Asynchronously gets the process at the specified index.
     * @param index Index of the process
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getAsync(int index, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Completes an asynchronous get operation.
     * @param asyncResult Result object from the async call
     * @return Process object
     */
    public native Process getFinish(Object asyncResult);
    /**
     * Synchronously gets the process at the specified index.
     * @param index Index of the process
     * @param cancellable Optional cancellable object
     * @return Process object
     */
    public native Process getSync(int index, Object cancellable);

    /**
     * Closes this process list and releases native resources.
     * This method is idempotent and safe to call multiple times.
     * <b>Warning:</b> Always call close() explicitly or use try-with-resources.
     */
    @Override
    public void close() {
        if (!closed && nativePtr != 0) {
            disposeNative(nativePtr);
            // Set nativePtr to 0 to prevent use-after-free
            nativePtr = 0;
            closed = true;
        }
    }

    /**
     * Native method to release native resources.
     * @param nativePtr Native pointer to the process list
     */
    private native void disposeNative(long nativePtr);
}
