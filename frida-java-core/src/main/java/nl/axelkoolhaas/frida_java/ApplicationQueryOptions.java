package nl.axelkoolhaas.frida_java;

/**
 * Options for querying applications.
 */
public class ApplicationQueryOptions implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    /**
     * Constructs a new ApplicationQueryOptions instance.
     */
    public ApplicationQueryOptions() {}
    /**
     * Internal constructor for native use.
     * @param nativePtr Native pointer to the options object
     */
    ApplicationQueryOptions(long nativePtr) { this.nativePtr = nativePtr; }

    /**
     * Set the name filter for application queries.
     * @param name Application name to filter by
     */
    public native void setName(String name);
    /**
     * Get the name filter for application queries.
     * @return Application name filter
     */
    public native String getName();
    /**
     * Set the process ID filter for application queries.
     * @param pid Process ID to filter by
     */
    public native void setPid(int pid);
    /**
     * Get the process ID filter for application queries.
     * @return Process ID filter
     */
    public native int getPid();
    /**
     * Set additional parameters for application queries.
     * @param parameters Map of parameters
     */
    public native void setParameters(java.util.Map<String, Object> parameters);
    /**
     * Get additional parameters for application queries.
     * @return Map of parameters
     */
    public native java.util.Map<String, Object> getParameters();

    /**
     * Close this ApplicationQueryOptions and release native resources.
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
