package nl.axelkoolhaas.frida_java;

/**
 * Represents a Frida Application.
 */
public class Application implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    Application(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the application identifier.
     * @return Application identifier string
     */
    public native String getIdentifier();

    /**
     * Get the application name.
     * @return Application name
     */
    public native String getName();

    /**
     * Get the process ID of the application.
     * @return Process ID
     */
    public native int getPid();

    /**
     * Get the parameters of the application.
     * @return Map of parameters
     */
    public native java.util.Map<String, Object> getParameters();

    /**
     * Close this application and release native resources.
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
     * Get the native pointer for JNI access.
     * @return Native pointer value
     */
    long getNativePtr() {
        return nativePtr;
    }

    /**
     * Native method to release native resources.
     */
    private native void disposeNative(long nativePtr);
}