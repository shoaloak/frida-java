package nl.axelkoolhaas;

/**
 * Represents a Frida session attached to a process.
 * A session allows script creation and communication with the target process.
 *
 * <p>This class implements {@link AutoCloseable} to ensure proper cleanup
 * of native resources. Use with try-with-resources or call {@link #detach()}
 * explicitly when done.</p>
 */
public class Session implements AutoCloseable {

    /** Native pointer to the FridaSession object */
    private final long nativePtr;

    /**
     * Session detach reasons
     */
    public enum DetachReason {
        APPLICATION_REQUESTED,
        PROCESS_REPLACED,
        PROCESS_TERMINATED,
        CONNECTION_TERMINATED,
        DEVICE_LOST
    }

    /**
     * Internal constructor called from native code.
     * @param nativePtr Native pointer to FridaSession
     */
    Session(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the process ID this session is attached to.
     * @return Process ID
     */
    public native int getPid();

    /**
     * Check if this session is detached.
     * @return true if the session is detached
     */
    public native boolean isDetached();

    /**
     * Detach from the target process.
     * @throws RuntimeException if detach fails
     */
    public native void detach();

    /**
     * Closes this session and releases any system resources associated with it.
     * This method calls {@link #detach()} if the session is not already detached.
     */
    @Override
    public void close() {
        if (!isDetached()) {
            detach();
        }
    }

    /**
     * Create a script in this session.
     * @param source JavaScript source code
     * @return Script object
     * @throws RuntimeException if script creation fails
     */
    public native Script createScript(String source);

    /**
     * Create a script in this session with options.
     * @param source JavaScript source code
     * @param name Script name
     * @return Script object
     * @throws RuntimeException if script creation fails
     */
    public native Script createScript(String source, String name);

    /**
     * Enable child gating (spawn gating for child processes).
     * @throws RuntimeException if enable fails
     */
    public native void enableChildGating();

    /**
     * Disable child gating.
     * @throws RuntimeException if disable fails
     */
    public native void disableChildGating();

    /**
     * Get the native pointer (for internal use).
     * @return Native pointer value
     */
    long getNativePtr() {
        return nativePtr;
    }

    @Override
    public String toString() {
        return String.format("Session{pid=%d, detached=%s}", getPid(), isDetached());
    }
}
