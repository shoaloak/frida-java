package nl.axelkoolhaas.frida_java;

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
    private volatile boolean closed = false;

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
     * This method calls detach() if the session is not already detached.
     * This method is idempotent and safe to call multiple times.
     * <b>Warning:</b> Always call close() explicitly or use try-with-resources.
     */
    @Override
    public void close() {
        if (!closed && nativePtr != 0) {
            try {
                if (!isDetached()) {
                    detach();
                }
            } catch (Exception e) {
                // Ignore exceptions during cleanup
                System.err.println("Warning: Exception during session cleanup: " + e.getMessage());
            } finally {
                closed = true;
            }
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
     * Get the device this session is attached to.
     * @return Device object
     */
    public native Device getDevice();

    /**
     * Get session parameters (if available).
     * @return Parameters as a map
     */
    public native java.util.Map<String, Object> getParameters();

    /**
     * Resume the session if it is suspended.
     * @throws RuntimeException if resume fails
     */
    public native void resume();

    /**
     * Resume the session asynchronously.
     * @param cancellable Optional cancellable object
     * @param callback Callback to invoke when operation completes
     * @param callbackTarget Optional callback target
     */
    public native void resumeAsync(Object cancellable, Object callback, Object callbackTarget);

    /**
     * Complete an asynchronous resume operation.
     * @param asyncResult The async result object
     */
    public native void resumeFinish(Object asyncResult);

    /**
     * Resume the session synchronously.
     * @param cancellable Optional cancellable object
     */
    public native void resumeSync(Object cancellable);

    /**
     * Create a script from bytes in this session.
     * @param bytes JavaScript source code as bytes
     * @return Script object
     * @throws RuntimeException if script creation fails
     */
    public native Script createScriptFromBytes(byte[] bytes);

    /**
     * Create a script from bytes asynchronously.
     * @param bytes JavaScript source code as bytes
     * @param cancellable Optional cancellable object
     * @param callback Callback to invoke when operation completes
     * @param callbackTarget Optional callback target
     */
    public native void createScriptFromBytesAsync(byte[] bytes, Object cancellable, Object callback, Object callbackTarget);

    /**
     * Complete an asynchronous createScriptFromBytes operation.
     * @param asyncResult The async result object
     * @return Script object
     */
    public native Script createScriptFromBytesFinish(Object asyncResult);

    /**
     * Create a script from bytes synchronously.
     * @param bytes JavaScript source code as bytes
     * @param cancellable Optional cancellable object
     * @return Script object
     */
    public native Script createScriptFromBytesSync(byte[] bytes, Object cancellable);

    /**
     * Compile a script in this session.
     * @param source JavaScript source code
     * @return Compiled script as bytes
     * @throws RuntimeException if compilation fails
     */
    public native byte[] compileScript(String source);

    /**
     * Compile a script asynchronously.
     * @param source JavaScript source code
     * @param cancellable Optional cancellable object
     * @param callback Callback to invoke when operation completes
     * @param callbackTarget Optional callback target
     */
    public native void compileScriptAsync(String source, Object cancellable, Object callback, Object callbackTarget);

    /**
     * Complete an asynchronous compileScript operation.
     * @param asyncResult The async result object
     * @return Compiled script as bytes
     */
    public native byte[] compileScriptFinish(Object asyncResult);

    /**
     * Compile a script synchronously.
     * @param source JavaScript source code
     * @param cancellable Optional cancellable object
     * @return Compiled script as bytes
     */
    public native byte[] compileScriptSync(String source, Object cancellable);

    /**
     * Snapshot a script in this session.
     * @param embedScript JavaScript source code to embed
     * @return Snapshot as bytes
     * @throws RuntimeException if snapshot fails
     */
    public native byte[] snapshotScript(String embedScript);

    /**
     * Snapshot a script asynchronously.
     * @param embedScript JavaScript source code to embed
     * @param cancellable Optional cancellable object
     * @param callback Callback to invoke when operation completes
     * @param callbackTarget Optional callback target
     */
    public native void snapshotScriptAsync(String embedScript, Object cancellable, Object callback, Object callbackTarget);

    /**
     * Complete an asynchronous snapshotScript operation.
     * @param asyncResult The async result object
     * @return Snapshot as bytes
     */
    public native byte[] snapshotScriptFinish(Object asyncResult);

    /**
     * Snapshot a script synchronously.
     * @param embedScript JavaScript source code to embed
     * @param cancellable Optional cancellable object
     * @return Snapshot as bytes
     */
    public native byte[] snapshotScriptSync(String embedScript, Object cancellable);

    /**
     * Set up a peer connection for this session.
     * @param options Peer connection options object
     * @throws RuntimeException if setup fails
     */
    public native void setupPeerConnection(Object options);

    /**
     * Set up a peer connection asynchronously.
     * @param options Peer connection options object
     * @param cancellable Optional cancellable object
     * @param callback Callback to invoke when operation completes
     * @param callbackTarget Optional callback target
     */
    public native void setupPeerConnectionAsync(Object options, Object cancellable, Object callback, Object callbackTarget);

    /**
     * Complete an asynchronous setupPeerConnection operation.
     * @param asyncResult The async result object
     */
    public native void setupPeerConnectionFinish(Object asyncResult);

    /**
     * Set up a peer connection synchronously.
     * @param options Peer connection options object
     * @param cancellable Optional cancellable object
     */
    public native void setupPeerConnectionSync(Object options, Object cancellable);

    /**
     * Join a portal for this session.
     * @param address Portal address
     * @param options Portal options object
     * @throws RuntimeException if join fails
     */
    public native Object joinPortal(String address, Object options);

    /**
     * Join a portal asynchronously.
     * @param address Portal address
     * @param options Portal options object
     * @param cancellable Optional cancellable object
     * @param callback Callback to invoke when operation completes
     * @param callbackTarget Optional callback target
     */
    public native void joinPortalAsync(String address, Object options, Object cancellable, Object callback, Object callbackTarget);

    /**
     * Complete an asynchronous joinPortal operation.
     * @param asyncResult The async result object
     * @return Portal membership object
     */
    public native Object joinPortalFinish(Object asyncResult);

    /**
     * Join a portal synchronously.
     * @param address Portal address
     * @param options Portal options object
     * @param cancellable Optional cancellable object
     * @return Portal membership object
     */
    public native Object joinPortalSync(String address, Object options, Object cancellable);

    /**
     * Get the persist timeout for this session, if available.
     * @return Persist timeout in milliseconds
     */
    public native int getPersistTimeout();

    /**
     * Register a callback to be invoked when the session is detached.
     * @param callback Runnable to invoke on detach
     */
    public native void onDetached(Runnable callback);

    /**
     * Register a callback to be invoked when the session is detached, with reason and crash info.
     * @param callback Callback accepting DetachReason and optional Crash object
     */
    public native void onDetachedWithReason(Object callback); // Use appropriate functional interface

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
