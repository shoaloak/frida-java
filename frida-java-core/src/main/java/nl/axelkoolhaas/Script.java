package nl.axelkoolhaas;

/**
 * Represents a Frida script that can be injected into a process.
 * Scripts are written in JavaScript and can interact with the target process.
 *
 * <p>This class implements {@link AutoCloseable} to ensure proper cleanup
 * of native resources. Use with try-with-resources or call {@link #unload()}
 * explicitly when done.</p>
 */
public class Script implements AutoCloseable {

    /** Native pointer to the FridaScript object */
    private final long nativePtr;

    /**
     * Script message handler interface
     */
    public interface MessageHandler {
        /**
         * Called when the script sends a message.
         * @param message JSON message from the script
         * @param data Optional binary data
         */
        void onMessage(String message, byte[] data);
    }

    /**
     * Internal constructor called from native code.
     * @param nativePtr Native pointer to FridaScript
     */
    Script(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Load the script into the target process.
     * @throws RuntimeException if loading fails
     */
    public native void load();

    /**
     * Unload this script from the target process.
     * @throws RuntimeException if unloading fails
     */
    public native void unload();

    /**
     * Closes this script and releases any system resources associated with it.
     * This method calls {@link #unload()} if the script is not already destroyed.
     */
    @Override
    public void close() {
        if (!isDestroyed()) {
            unload();
        }
    }

    /**
     * Check if the script is destroyed.
     * @return true if the script is destroyed
     */
    public native boolean isDestroyed();

    /**
     * Post a message to the script.
     * @param message JSON message to send
     * @throws RuntimeException if posting fails
     */
    public native void post(String message);

    /**
     * Post a message to the script with binary data.
     * @param message JSON message to send
     * @param data Binary data to send
     * @throws RuntimeException if posting fails
     */
    public native void post(String message, byte[] data);

    /**
     * Set the message handler for this script.
     * @param handler Message handler to receive script messages
     */
    public native void setMessageHandler(MessageHandler handler);

    /**
     * Get the native pointer (for internal use).
     * @return Native pointer value
     */
    long getNativePtr() {
        return nativePtr;
    }

    @Override
    public String toString() {
        return String.format("Script{destroyed=%s}", isDestroyed());
    }


}
