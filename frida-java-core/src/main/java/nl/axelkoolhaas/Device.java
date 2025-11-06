package nl.axelkoolhaas;

/**
 * Represents a Frida device that can be used for attaching to processes.
 * A device can be local, remote, or USB-connected.
 */
public class Device {

    /** Native pointer to the FridaDevice object */
    private final long nativePtr;
    private volatile boolean disposed = false;

    /**
     * Device types supported by Frida
     */
    public enum Type {
        LOCAL,
        REMOTE,
        USB
    }

    /**
     * Internal constructor called from native code.
     * @param nativePtr Native pointer to FridaDevice
     */
    Device(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the device ID.
     * @return Device identifier string
     */
    public native String getId();

    /**
     * Get the device name.
     * @return Human-readable device name
     */
    public native String getName();

    /**
     * Get the device type.
     * @return Device type (LOCAL, REMOTE, or USB)
     */
    public native Type getType();

    /**
     * Check if the device is lost (disconnected).
     * @return true if the device is no longer available
     */
    public native boolean isLost();

    /**
     * Attach to a process on this device.
     * @param pid Process ID to attach to
     * @return Session object for the attached process
     * @throws RuntimeException if attachment fails
     */
    public native Session attach(int pid);

    /**
     * Attach to a process on this device by name.
     * @param processName Name of the process to attach to
     * @return Session object for the attached process
     * @throws RuntimeException if attachment fails
     */
    public native Session attachByName(String processName);

    /**
     * Spawn a new process on this device.
     * @param program Path to the program to spawn
     * @return Process ID of the spawned process
     * @throws RuntimeException if spawning fails
     */
    public native int spawn(String program);

    /**
     * Spawn a new process on this device with arguments.
     * @param program Path to the program to spawn
     * @param args Command line arguments
     * @return Process ID of the spawned process
     * @throws RuntimeException if spawning fails
     */
    public native int spawn(String program, String[] args);

    /**
     * Resume a previously spawned process.
     * @param pid Process ID to resume
     * @throws RuntimeException if resume fails
     */
    public native void resume(int pid);

    /**
     * Kill a process on this device.
     * @param pid Process ID to kill
     * @throws RuntimeException if kill fails
     */
    public native void kill(int pid);

    /**
     * Enumerate running processes on this device.
     * @return Array of process information
     */
    public native ProcessInfo[] enumerateProcesses();

    /**
     * Get the native pointer (for internal use).
     * @return Native pointer value
     */
    long getNativePtr() {
        return nativePtr;
    }

    /**
     * Clean up native resources.
     */
    private native void disposeNative(long nativePtr);

    /**
     * Dispose of this device and release native resources.
     * This should be called when the device is no longer needed.
     */
    public void dispose() {
        if (!disposed && nativePtr != 0) {
            disposeNative(nativePtr);
            disposed = true;
        }
    }

    @Override
    public String toString() {
        return String.format("Device{name='%s', type=%s, id='%s'}",
            getName(), getType(), getId());
    }


}
