package nl.axelkoolhaas.frida_java;

/**
 * Represents a Frida device that can be used for attaching to processes.
 * A device can be local, remote, or USB-connected.
 */
public class Device implements AutoCloseable {

    /** Native pointer to the FridaDevice object */
    private final long nativePtr;
    private volatile boolean closed = false;

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
     * Query system parameters asynchronously.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void querySystemParameters(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a system parameter query.
     * @param asyncResult Result object from the async call
     * @return Map of system parameters
     */
    public native java.util.Map<String, Object> querySystemParametersFinish(Object asyncResult);
    /**
     * Query system parameters synchronously.
     * @param cancellable Optional cancellable object
     * @return Map of system parameters
     */
    public native java.util.Map<String, Object> querySystemParametersSync(Object cancellable);

    /**
     * Get the frontmost application asynchronously.
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getFrontmostApplication(Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a frontmost application query.
     * @param asyncResult Result object from the async call
     * @return The frontmost Application
     */
    public native Application getFrontmostApplicationFinish(Object asyncResult);
    /**
     * Get the frontmost application synchronously.
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @return The frontmost Application
     */
    public native Application getFrontmostApplicationSync(Object options, Object cancellable);

    /**
     * Enumerate applications asynchronously.
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void enumerateApplications(Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an application enumeration.
     * @param asyncResult Result object from the async call
     * @return ApplicationList of applications
     */
    public native ApplicationList enumerateApplicationsFinish(Object asyncResult);
    /**
     * Enumerate applications synchronously.
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @return ApplicationList of applications
     */
    public native ApplicationList enumerateApplicationsSync(Object options, Object cancellable);

    /**
     * Enumerate processes asynchronously.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void enumerateProcesses(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a process enumeration.
     * @param asyncResult Result object from the async call
     * @return ProcessList of processes
     */
    public native ProcessList enumerateProcessesFinish(Object asyncResult);
    /**
     * Enumerate processes synchronously.
     * @param cancellable Optional cancellable object
     * @return ProcessList of processes
     */
    public native ProcessList enumerateProcessesSync(Object cancellable);

    /**
     * Enumerate pending spawn asynchronously.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void enumeratePendingSpawn(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a pending spawn enumeration.
     * @param asyncResult Result object from the async call
     * @return SpawnList of pending spawns
     */
    public native SpawnList enumeratePendingSpawnFinish(Object asyncResult);
    /**
     * Enumerate pending spawn synchronously.
     * @param cancellable Optional cancellable object
     * @return SpawnList of pending spawns
     */
    public native SpawnList enumeratePendingSpawnSync(Object cancellable);

    /**
     * Enumerate child processes asynchronously.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void enumerateChild(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a child enumeration.
     * @param asyncResult Result object from the async call
     * @return ChildList of child processes
     */
    public native ChildList enumerateChildFinish(Object asyncResult);
    /**
     * Enumerate child processes synchronously.
     * @param cancellable Optional cancellable object
     * @return ChildList of child processes
     */
    public native ChildList enumerateChildSync(Object cancellable);

    /**
     * Enumerate sessions asynchronously.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void enumerateSessions(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a session enumeration.
     * @param asyncResult Result object from the async call
     * @return Array of Session objects
     */
    public native Session[] enumerateSessionsFinish(Object asyncResult);
    /**
     * Enumerate sessions synchronously.
     * @param cancellable Optional cancellable object
     * @return Array of Session objects
     */
    public native Session[] enumerateSessionsSync(Object cancellable);

    // Get process by PID
    /**
     * Get process by PID asynchronously.
     * @param pid Process ID
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getProcessByPid(int pid, Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a process query by PID.
     * @param asyncResult Result object from the async call
     * @return The Process object
     */
    public native Process getProcessByPidFinish(Object asyncResult);
    /**
     * Get process by PID synchronously.
     * @param pid Process ID
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @return The Process object
     */
    public native Process getProcessByPidSync(int pid, Object options, Object cancellable);

    // Get process by name
    /**
     * Get process by name asynchronously.
     * @param name Process name
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getProcessByName(String name, Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a process query by name.
     * @param asyncResult Result object from the async call
     * @return The Process object
     */
    public native Process getProcessByNameFinish(Object asyncResult);
    /**
     * Get process by name synchronously.
     * @param name Process name
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @return The Process object
     */
    public native Process getProcessByNameSync(String name, Object options, Object cancellable);

    // Get process by predicate
    /**
     * Get process by predicate asynchronously.
     * @param predicate Predicate object
     * @param predicateTarget Target object for the predicate
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getProcess(Object predicate, Object predicateTarget, Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a process query by predicate.
     * @param asyncResult Result object from the async call
     * @return The Process object
     */
    public native Process getProcessFinish(Object asyncResult);
    /**
     * Get process by predicate synchronously.
     * @param predicate Predicate object
     * @param predicateTarget Target object for the predicate
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @return The Process object
     */
    public native Process getProcessSync(Object predicate, Object predicateTarget, Object options, Object cancellable);

    // Find process by PID
    /**
     * Find process by PID asynchronously.
     * @param pid Process ID
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void findProcessByPid(int pid, Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a process find by PID.
     * @param asyncResult Result object from the async call
     * @return The Process object
     */
    public native Process findProcessByPidFinish(Object asyncResult);
    /**
     * Find process by PID synchronously.
     * @param pid Process ID
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @return The Process object
     */
    public native Process findProcessByPidSync(int pid, Object options, Object cancellable);

    // Find process by name
    /**
     * Find process by name asynchronously.
     * @param name Process name
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void findProcessByName(String name, Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a process find by name.
     * @param asyncResult Result object from the async call
     * @return The Process object
     */
    public native Process findProcessByNameFinish(Object asyncResult);
    /**
     * Find process by name synchronously.
     * @param name Process name
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @return The Process object
     */
    public native Process findProcessByNameSync(String name, Object options, Object cancellable);

    // Find process by predicate
    /**
     * Find process by predicate asynchronously.
     * @param predicate Predicate object
     * @param predicateTarget Target object for the predicate
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void findProcess(Object predicate, Object predicateTarget, Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a process find by predicate.
     * @param asyncResult Result object from the async call
     * @return The Process object
     */
    public native Process findProcessFinish(Object asyncResult);
    /**
     * Find process by predicate synchronously.
     * @param predicate Predicate object
     * @param predicateTarget Target object for the predicate
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @return The Process object
     */
    public native Process findProcessSync(Object predicate, Object predicateTarget, Object options, Object cancellable);

    // Enumerate processes (with options)
    /**
     * Enumerate processes with options asynchronously.
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void enumerateProcessesWithOptions(Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a process enumeration with options.
     * @param asyncResult Result object from the async call
     * @return ProcessList of processes
     */
    public native ProcessList enumerateProcessesWithOptionsFinish(Object asyncResult);
    /**
     * Enumerate processes with options synchronously.
     * @param options Query options
     * @param cancellable Optional cancellable object
     * @return ProcessList of processes
     */
    public native ProcessList enumerateProcessesWithOptionsSync(Object options, Object cancellable);

    // Enable spawn gating
    /**
     * Enable spawn gating asynchronously.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void enableSpawnGating(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete enabling spawn gating.
     * @param asyncResult Result object from the async call
     */
    public native void enableSpawnGatingFinish(Object asyncResult);
    /**
     * Enable spawn gating synchronously.
     * @param cancellable Optional cancellable object
     */
    public native void enableSpawnGatingSync(Object cancellable);

    // Disable spawn gating
    /**
     * Disable spawn gating asynchronously.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void disableSpawnGating(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete disabling spawn gating.
     * @param asyncResult Result object from the async call
     */
    public native void disableSpawnGatingFinish(Object asyncResult);
    /**
     * Disable spawn gating synchronously.
     * @param cancellable Optional cancellable object
     */
    public native void disableSpawnGatingSync(Object cancellable);

    // Spawn with options
    /**
     * Spawn with options asynchronously.
     * @param program Path to the program
     * @param options Spawn options
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void spawnWithOptions(String program, Object options, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a spawn with options.
     * @param asyncResult Result object from the async call
     * @return Process ID of the spawned process
     */
    public native int spawnWithOptionsFinish(Object asyncResult);
    /**
     * Spawn with options synchronously.
     * @param program Path to the program
     * @param options Spawn options
     * @param cancellable Optional cancellable object
     * @return Process ID of the spawned process
     */
    public native int spawnWithOptionsSync(String program, Object options, Object cancellable);

    // Input
    /**
     * Send input to a process asynchronously.
     * @param pid Process ID
     * @param data Input data
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void input(int pid, Object data, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an input operation.
     * @param asyncResult Result object from the async call
     */
    public native void inputFinish(Object asyncResult);
    /**
     * Send input to a process synchronously.
     * @param pid Process ID
     * @param data Input data
     * @param cancellable Optional cancellable object
     */
    public native void inputSync(int pid, Object data, Object cancellable);

    // Resume (async variants)
    /**
     * Resume a process asynchronously.
     * @param pid Process ID
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void resumeAsync(int pid, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a resume operation.
     * @param asyncResult Result object from the async call
     */
    public native void resumeFinish(Object asyncResult);
    /**
     * Resume a process synchronously.
     * @param pid Process ID
     * @param cancellable Optional cancellable object
     */
    public native void resumeSync(int pid, Object cancellable);

    // Kill (async variants)
    /**
     * Kill a process asynchronously.
     * @param pid Process ID
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void killAsync(int pid, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a kill operation.
     * @param asyncResult Result object from the async call
     */
    public native void killFinish(Object asyncResult);
    /**
     * Kill a process synchronously.
     * @param pid Process ID
     * @param cancellable Optional cancellable object
     */
    public native void killSync(int pid, Object cancellable);

    // Enumerate pending children
    /**
     * Enumerate pending children asynchronously.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void enumeratePendingChildren(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete a pending children enumeration.
     * @param asyncResult Result object from the async call
     * @return ChildList of pending children
     */
    public native ChildList enumeratePendingChildrenFinish(Object asyncResult);
    /**
     * Enumerate pending children synchronously.
     * @param cancellable Optional cancellable object
     * @return ChildList of pending children
     */
    public native ChildList enumeratePendingChildrenSync(Object cancellable);

    /**
     * Get the native pointer (for internal use).
     * @return Native pointer value
     */
    long getNativePtr() {
        return nativePtr;
    }

    /**
     * Native method to release native resources.
     */
    private native void disposeNative(long nativePtr);

    /**
     * Close this device and release native resources.
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

    @Override
    public String toString() {
        return String.format("Device{name='%s', type=%s, id='%s'}",
            getName(), getType(), getId());
    }

    /**
     * Enumerate processes on this device (convenience overload).
     * Returns a ProcessList that must be closed by the caller.
     * @return ProcessList of running processes
     */
    public ProcessList enumerateProcesses() {
        return enumerateProcessesSync(null);
    }


}
