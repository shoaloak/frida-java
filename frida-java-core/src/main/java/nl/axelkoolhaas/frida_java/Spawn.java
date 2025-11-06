package nl.axelkoolhaas.frida_java;

public class Spawn {
    private long nativePtr;

    Spawn(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the process ID of the spawn.
     * @return Process ID
     */
    public native int getPid();

    /**
     * Get the identifier of the spawn.
     * @return Spawn identifier
     */
    public native String getIdentifier();

    /**
     * Get the parent process ID of the spawn.
     * @return Parent process ID
     */
    public native int getParentPid();

    /**
     * Get the origin of the spawn.
     * @return Origin string
     */
    public native String getOrigin();

    /**
     * Get the argument vector (argv) of the spawn.
     * @return Array of argument strings
     */
    public native String[] getArgv();

    /**
     * Get the environment variables of the spawn.
     * @return Map of environment variables
     */
    public native java.util.Map<String, String> getEnv();

    // Async/sync/finish variants for properties (if Frida API supports it)
    public native void getPidAsync(Object cancellable, Object callback, Object callbackTarget);
    public native int getPidFinish(Object asyncResult);
    public native int getPidSync(Object cancellable);

    public native void getIdentifierAsync(Object cancellable, Object callback, Object callbackTarget);
    public native String getIdentifierFinish(Object asyncResult);
    public native String getIdentifierSync(Object cancellable);

    public native void getParentPidAsync(Object cancellable, Object callback, Object callbackTarget);
    public native int getParentPidFinish(Object asyncResult);
    public native int getParentPidSync(Object cancellable);

    public native void getOriginAsync(Object cancellable, Object callback, Object callbackTarget);
    public native String getOriginFinish(Object asyncResult);
    public native String getOriginSync(Object cancellable);

    public native void getArgvAsync(Object cancellable, Object callback, Object callbackTarget);
    public native String[] getArgvFinish(Object asyncResult);
    public native String[] getArgvSync(Object cancellable);

    public native void getEnvAsync(Object cancellable, Object callback, Object callbackTarget);
    public native java.util.Map<String, String> getEnvFinish(Object asyncResult);
    public native java.util.Map<String, String> getEnvSync(Object cancellable);
}
