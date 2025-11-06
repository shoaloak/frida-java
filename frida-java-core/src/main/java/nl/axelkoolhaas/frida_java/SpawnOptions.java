package nl.axelkoolhaas.frida_java;

/**
 * Represents options for spawning a process on a Frida device.
 */
public class SpawnOptions {
    private long nativePtr;

    public SpawnOptions() {}

    SpawnOptions(long nativePtr) { this.nativePtr = nativePtr; }

    // Async/sync/finish variants for all properties (if Frida API supports it)
    public native void getArgvAsync(Object cancellable, Object callback, Object callbackTarget);
    public native String[] getArgvFinish(Object asyncResult);
    public native String[] getArgvSync(Object cancellable);
    public native void setArgvAsync(String[] argv, Object cancellable, Object callback, Object callbackTarget);
    public native void setArgvFinish(Object asyncResult);
    public native void setArgvSync(String[] argv, Object cancellable);

    public native void getEnvpAsync(Object cancellable, Object callback, Object callbackTarget);
    public native String[] getEnvpFinish(Object asyncResult);
    public native String[] getEnvpSync(Object cancellable);
    public native void setEnvpAsync(String[] envp, Object cancellable, Object callback, Object callbackTarget);
    public native void setEnvpFinish(Object asyncResult);
    public native void setEnvpSync(String[] envp, Object cancellable);

    public native void getEnvAsync(Object cancellable, Object callback, Object callbackTarget);
    public native String[] getEnvFinish(Object asyncResult);
    public native String[] getEnvSync(Object cancellable);
    public native void setEnvAsync(String[] env, Object cancellable, Object callback, Object callbackTarget);
    public native void setEnvFinish(Object asyncResult);
    public native void setEnvSync(String[] env, Object cancellable);

    public native void getCwdAsync(Object cancellable, Object callback, Object callbackTarget);
    public native String getCwdFinish(Object asyncResult);
    public native String getCwdSync(Object cancellable);
    public native void setCwdAsync(String cwd, Object cancellable, Object callback, Object callbackTarget);
    public native void setCwdFinish(Object asyncResult);
    public native void setCwdSync(String cwd, Object cancellable);

    public native void getStdioAsync(Object cancellable, Object callback, Object callbackTarget);
    public native int getStdioFinish(Object asyncResult);
    public native int getStdioSync(Object cancellable);
    public native void setStdioAsync(int stdio, Object cancellable, Object callback, Object callbackTarget);
    public native void setStdioFinish(Object asyncResult);
    public native void setStdioSync(int stdio, Object cancellable);

    public native void getAuxAsync(Object cancellable, Object callback, Object callbackTarget);
    public native java.util.Map<String, Object> getAuxFinish(Object asyncResult);
    public native java.util.Map<String, Object> getAuxSync(Object cancellable);
    public native void setAuxAsync(java.util.Map<String, Object> aux, Object cancellable, Object callback, Object callbackTarget);
    public native void setAuxFinish(Object asyncResult);
    public native void setAuxSync(java.util.Map<String, Object> aux, Object cancellable);

    // Resource management if needed
    // private native void disposeNative(long nativePtr);
    // public void dispose() { ... }
}
