package nl.axelkoolhaas.frida_java;

/**
 * Options for querying processes.
 */
public class ProcessQueryOptions {
    private long nativePtr;

    public ProcessQueryOptions() {}
    ProcessQueryOptions(long nativePtr) { this.nativePtr = nativePtr; }

    // Native method stubs for options
    public native void setName(String name);
    public native String getName();
    public native void setPid(int pid);
    public native int getPid();
    public native void setParameters(java.util.Map<String, Object> parameters);
    public native java.util.Map<String, Object> getParameters();
}
