package nl.axelkoolhaas.frida_java;

/**
 * Options for matching processes.
 */
public class ProcessMatchOptions {
    private long nativePtr;

    public ProcessMatchOptions() {}
    ProcessMatchOptions(long nativePtr) { this.nativePtr = nativePtr; }

    // Native method stubs for options
    public native void setTimeout(int timeout);
    public native int getTimeout();
    public native void setScope(int scope);
    public native int getScope();
}
