package nl.axelkoolhaas.frida_java;

/**
 * Options for creating a session.
 */
public class SessionOptions {
    private long nativePtr;

    public SessionOptions() {}
    SessionOptions(long nativePtr) { this.nativePtr = nativePtr; }

    // Native method stubs for options
    /**
     * Set the persist timeout for the session.
     * @param timeout Timeout in milliseconds
     */
    public native void setPersistTimeout(int timeout);

    /**
     * Get the persist timeout for the session.
     * @return Timeout in milliseconds
     */
    public native int getPersistTimeout();

    /**
     * Set the realm for the session.
     * @param realm Realm string
     */
    public native void setRealm(String realm);

    /**
     * Get the realm for the session.
     * @return Realm string
     */
    public native String getRealm();

    /**
     * Set the parameters for the session.
     * @param parameters Map of parameters
     */
    public native void setParameters(java.util.Map<String, Object> parameters);

    /**
     * Get the parameters for the session.
     * @return Map of parameters
     */
    public native java.util.Map<String, Object> getParameters();
}
