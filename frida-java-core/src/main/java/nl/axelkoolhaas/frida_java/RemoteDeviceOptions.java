package nl.axelkoolhaas.frida_java;

/**
 * Represents options for a remote Frida device.
 */
public class RemoteDeviceOptions {
    private long nativePtr;

    public RemoteDeviceOptions() {}
    RemoteDeviceOptions(long nativePtr) { this.nativePtr = nativePtr; }

    /**
     * Get the certificate for the remote device.
     * @return Certificate object
     */
    public native Object getCertificate();

    /**
     * Set the certificate for the remote device.
     * @param value Certificate object
     */
    public native void setCertificate(Object value);

    /**
     * Get the origin string for the remote device.
     * @return Origin string
     */
    public native String getOrigin();

    /**
     * Set the origin string for the remote device.
     * @param value Origin string
     */
    public native void setOrigin(String value);

    /**
     * Get the token for the remote device.
     * @return Token string
     */
    public native String getToken();

    /**
     * Set the token for the remote device.
     * @param value Token string
     */
    public native void setToken(String value);

    /**
     * Get the keepalive interval for the remote device.
     * @return Keepalive interval in seconds
     */
    public native int getKeepaliveInterval();

    /**
     * Set the keepalive interval for the remote device.
     * @param value Keepalive interval in seconds
     */
    public native void setKeepaliveInterval(int value);

    // Async/sync/finish variants for all properties (if Frida API supports it)
    public native void getCertificateAsync(Object cancellable, Object callback, Object callbackTarget);
    public native Object getCertificateFinish(Object asyncResult);
    public native Object getCertificateSync(Object cancellable);
    public native void setCertificateAsync(Object value, Object cancellable, Object callback, Object callbackTarget);
    public native void setCertificateFinish(Object asyncResult);
    public native void setCertificateSync(Object value, Object cancellable);

    public native void getOriginAsync(Object cancellable, Object callback, Object callbackTarget);
    public native String getOriginFinish(Object asyncResult);
    public native String getOriginSync(Object cancellable);
    public native void setOriginAsync(String value, Object cancellable, Object callback, Object callbackTarget);
    public native void setOriginFinish(Object asyncResult);
    public native void setOriginSync(String value, Object cancellable);

    public native void getTokenAsync(Object cancellable, Object callback, Object callbackTarget);
    public native String getTokenFinish(Object asyncResult);
    public native String getTokenSync(Object cancellable);
    public native void setTokenAsync(String value, Object cancellable, Object callback, Object callbackTarget);
    public native void setTokenFinish(Object asyncResult);
    public native void setTokenSync(String value, Object cancellable);

    public native void getKeepaliveIntervalAsync(Object cancellable, Object callback, Object callbackTarget);
    public native int getKeepaliveIntervalFinish(Object asyncResult);
    public native int getKeepaliveIntervalSync(Object cancellable);
    public native void setKeepaliveIntervalAsync(int value, Object cancellable, Object callback, Object callbackTarget);
    public native void setKeepaliveIntervalFinish(Object asyncResult);
    public native void setKeepaliveIntervalSync(int value, Object cancellable);
}
