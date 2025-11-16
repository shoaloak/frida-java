/*
 * Copyright (C) 2025 Axel Koolhaas
 *
 * This file is part of frida-java.
 *
 * frida-java is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * frida-java is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with frida-java.  If not, see <https://www.gnu.org/licenses/>.
 */

package nl.axelkoolhaas.frida_java;

/**
 * Represents a Frida Child process or object.
 * <p>
 * Note: This class implements {@link AutoCloseable} to allow
 * automatic resource management. It is important to close
 * instances of this class to free native resources.
 * </p>
 */
public class Child implements AutoCloseable {
    private final long nativePtr;
    private volatile boolean closed = false;

    Child(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    // Native methods for Frida.Child properties and methods
    public native int getPid();
    public native int getParentPid();
    public native String getOrigin();
    public native String[] getArgv();
    public native java.util.Map<String, String> getEnv();

    // Async/sync/finish variants for properties (if Frida API supports it)
    public native void getPidAsync(Object cancellable, Object callback, Object callbackTarget);
    public native int getPidFinish(Object asyncResult);
    public native int getPidSync(Object cancellable);

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

    /**
     * Close this child and release native resources.
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

    /**
     * Native method to release native resources.
     */
    private native void disposeNative(long nativePtr);
}
