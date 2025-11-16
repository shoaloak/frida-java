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
 * Represents a Frida Application.
 */
public class Application implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    Application(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the application identifier.
     * @return Application identifier string
     */
    public native String getIdentifier();

    /**
     * Get the application name.
     * @return Application name
     */
    public native String getName();

    /**
     * Get the process ID of the application.
     * @return Process ID
     */
    public native int getPid();

    /**
     * Get the parameters of the application.
     * @return Map of parameters
     */
    public native java.util.Map<String, Object> getParameters();

    /**
     * Close this application and release native resources.
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
     * Get the native pointer for JNI access.
     * @return Native pointer value
     */
    long getNativePtr() {
        return nativePtr;
    }

    /**
     * Native method to release native resources.
     */
    private native void disposeNative(long nativePtr);
}