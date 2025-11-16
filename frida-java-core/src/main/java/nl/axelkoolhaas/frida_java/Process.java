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
 * Represents a Frida Process.
 * <p>
 * Implements {@link AutoCloseable} for safe native resource management.
 * Always call {@link #close()} explicitly or use try-with-resources.
 * </p>
 */
public class Process implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    /**
     * Internal constructor for native use.
     * @param nativePtr Native pointer to the process object
     */
    Process(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the process ID.
     * @return Process ID
     */
    public native int getPid();

    /**
     * Get the process name.
     * @return Process name
     */
    public native String getName();

    /**
     * Get the parent process ID.
     * @return Parent process ID
     */
    public native int getParentPid();

    /**
     * Get the process identifier string.
     * @return Process identifier
     */
    public native String getIdentifier();

    /**
     * Asynchronously get the process ID.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getPidAsync(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous getPid operation.
     * @param asyncResult Result object from the async call
     * @return Process ID
     */
    public native int getPidFinish(Object asyncResult);
    /**
     * Synchronously get the process ID.
     * @param cancellable Optional cancellable object
     * @return Process ID
     */
    public native int getPidSync(Object cancellable);

    /**
     * Asynchronously get the process name.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getNameAsync(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous getName operation.
     * @param asyncResult Result object from the async call
     * @return Process name
     */
    public native String getNameFinish(Object asyncResult);
    /**
     * Synchronously get the process name.
     * @param cancellable Optional cancellable object
     * @return Process name
     */
    public native String getNameSync(Object cancellable);

    /**
     * Asynchronously get the parent process ID.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getParentPidAsync(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous getParentPid operation.
     * @param asyncResult Result object from the async call
     * @return Parent process ID
     */
    public native int getParentPidFinish(Object asyncResult);
    /**
     * Synchronously get the parent process ID.
     * @param cancellable Optional cancellable object
     * @return Parent process ID
     */
    public native int getParentPidSync(Object cancellable);

    /**
     * Asynchronously get the process identifier string.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getIdentifierAsync(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous getIdentifier operation.
     * @param asyncResult Result object from the async call
     * @return Process identifier
     */
    public native String getIdentifierFinish(Object asyncResult);
    /**
     * Synchronously get the process identifier string.
     * @param cancellable Optional cancellable object
     * @return Process identifier
     */
    public native String getIdentifierSync(Object cancellable);

    /**
     * Close this process and release native resources.
     * This method is idempotent and safe to call multiple times.
     * <b>Warning:</b> Always call close() explicitly or use try-with-resources.
     */
    @Override
    public void close() {
        if (!closed && nativePtr != 0) {
            disposeNative(nativePtr);
            nativePtr = 0; // Prevent use-after-free
            closed = true;
        }
    }
    /**
     * Native method to release native resources.
     */
    private native void disposeNative(long nativePtr);
}
