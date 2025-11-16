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
 * Represents a list of Frida Applications.
 */
public class ApplicationList implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    ApplicationList(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the number of applications in the list.
     * @return Number of applications
     */
    public native int size();
    /**
     * Get the application at the specified index.
     * @param index Index of the application
     * @return Application object
     */
    public native Application get(int index);
    /**
     * Convert the application list to an array.
     * @return Array of Application objects
     */
    public native Application[] toArray();

    // Async/sync/finish variants for size
    /**
     * Asynchronously get the number of applications in the list.
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void sizeAsync(Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous size operation.
     * @param asyncResult Result object from the async call
     * @return Number of applications
     */
    public native int sizeFinish(Object asyncResult);
    /**
     * Synchronously get the number of applications in the list.
     * @param cancellable Optional cancellable object
     * @return Number of applications
     */
    public native int sizeSync(Object cancellable);

    // Async/sync/finish variants for get
    /**
     * Asynchronously get the application at the specified index.
     * @param index Index of the application
     * @param cancellable Optional cancellable object
     * @param callback Callback to receive the result
     * @param callbackTarget Target object for the callback
     */
    public native void getAsync(int index, Object cancellable, Object callback, Object callbackTarget);
    /**
     * Complete an asynchronous get operation.
     * @param asyncResult Result object from the async call
     * @return Application object
     */
    public native Application getFinish(Object asyncResult);
    /**
     * Synchronously get the application at the specified index.
     * @param index Index of the application
     * @param cancellable Optional cancellable object
     * @return Application object
     */
    public native Application getSync(int index, Object cancellable);

    /**
     * Close this application list and release native resources.
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
