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
 * Options for querying the frontmost application.
 * <p>
 * Implements {@link AutoCloseable} for safe native resource management.
 * Always call {@link #close()} explicitly or use try-with-resources.
 * </p>
 */
public class FrontmostQueryOptions implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    /**
     * Constructs a new FrontmostQueryOptions instance.
     */
    public FrontmostQueryOptions() {}
    /**
     * Internal constructor for native use.
     * @param nativePtr Native pointer to the options object
     */
    FrontmostQueryOptions(long nativePtr) { this.nativePtr = nativePtr; }

    /**
     * Set the user for the frontmost application query.
     * @param user User name
     */
    public native void setUser(String user);
    /**
     * Get the user for the frontmost application query.
     * @return User name
     */
    public native String getUser();
    /**
     * Set the session for the frontmost application query.
     * @param session Session name
     */
    public native void setSession(String session);
    /**
     * Get the session for the frontmost application query.
     * @return Session name
     */
    public native String getSession();

    /**
     * Close this FrontmostQueryOptions and release native resources.
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
