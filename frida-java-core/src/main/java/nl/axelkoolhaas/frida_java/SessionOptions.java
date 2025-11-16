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
