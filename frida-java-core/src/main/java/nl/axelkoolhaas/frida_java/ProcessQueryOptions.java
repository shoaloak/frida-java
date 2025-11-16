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
