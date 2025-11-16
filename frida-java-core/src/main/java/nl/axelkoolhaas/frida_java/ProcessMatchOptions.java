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
