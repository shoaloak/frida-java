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

public class SpawnList implements AutoCloseable {
    private long nativePtr;
    private volatile boolean closed = false;

    SpawnList(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    /**
     * Get the number of spawns in the list.
     * @return Number of spawns
     */
    public native int size();

    /**
     * Get the spawn at the specified index.
     * @param index Index of the spawn
     * @return Spawn object
     */
    public native Spawn get(int index);

    /**
     * Convert the spawn list to an array.
     * @return Array of Spawn objects
     */
    public native Spawn[] toArray();

    // Async/sync/finish variants for size
    public native void sizeAsync(Object cancellable, Object callback, Object callbackTarget);
    public native int sizeFinish(Object asyncResult);
    public native int sizeSync(Object cancellable);

    // Async/sync/finish variants for get
    public native void getAsync(int index, Object cancellable, Object callback, Object callbackTarget);
    public native Spawn getFinish(Object asyncResult);
    public native Spawn getSync(int index, Object cancellable);

    /**
     * Close this spawn list and release native resources.
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
