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

package nl.axelkoolhaas.frida_java.frida;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

/**
 * File monitor for watching file system changes
 */
public class FileMonitor implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(FileMonitor.class);
    private final MemorySegment monitorPtr;

    private static final MethodHandle FRIDA_FILE_MONITOR_NEW;
    private static final MethodHandle FRIDA_FILE_MONITOR_GET_PATH;
    private static final MethodHandle FRIDA_FILE_MONITOR_ENABLE_SYNC;
    private static final MethodHandle FRIDA_FILE_MONITOR_DISABLE_SYNC;

    static {
        Frida.ensureInitialized();

        FRIDA_FILE_MONITOR_NEW = FridaLibraryLoader.findFunction("frida_file_monitor_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_FILE_MONITOR_GET_PATH = FridaLibraryLoader.findFunction("frida_file_monitor_get_path",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_FILE_MONITOR_ENABLE_SYNC = FridaLibraryLoader.findFunction("frida_file_monitor_enable_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_FILE_MONITOR_DISABLE_SYNC = FridaLibraryLoader.findFunction("frida_file_monitor_disable_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /**
     * Create a new file monitor for the specified path
     * @param path File path to monitor
     */
    public FileMonitor(String path) {
        log.debug("Creating FileMonitor for path: {}", path);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pathPtr = arena.allocateFrom(path);
            this.monitorPtr = (MemorySegment) FRIDA_FILE_MONITOR_NEW.invoke(pathPtr);
            FridaNativeUtils.requireValidPointer(monitorPtr, "FileMonitor pointer");
            log.debug("FileMonitor created for: {}", path);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to create FileMonitor: {}", e.getMessage());
            throw new FridaException("Failed to create FileMonitor for path: " + path, e);
        }
    }

    /**
     * Get the monitored file path
     * @return File path being monitored
     */
    public String getPath() {
        try {
            MemorySegment pathPtr = (MemorySegment) FRIDA_FILE_MONITOR_GET_PATH.invoke(monitorPtr);
            String path = FridaNativeUtils.memorySegmentToString(pathPtr);
            log.trace("Got monitor path: {}", path);
            return path;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to get monitor path: {}", e.getMessage());
            throw new FridaException("Failed to get monitor path", e);
        }
    }

    /**
     * Enable file monitoring
     * @throws FridaException if enabling fails
     */
    public void enable() {
        log.debug("Enabling file monitor");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            FRIDA_FILE_MONITOR_ENABLE_SYNC.invoke(monitorPtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "enable file monitor");
            log.debug("File monitor enabled");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to enable file monitor: {}", e.getMessage());
            throw new FridaException("Failed to enable file monitor", e);
        }
    }

    /**
     * Disable file monitoring
     * @throws FridaException if disabling fails
     */
    public void disable() {
        log.debug("Disabling file monitor");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            FRIDA_FILE_MONITOR_DISABLE_SYNC.invoke(monitorPtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "disable file monitor");
            log.debug("File monitor disabled");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to disable file monitor: {}", e.getMessage());
            throw new FridaException("Failed to disable file monitor", e);
        }
    }

    /**
     * Register callbacks for file monitor events
     *
     * Available signals:
     * - "change": Emitted when a file change is detected
     *   Callback signature: void onFileChange(String changedFile, String otherFile, String changeType)
     *
     * @param signalName Signal name to connect to
     * @param callback Callback function
     * @throws IllegalArgumentException if signal name is unknown
     */
    public void on(String signalName, Object callback) {
        if (callback == null) {
            throw new IllegalArgumentException("Callback cannot be null");
        }

        log.debug("Registering callback for file monitor signal: {}", signalName);

        if (!"change".equals(signalName)) {
            throw new IllegalArgumentException("Unknown signal: " + signalName + ". Only 'change' is supported.");
        }

        try {
            long handlerId = Closure.connectClosure(monitorPtr, signalName, callback);

            if (handlerId > 0) {
                log.trace("Connected file monitor signal '{}' with handler ID {}", signalName, handlerId);
            } else {
                log.warn("Failed to connect file monitor signal '{}' - no handler ID returned", signalName);
            }
        } catch (Exception e) {
            log.debug("Failed to connect file monitor signal '{}': {}", signalName, e.getMessage());
            throw new FridaException("Failed to connect file monitor signal '" + signalName + "'", e);
        }

        log.trace("Registered callback for file monitor signal '{}'", signalName);
    }

    @Override
    public void close() {
        try {
            FridaNativeUtils.fridaUnref(monitorPtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to cleanup FileMonitor", e);
        }
    }
}

