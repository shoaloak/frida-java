/*
 * Copyright (C) 2026 Axel Koolhaas
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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Compiler is used to compile TypeScript/JavaScript scripts for Frida.
 */
public class Compiler implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(Compiler.class);
    private final MemorySegment compilerPtr;
    private final DeviceManager ownedDeviceManager;
    private volatile boolean closed = false;

    // Simple callback storage
    private final Map<CompilerSignal, Object> callbacks = new ConcurrentHashMap<>();
    // Store handler IDs for signal connections
    private final Map<CompilerSignal, Long> handlerIds = new ConcurrentHashMap<>();

    private static final MethodHandle FRIDA_COMPILER_NEW;
    private static final MethodHandle FRIDA_COMPILER_BUILD_SYNC;
    private static final MethodHandle FRIDA_COMPILER_WATCH_SYNC;

    // Used to remove listeners
    private static final MethodHandle G_SIGNAL_HANDLER_DISCONNECT;

    static {
        Frida.ensureInitialized();

        FRIDA_COMPILER_NEW = FridaLibraryLoader.findFunction("frida_compiler_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_COMPILER_BUILD_SYNC = FridaLibraryLoader.findFunction("frida_compiler_build_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_COMPILER_WATCH_SYNC = FridaLibraryLoader.findFunction("frida_compiler_watch_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        G_SIGNAL_HANDLER_DISCONNECT = FridaLibraryLoader.findFunction("g_signal_handler_disconnect",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
    }


    /**
     * Create a new compiler instance.
     * Creates and owns a DeviceManager internally.
     */
    public Compiler() {
        DeviceManager deviceManager = new DeviceManager();
        try {
            this.compilerPtr = (MemorySegment) FRIDA_COMPILER_NEW.invoke(deviceManager.getPointer());
            this.ownedDeviceManager = deviceManager;
            log.debug("Compiler created with owned DeviceManager");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            deviceManager.close();
            throw e;
        } catch (Throwable e) {
            deviceManager.close();
            log.error("Failed to create Compiler: {}", e.getMessage());
            throw new FridaException("Failed to create Compiler", e);
        }
    }

    /**
     * Create a new compiler instance with the given device manager.
     * The caller retains ownership of the DeviceManager.
     *
     * @param deviceManager Device manager to use for compilation
     */
    public Compiler(DeviceManager deviceManager) {
        try {
            this.compilerPtr = (MemorySegment) FRIDA_COMPILER_NEW.invoke(deviceManager.getPointer());
            this.ownedDeviceManager = null;
            log.debug("Compiler created with caller-owned DeviceManager");
        } catch (Throwable e) {
            throw new FridaException("Failed to create Compiler", e);
        }
    }

    /**
     * Build a script from the given entrypoint.
     *
     * @param entrypoint Path to the entrypoint script (TypeScript or JavaScript)
     * @return Compiled JavaScript bundle as a string
     * @throws FridaException if compilation fails
     */
    public String build(String entrypoint) {
        return build(entrypoint, null);
    }

    /**
     * Build a script from the given entrypoint with options.
     *
     * @param entrypoint Path to the entrypoint script (TypeScript or JavaScript)
     * @param options Compiler options (can be null for defaults)
     * @return Compiled JavaScript bundle as a string
     * @throws FridaException if compilation fails
     */
    public String build(String entrypoint, CompilerOptions options) {
        log.debug("Building script from entrypoint: {}", entrypoint);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment entrypointPtr = arena.allocateFrom(entrypoint);
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment optionsPtr = options != null ? options.getPointer() : MemorySegment.NULL;

            log.trace("Native call: frida_compiler_build_sync(entrypoint={})", entrypoint);
            MemorySegment resultPtr = (MemorySegment) FRIDA_COMPILER_BUILD_SYNC.invoke(
                    compilerPtr, entrypointPtr, optionsPtr, MemorySegment.NULL, errorPtr
            );

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "build script from " + entrypoint);

            return FridaNativeUtils.memorySegmentToString(resultPtr);
        } catch (Throwable e) {
            throw new FridaException("Failed to build script from " + entrypoint, e);
        }
    }

    /**
     * Watch for changes at the entrypoint and emit "output" signal on recompilation.
     *
     * @param entrypoint Path to the entrypoint script (TypeScript or JavaScript)
     * @throws FridaException if watch setup fails
     */
    public void watch(String entrypoint) {
        watch(entrypoint, null);
    }

    /**
     * Watch for changes at the entrypoint and emit "output" signal on recompilation.
     *
     * @param entrypoint Path to the entrypoint script (TypeScript or JavaScript)
     * @param options Compiler options (can be null for defaults)
     * @throws FridaException if watch setup fails
     */
    public void watch(String entrypoint, CompilerOptions options) {
        log.debug("Starting watch on entrypoint: {}", entrypoint);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment entrypointPtr = arena.allocateFrom(entrypoint);
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment optionsPtr = options != null ? options.getPointer() : MemorySegment.NULL;

            log.trace("Native call: frida_compiler_watch_sync(entrypoint={})", entrypoint);
            FRIDA_COMPILER_WATCH_SYNC.invoke(
                    compilerPtr, entrypointPtr, optionsPtr, MemorySegment.NULL, errorPtr
            );

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "watch script at " + entrypoint);
        } catch (Throwable e) {
            throw new FridaException("Failed to watch script at " + entrypoint, e);
        }
    }

    public void on(CompilerSignal signal, Object callback) {
        if (callback == null) throw new IllegalArgumentException("Callback cannot be null");

        // 1. Clean up existing handler for this signal if present
        //    (Prevents double-firing if on() is called twice)
        if (callbacks.containsKey(signal)) {
            off(signal);
        }

        // Validate callback types
        switch (signal) {
            case STARTING, FINISHED, FILE_CHANGED -> {
                if (!(callback instanceof Runnable))
                    throw new IllegalArgumentException("Signal " + signal + " requires Runnable");
            }
            case OUTPUT -> {
                if (!(callback instanceof SignalCallbacks.CompilerOutputCallback))
                    throw new IllegalArgumentException("Signal output requires OutputCallback");
            }
            case DIAGNOSTICS -> {
                if (!(callback instanceof SignalCallbacks.CompilerDiagnosticsCallback))
                    throw new IllegalArgumentException("Signal diagnostics requires DiagnosticsCallback");
            }
        }

        callbacks.put(signal, callback);

        // 2. Connect new handler
        long handlerId = Closure.connectClosure(compilerPtr, signal.getName(), callback);
        handlerIds.put(signal, handlerId);

        log.debug("Registered callback for signal '{}', handlerId: {}", signal.getName(), handlerId);
    }

    public void off(CompilerSignal signal) {
        Object removedCallback = callbacks.remove(signal);
        Long handlerId = handlerIds.remove(signal);

        if (handlerId != null) {
            try {
                // 1. Notify GLib to disconnect the signal on the Native Object
                //    This stops the C side from emitting the event.
                G_SIGNAL_HANDLER_DISCONNECT.invoke(compilerPtr, handlerId);

                // 2. Clean up Java Upcall Stub
                Closure.disconnectClosure(handlerId);

                log.debug("Disconnected native handler for signal: {}", signal.getName());
            } catch (Throwable e) {
                log.error("Failed to disconnect signal {}", signal.getName(), e);
            }
        }
    }

    public void clean() {
        if (closed) return;

        // Disconnect all signal handlers properly
        for (CompilerSignal signal : handlerIds.keySet()) {
            off(signal);
        }

        FridaNativeUtils.fridaUnref(compilerPtr);

        if (ownedDeviceManager != null) {
            try {
                ownedDeviceManager.close();
            } catch (Exception e) {
                log.warn("Failed to close owned DeviceManager", e);
            }
        }
        closed = true;
    }

    @Override
    public void close() {
        clean();
    }
}