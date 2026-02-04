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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Compiler is used to compile TypeScript/JavaScript scripts for Frida.
 *
 * <p>Available signals:
 * <ul>
 *   <li>{@link CompilerSignal#STARTING} - Emitted when compilation starts. Callback: {@code Runnable}</li>
 *   <li>{@link CompilerSignal#FINISHED} - Emitted when compilation finishes. Callback: {@code Runnable}</li>
 *   <li>{@link CompilerSignal#OUTPUT} - Emitted with compiled bundle. Callback: {@code OutputCallback}</li>
 *   <li>{@link CompilerSignal#DIAGNOSTICS} - Emitted with diagnostic messages. Callback: {@code DiagnosticsCallback}</li>
 *   <li>{@link CompilerSignal#FILE_CHANGED} - Emitted when a watched file changes. Callback: {@code Runnable}</li>
 * </ul>
 */
public class Compiler implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(Compiler.class);
    private final MemorySegment compilerPtr;
    private final Map<String, Long> handlerIds = new ConcurrentHashMap<>();
    private final DeviceManager ownedDeviceManager; // Track if we own the DeviceManager
    private volatile boolean closed = false;

    private static final MethodHandle FRIDA_COMPILER_NEW;
    private static final MethodHandle FRIDA_COMPILER_BUILD_SYNC;
    private static final MethodHandle FRIDA_COMPILER_WATCH_SYNC;

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
            this.ownedDeviceManager = null; // We don't own this one
            log.debug("Compiler created with caller-owned DeviceManager");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.error("Failed to create Compiler: {}", e.getMessage());
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
                    compilerPtr,
                    entrypointPtr,
                    optionsPtr,
                    MemorySegment.NULL, // cancellable
                    errorPtr
            );

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "build script from " + entrypoint);

            String result = FridaNativeUtils.memorySegmentToString(resultPtr);
            log.debug("Successfully built script from {}, output size: {} bytes", entrypoint, result.length());
            return result;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.error("Failed to build script from {}: {}", entrypoint, e.getMessage());
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
                    compilerPtr,
                    entrypointPtr,
                    optionsPtr,
                    MemorySegment.NULL, // cancellable
                    errorPtr
            );

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "watch script at " + entrypoint);

            log.debug("Successfully started watching: {}", entrypoint);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.error("Failed to watch script at {}: {}", entrypoint, e.getMessage());
            throw new FridaException("Failed to watch script at " + entrypoint, e);
        }
    }

    /**
     * Connect to compiler signals.
     *
     * <p>Available signals:
     * <ul>
     *   <li>{@link CompilerSignal#STARTING} - Callback: {@code Runnable}</li>
     *   <li>{@link CompilerSignal#FINISHED} - Callback: {@code Runnable}</li>
     *   <li>{@link CompilerSignal#OUTPUT} - Callback: {@code SignalCallbacks.CompilerOutputCallback} receiving the compiled bundle</li>
     *   <li>{@link CompilerSignal#DIAGNOSTICS} - Callback: {@code SignalCallbacks.CompilerDiagnosticsCallback} receiving diagnostic text</li>
     *   <li>{@link CompilerSignal#FILE_CHANGED} - Callback: {@code Runnable}</li>
     * </ul>
     *
     * @param signal Signal to connect to
     * @param callback Callback to invoke when the signal is emitted
     */
    public void on(CompilerSignal signal, Object callback) {
        if (callback == null) {
            throw new IllegalArgumentException("Callback cannot be null");
        }

        log.debug("Connecting to compiler signal: {}", signal.getName());

        long handlerId = switch (signal) {
            case STARTING, FINISHED, FILE_CHANGED -> {
                if (!(callback instanceof Runnable)) {
                    throw new IllegalArgumentException("Signal '" + signal.getName() + "' requires a Runnable callback");
                }
                yield FridaNativeUtils.connectSignal(compilerPtr, signal.getName(), callback, FridaNativeUtils.getCompilerType());
            }
            case OUTPUT -> {
                if (!(callback instanceof SignalCallbacks.CompilerOutputCallback)) {
                    throw new IllegalArgumentException("Signal 'output' requires a SignalCallbacks.CompilerOutputCallback");
                }
                yield FridaNativeUtils.connectSignal(compilerPtr, signal.getName(), callback, FridaNativeUtils.getCompilerType());
            }
            case DIAGNOSTICS -> {
                if (!(callback instanceof SignalCallbacks.CompilerDiagnosticsCallback)) {
                    throw new IllegalArgumentException("Signal 'diagnostics' requires a SignalCallbacks.CompilerDiagnosticsCallback");
                }
                yield FridaNativeUtils.connectSignal(compilerPtr, signal.getName(), callback, FridaNativeUtils.getCompilerType());
            }
        };

        if (handlerId > 0) {
            handlerIds.put(signal.getName(), handlerId);
            log.trace("Connected to signal '{}' with handler ID {}", signal.getName(), handlerId);
        }
    }

    /**
     * Disconnect from a signal.
     *
     * @param signal Signal to disconnect from
     */
    public void off(CompilerSignal signal) {
        Long handlerId = handlerIds.remove(signal.getName());
        if (handlerId != null) {
            log.debug("Disconnecting from compiler signal: {}", signal.getName());
            FridaNativeUtils.disconnectSignal(compilerPtr, handlerId);
        }
    }

    /**
     * Clean up resources held by the compiler.
     */
    public void clean() {
        if (closed) {
            return; // Already cleaned up
        }

        log.debug("Cleaning up Compiler");
        // Disconnect all signals
        for (Map.Entry<String, Long> entry : handlerIds.entrySet()) {
            log.debug("Disconnecting from compiler signal: {}", entry.getKey());
            FridaNativeUtils.disconnectSignal(compilerPtr, entry.getValue());
        }
        handlerIds.clear();

        FridaNativeUtils.fridaUnref(compilerPtr);

        // Close owned DeviceManager if we created it
        if (ownedDeviceManager != null) {
            try {
                ownedDeviceManager.close();
                log.debug("Closed owned DeviceManager");
            } catch (Exception e) {
                log.warn("Failed to close owned DeviceManager: {}", e.getMessage());
            }
        }

        closed = true;
    }

    @Override
    public void close() {
        clean();
    }
}
