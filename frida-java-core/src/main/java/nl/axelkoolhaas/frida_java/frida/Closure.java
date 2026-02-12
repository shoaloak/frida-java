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

import nl.axelkoolhaas.frida_java.util.GSignalUtil;
import nl.axelkoolhaas.frida_java.util.GValueUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Manages GObject signal connections between native code and Java callbacks.
 * This class implements GClosure with a custom marshal function.
 * The marshal function receives GValues from the signal and converts them to Java types.
 * <br>
 * This is not a closure in the traditional sense, but the name is kept for consistency with GClosure.
 * This class looks scary, but essentially it just maps native signal C callbacks back to Java methods.
 * It does this through Linker upcall stub (MarshalStub) and a static dispatch method (handleMarshal).
 */
public class Closure {
    private static final Logger log = LoggerFactory.getLogger(Closure.class);
    private static final AtomicLong CLOSURE_ID_GENERATOR = new AtomicLong(1);

    // Maps closure ID -> ClosureData (callback + signal name)
    private static final ConcurrentHashMap<Long, ClosureData> ACTIVE_CLOSURES = new ConcurrentHashMap<>();

    // Maps GClosure pointer address -> closure ID (for marshal dispatch)
    private static final ConcurrentHashMap<Long, Long> CLOSURE_PTR_TO_ID = new ConcurrentHashMap<>();

    // Shared marshal function upcall stub (created once, reused for all closures)
    private static final MemorySegment MARSHAL_STUB;

    private static volatile SignalCallbacks.ErrorHandler errorHandler = null;

    static {
        MARSHAL_STUB = createMarshalStub();
    }

    /**
     * Internal data structure to hold callback info
     */
    private record ClosureData(Object callback, String signalName) {
    }

    /**
     * Create the shared marshal function upcall stub.
     * <pre>
     * void
     * (* GClosureMarshal) (
     *   GClosure* closure,
     *   GValue* return_value,
     *   guint n_param_values,
     *   const GValue* param_values,
     *   gpointer invocation_hint,
     *   gpointer marshal_data
     * )
     * </pre>
     */
    private static MemorySegment createMarshalStub() {
        try {
            MethodHandle marshalHandler = MethodHandles.lookup()
                    .findStatic(Closure.class, "handleMarshal",
                            MethodType.methodType(void.class,
                                    MemorySegment.class, MemorySegment.class, int.class,
                                    MemorySegment.class, MemorySegment.class, MemorySegment.class
                            ));

            FunctionDescriptor descriptor = FunctionDescriptor.ofVoid(
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS
            );

            // Use global arena so the stub lives for the lifetime of the JVM
            return Linker.nativeLinker().upcallStub(marshalHandler, descriptor, Arena.global());
        } catch (Throwable e) {
            throw new FridaException("Failed to create marshal stub", e);
        }
    }

    /**
     * Marshal function called by GLib when a signal is emitted.
     * This extracts GValues and dispatches to the appropriate Java callback.
     * Essentially a Java implementation of
     * <a href="https://docs.gtk.org/gobject/callback.ClosureMarshal.html">GClosureMarshal</a>
     */
    public static void handleMarshal(MemorySegment closurePtr, MemorySegment returnValue,
                                     int nParams, MemorySegment paramsPtr,
                                     MemorySegment invocationHint, MemorySegment marshalData) {
        // Look up the closure ID using the GClosure pointer
        long ptrAddr = closurePtr.address();
        Long closureId = CLOSURE_PTR_TO_ID.get(ptrAddr);
        if (closureId == null) {
            log.trace("No closure ID found for pointer {}", ptrAddr);
            // TODO: shouldn't we throw here?
            return;
        }

        // Look up the callback data using the closure ID
        ClosureData data = ACTIVE_CLOSURES.get(closureId);
        if (data == null) {
            log.trace("No callback found for closure ID {}", closureId);
            // TODO: shouldn't we throw here?
            return;
        }

        log.trace("Marshal called for signal '{}', closure ID {}, nParams {}", data.signalName, closureId, nParams);

        // Reinterpret the pointer as an array of GValues
        MemorySegment params = paramsPtr.reinterpret((long) nParams * GValueUtil.LAYOUT.byteSize());

        try {
            switch (data.signalName) {
                // Signals with no parameters (other than instance)
                // Compiler: starting, finished, file-changed
                // Script: destroyed
                // Device: lost
                // DeviceManager: changed
                case "starting", "finished", "file-changed", "destroyed", "lost", "changed" ->
                        handleSimpleMarshal(data.callback);

                case "detached" -> {
                    // Session.detached(reason, crash)
                    if (nParams >= 3) {
                        handleSessionDetachedMarshal(data.callback, nParams, params);
                    } else {
                        // Bus.detached()
                        handleSimpleMarshal(data.callback);
                    }
                }

                case "output" -> {
                    if (data.callback instanceof SignalCallbacks.CompilerOutputCallback) {
                        // Compiler.output(bundle, options)
                        handleCompilerOutputMarshal(data.callback, nParams, params);
                    } else if (data.callback instanceof SignalCallbacks.DeviceOutputCallback) {
                        // Device.output(pid, fd, data)
                        handleDeviceOutputMarshal(data.callback, nParams, params);
                    } else if (data.callback instanceof SignalCallbacks.ProcessOutputCallback) {
                        // Process.output(fd, data)
                        handleProcessOutputMarshal(data.callback, nParams, params);
                    }
                }

                // Messaging
                case "message" -> handleScriptMessageMarshal(data.callback, nParams, params);
                case "diagnostics" -> handleCompilerDiagnosticsMarshal(data.callback, nParams, params);

                // Discovery
                case "added", "removed" -> handleDeviceDiscoveryMarshal(data.callback, nParams, params);
                case "process-added", "process-removed" -> handleProcessDiscoveryMarshal(data.callback, nParams, params);

                case "spawn-added", "spawn-removed" -> handleSpawnDiscoveryMarshal(data.callback, nParams, params);
                case "child-added", "child-removed" -> handleChildDiscoveryMarshal(data.callback, nParams, params);

                // Events
                case "crashed" -> handleCrashSignalMarshal(data.callback, nParams, params);
                case "uninjected" -> handleUninjectedSignalMarshal(data.callback, nParams, params);

                default -> log.trace("Unknown signal '{}' in marshal", data.signalName);
            }
        } catch (Exception e) {
            log.error("Marshal failed for signal '{}': {}", data.signalName, e.getMessage(), e);

            SignalCallbacks.ErrorHandler handler = errorHandler;
            if (handler != null) {
                try {
                    handler.onCallbackError(data.signalName, e);
                } catch (Exception handlerError) {
                    log.error("Error handler itself threw exception: {}", handlerError.getMessage(), handlerError);
                }
            }
        }
    }

    /* Start of all handler methods, might want to refactor this into a strategy pattern or something... */

    /**
     * Handle simple signals that have no extra parameters.
     * nParams: 1 (Instance only)
     */
    private static void handleSimpleMarshal(Object callback) {
        if (callback instanceof SignalCallbacks.VoidCallback cb) {
            cb.onAction();
        } else if (callback instanceof Runnable runnable) {
            runnable.run();
        }
    }

    /**
     * Handle the "detached" signal marshal for Session and Bus.
     * nParams: 3 (Instance, Reason, Crash)
     */
    private static void handleSessionDetachedMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.SessionDetachedCallback cb && nParams >= 3) {
            int reason = GValueUtil.extractInt(GValueUtil.getAt(params, 1));
            MemorySegment crashPtr = GValueUtil.extractPointer(GValueUtil.getAt(params, 2));

            // TODO: should we increase the ref count of the crash object here?
//            Crash crash = null;
//            if (crashPtr != null && !crashPtr.equals(MemorySegment.NULL)) {
//                FridaNativeUtils.gObjectRef(crashPtr);
//                crash = new Crash(crashPtr);
//            }
//            cb.onDetach(reason, crash);

            cb.onDetach(reason, new Crash(crashPtr));
        } else {
            throw new FridaException("Detached signal marshal called with incompatible callback or insufficient params");
        }
    }

    /**
     * Handle the "output" signal marshal for Compiler.
     * nParams: 3 (Instance, Bundle, Options)
     */
    private static void handleCompilerOutputMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.CompilerOutputCallback cb && nParams >= 3) {
            // Bundle (FridaBundle*)
            MemorySegment bundlePtr = GValueUtil.extractPointer(GValueUtil.getAt(params, 1));
            String bundle = GValueUtil.extractString(GValueUtil.getAt(params, 1));

            // Options (FridaCompilerOptions*)
            MemorySegment optionsPtr = GValueUtil.extractPointer(GValueUtil.getAt(params, 2));

            // TODO: should we increase the ref count of the options object here?
//            CompilerOptions options = null;
//            if (optionsPtr != null && !optionsPtr.equals(MemorySegment.NULL)) {
//                FridaNativeUtils.gObjectRef(optionsPtr);
//                options = new CompilerOptions(optionsPtr, false); // false because we already manually ref'd
//            }
//            cb.onOutput(bundle, options);

            cb.onOutput(bundle, new CompilerOptions(optionsPtr));
        } else {
            throw new FridaException("Compiler output signal marshal called with incompatible callback or insufficient params");
        }
    }

    /**
     * Handle the "output" signal marshal for Device.
     * nParams: 4 (Instance, pid, fd, data)
     */
    private static void handleDeviceOutputMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.DeviceOutputCallback cb && nParams >= 4) {
            int pid = GValueUtil.extractInt(GValueUtil.getAt(params, 1));
            int fd = GValueUtil.extractInt(GValueUtil.getAt(params, 2));
            byte[] data = GValueUtil.extractBytes(GValueUtil.getAt(params, 3));
            cb.onOutput(pid, fd, data);
        } else {
            throw new FridaException("Device output signal marshal called with incompatible callback or insufficient params");
        }
    }

    /**
     * Handle the "output" signal marshal for Process.
     * nParams: 3 (Instance, fd, data)
     */
    private static void handleProcessOutputMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.ProcessOutputCallback cb && nParams >= 3) {
            int fd = GValueUtil.extractInt(GValueUtil.getAt(params, 1));
            byte[] data = GValueUtil.extractBytes(GValueUtil.getAt(params, 2));
            cb.onOutput(fd, data);
        } else {
            throw new FridaException("Process output signal marshal called with incompatible callback or insufficient params");
        }
    }

    /**
     * Handle the "message" signal marshal for Script.
     * nParams:3 (Instance, String, Bytes)
     */
    private static void handleScriptMessageMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.MessageCallback cb && nParams >= 3) {
            String message = GValueUtil.extractString(GValueUtil.getAt(params, 1));
            byte[] data = GValueUtil.extractBytes(GValueUtil.getAt(params, 2));
            cb.onMessage(message, data);
        } else {
            throw new FridaException("Message signal marshal called with incompatible callback or insufficient params");
        }
    }

    /**
     * Handle the "diagnostics" signal marshal for Compiler.
     * nParams: 2 (Instance, Diagnostics)
     */
    private static void handleCompilerDiagnosticsMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.CompilerDiagnosticsCallback cb && nParams >= 2) {
            String diagnostic = GValueUtil.extractString(GValueUtil.getAt(params, 1));
            cb.onDiagnostics(diagnostic);
        } else {
            throw new FridaException("Compiler diagnostics signal marshal called with incompatible callback or insufficient params");
        }
    }

    /**
     * DeviceManager: void added/removed (Device device)
     */
    private static void handleDeviceDiscoveryMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.DeviceCallback cb && nParams >= 2) {
            MemorySegment ptr = GValueUtil.extractPointer(GValueUtil.getAt(params, 1));
            // TODO: should we increase the ref count of the device object here?
//            if (ptr != null && !ptr.equals(MemorySegment.NULL)) {
//                FridaNativeUtils.gObjectRef(ptr);
//                cb.onAction(new Device(ptr));
//            }
            cb.onAction(new Device(ptr));
        }
    }

    /**
     * Device: void process-added/removed (Process process)
     */
    private static void handleProcessDiscoveryMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.ProcessCallback cb && nParams >= 2) {
            MemorySegment ptr = GValueUtil.extractPointer(GValueUtil.getAt(params, 1));
            // TODO: should we increase the ref count of the process object here?
//            if (ptr != null && !ptr.equals(MemorySegment.NULL)) {
//                FridaNativeUtils.gObjectRef(ptr);
//                cb.onProcess(new Process(ptr));
//            }
            cb.onProcess(new Process(ptr));
        }
    }

    /**
     * Device: void spawn-added/removed (Spawn spawn)
     */
    private static void handleSpawnDiscoveryMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.SpawnCallback cb && nParams >= 2) {
            MemorySegment ptr = GValueUtil.extractPointer(GValueUtil.getAt(params, 1));
            // TODO: should we increase the ref count of the spawn object here?
//            if (ptr != null && !ptr.equals(MemorySegment.NULL)) {
//                FridaNativeUtils.gObjectRef(ptr);
//                cb.onSpawn(new Spawn(ptr));
//            }
            cb.onSpawn(new Spawn(ptr));
        }
    }

    /**
     * Device: void child-added/removed (Child child)
     */
    private static void handleChildDiscoveryMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.ChildCallback cb && nParams >= 2) {
            MemorySegment ptr = GValueUtil.extractPointer(GValueUtil.getAt(params, 1));
            // TODO: should we increase the ref count of the child object here?
//            if (ptr != null && !ptr.equals(MemorySegment.NULL)) {
//                FridaNativeUtils.gObjectRef(ptr);
//                cb.onChild(new Child(ptr));
//            }
            cb.onChild(new Child(ptr));
        }
    }

    // TODO process-added process-removed

    private static void handleCrashSignalMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.CrashCallback cb && nParams >= 2) {
            MemorySegment ptr = GValueUtil.extractPointer(GValueUtil.getAt(params, 1));
            // TODO: should we increase the ref count of the crash object here?
//            if (ptr != null && !ptr.equals(MemorySegment.NULL)) {
//                FridaNativeUtils.gObjectRef(ptr);
//                cb.onCrash(new Crash(ptr));
//            }
            cb.onCrash(new Crash(ptr));
        }
    }

    private static void handleUninjectedSignalMarshal(Object callback, int nParams, MemorySegment params) {
        if (callback instanceof SignalCallbacks.UninjectedCallback cb && nParams >= 2) {
            int id = GValueUtil.extractInt(GValueUtil.getAt(params, 1));
            cb.onUninjected(id);
        }
    }

    /**
     * Set a global error handler for callback exceptions.
     * The error handler will be invoked when a callback throws an exception.
     *
     * @param handler Error handler to register, or null to remove the handler
     */
    public static void setErrorHandler(SignalCallbacks.ErrorHandler handler) {
        errorHandler = handler;
    }

    /**
     * Connect a closure to a signal using GLib's signal system.
     * 1. Create GClosure with g_closure_new_simple
     * 2. Set custom marshal function with g_closure_set_marshal
     * 3. Lookup signal ID with g_signal_lookup
     * 4. Connect with g_signal_connect_closure_by_id
     *
     * @param object The GObject to connect the signal to
     * @param signalName The signal name (e.g., "message")
     * @param callback The callback to register
     * @return Handler ID for the connection, or 0 if failed
     */
    public static long connectClosure(MemorySegment object, String signalName, Object callback) {
        log.debug("Connecting signal '{}' using GClosure with custom marshal", signalName);

        try {
            // Generate closure ID and store the callback
            long closureId = CLOSURE_ID_GENERATOR.getAndIncrement();
            ACTIVE_CLOSURES.put(closureId, new ClosureData(callback, signalName));

            // Lookup signal ID
            int signalId = GSignalUtil.lookupSignal(object, signalName);
            if (signalId == 0) {
                log.debug("Signal '{}' not found on object", signalName);
                ACTIVE_CLOSURES.remove(closureId);
                return 0;
            }

            // Create GClosure with our marshal function (equivalent to Go's newClosure())
            MemorySegment gClosure = GSignalUtil.createClosureWithMarshal(MARSHAL_STUB);

            // Map the GClosure pointer to our closure ID so marshal can find the callback
            CLOSURE_PTR_TO_ID.put(gClosure.address(), closureId);

            // Connect the closure to the signal (equivalent to Go's g_signal_connect_closure_by_id)
            long handlerId = GSignalUtil.connectClosureById(object, signalId, gClosure, true);

            log.debug("Connected signal '{}' with handler ID {}, closure ID {}", signalName, handlerId, closureId);
            return handlerId;
        } catch (Exception e) {
            log.error("Failed to connect signal '{}': {}", signalName, e.getMessage(), e);
            throw new FridaException("Failed to connect script message signal", e);
        }
    }

    /**
     * Disconnect a closure by handler ID.
     *
     * @param closureId The closure ID to disconnect
     */
    public static void disconnectClosure(long closureId) {
        ClosureData removed = ACTIVE_CLOSURES.remove(closureId);
        if (removed != null) {
            log.debug("Disconnected closure {}", closureId);
        }
    }
}
