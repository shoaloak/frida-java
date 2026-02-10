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
 * It does this through Linker upcall stub (MarshalStub) and a static dispatch method.
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
     *
     * GClosureMarshal signature:
     * void marshal(GClosure *closure, GValue *return_value, guint n_param_values,
     *              const GValue *param_values, gpointer invocation_hint, gpointer marshal_data)
     */
    private static MemorySegment createMarshalStub() {
        try {
            MethodHandle marshalHandler = MethodHandles.lookup()
                    .findStatic(Closure.class, "handleMarshal",
                            MethodType.methodType(void.class,
                                    MemorySegment.class,  // GClosure *closure
                                    MemorySegment.class,  // GValue *return_value
                                    int.class,            // guint n_param_values
                                    MemorySegment.class,  // const GValue *param_values
                                    MemorySegment.class,  // gpointer invocation_hint
                                    MemorySegment.class   // gpointer marshal_data
                            ));

            FunctionDescriptor descriptor = FunctionDescriptor.ofVoid(
                    ValueLayout.ADDRESS,    // GClosure *closure
                    ValueLayout.ADDRESS,    // GValue *return_value
                    ValueLayout.JAVA_INT,   // guint n_param_values
                    ValueLayout.ADDRESS,    // const GValue *param_values
                    ValueLayout.ADDRESS,    // gpointer invocation_hint
                    ValueLayout.ADDRESS     // gpointer marshal_data
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
     */
    public static void handleMarshal(MemorySegment closurePtr, MemorySegment returnValue,
                                     int nParams, MemorySegment paramsPtr,
                                     MemorySegment invocationHint, MemorySegment marshalData) {
        // Get closure ID from the pointer address
        long ptrAddr = closurePtr.address();
        Long closureId = CLOSURE_PTR_TO_ID.get(ptrAddr);

        if (closureId == null) {
            log.trace("No closure ID found for pointer {}", ptrAddr);
            return;
        }

        ClosureData data = ACTIVE_CLOSURES.get(closureId);
        if (data == null) {
            log.trace("No callback found for closure ID {}", closureId);
            return;
        }

        log.trace("Marshal called for signal '{}', closure ID {}, nParams {}", data.signalName, closureId, nParams);

        try {
            // Extract values from the GValue array
            // GValue is typically 24 bytes on 64-bit systems (8 bytes GType + 16 bytes data union)
            int gvalueSize = 24; // TODO: This should be determined dynamically based on the platform and GLib version

            // First param (index 0) is always the instance (GObject), skip it like Go does
            // Actual signal parameters start at index 1
            switch (data.signalName) {
                case "message" -> handleMessageMarshal(data.callback, nParams, paramsPtr, gvalueSize);
                case "output" -> handleOutputMarshal(data.callback, nParams, paramsPtr, gvalueSize);
                case "detached", "lost" -> handleSimpleMarshal(data.callback);
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

    /**
     * Handle the "message" signal marshal.
     * Signal signature: void callback(FridaScript *script, const gchar *message, GBytes *data)
     * So nParams = 3 (instance + message + data)
     */
    private static void handleMessageMarshal(Object callback, int nParams, MemorySegment paramsPtr, int gvalueSize) {
        if (!(callback instanceof SignalCallbacks.MessageCallback messageCallback)) {
            log.trace("Callback is not a MessageCallback");
            return;
        }

        if (nParams < 3) {
            log.trace("Message signal has insufficient params: {}", nParams);
            return;
        }

        try {
            // Reinterpret the params pointer to allow access to GValue array
            MemorySegment params = paramsPtr.reinterpret((long) nParams * gvalueSize);

            // param[1] = message (const gchar*)
            MemorySegment messageGValue = params.asSlice((long) gvalueSize, gvalueSize);
            String message = GValueUtil.extractString(messageGValue);

            // param[2] = data (GBytes*)
            MemorySegment dataGValue = params.asSlice((long) 2 * gvalueSize, gvalueSize);
            byte[] data = GValueUtil.extractBytes(dataGValue);

            log.trace("Dispatching message signal: message length={}, data length={}",
                    message != null ? message.length() : 0, data != null ? data.length : 0);

            messageCallback.onMessage(message, data);
        } catch (Exception e) {
            log.error("Failed to handle message marshal: {}", e.getMessage(), e);
        }
    }

    /**
     * Handle the "output" signal marshal.
     * Signal signature: void callback(FridaDevice *device, guint pid, gint fd, GBytes *data)
     * So nParams = 4 (instance + pid + fd + data)
     */
    private static void handleOutputMarshal(Object callback, int nParams, MemorySegment paramsPtr, int gvalueSize) {
        if (!(callback instanceof SignalCallbacks.OutputCallback outputCallback)) {
            log.trace("Callback is not an OutputCallback");
            return;
        }

        if (nParams < 4) {
            log.trace("Output signal has insufficient params: {}", nParams);
            return;
        }

        try {
            // Reinterpret the params pointer to allow access to GValue array
            MemorySegment params = paramsPtr.reinterpret((long) nParams * gvalueSize);

            // param[1] = pid (guint)
            MemorySegment pidGValue = params.asSlice(gvalueSize, gvalueSize);
            int pid = GValueUtil.extractInt(pidGValue);

            // param[2] = fd (gint)
            MemorySegment fdGValue = params.asSlice((long) 2 * gvalueSize, gvalueSize);
            int fd = GValueUtil.extractInt(fdGValue);

            // param[3] = data (GBytes*)
            MemorySegment dataGValue = params.asSlice((long) 3 * gvalueSize, gvalueSize);
            byte[] data = GValueUtil.extractBytes(dataGValue);

            log.trace("Dispatching output signal: pid={}, fd={}, data length={}", pid, fd, data != null ? data.length : 0);

            outputCallback.onOutput(pid, fd, data);
        } catch (Exception e) {
            log.error("Failed to handle output marshal: {}", e.getMessage(), e);
        }
    }

    /**
     * Handle simple signals (detached, lost) that have no extra parameters.
     */
    private static void handleSimpleMarshal(Object callback) {
        if (callback instanceof Runnable runnable) {
            runnable.run();
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
     * Connect a closure to a script signal using GLib's signal system.
     * This uses the Go-style approach:
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

            // Lookup signal ID (equivalent to Go's C.lookup_signal)
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
