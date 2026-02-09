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
import nl.axelkoolhaas.frida_java.util.GBytesUtil;
import nl.axelkoolhaas.frida_java.util.GSignalUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodType;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Manages GObject signal connections between native code and Java callbacks.
 * This is not a closure in the traditional sense, but the name is kept for consistency with GClosure.
 * This class looks scary, but essentially it just maps native signal C callbacks back to Java methods.
 * It does this through Linker upcall stubs and a static dispatch method.
 */
public class Closure {
    private static final Logger log = LoggerFactory.getLogger(Closure.class);
    private static final AtomicLong CLOSURE_ID_GENERATOR = new AtomicLong(1);
    private static final ConcurrentHashMap<Long, Object> ACTIVE_CLOSURES = new ConcurrentHashMap<>();

    private static volatile SignalCallbacks.ErrorHandler errorHandler = null;

    /**
     * Set a global error handler for callback exceptions.
     * The error handler will be invoked when a callback throws an exception.
     *
     * @param handler Error handler to register, or null to remove the handler
     */
    public static void setErrorHandler(SignalCallbacks.ErrorHandler handler) {
        errorHandler = handler;
    }

    private final long id;
    private final MemorySegment nativeCallback;

    private Closure(long id, MemorySegment nativeCallback) {
        this.id = id;
        this.nativeCallback = nativeCallback;
    }

    /**
     * Create a new closure for a Java callback
     */
    public static Closure create(Object callback, String signalName) {
        long id = CLOSURE_ID_GENERATOR.getAndIncrement();

        // Create native callback stub that will call back to Java
        MemorySegment nativeCallback = createNativeCallback(id, signalName);

        // Store callback in map for dispatch
        ACTIVE_CLOSURES.put(id, callback);

        log.debug("Created closure {} for '{}' signal with native callback: {}", id, signalName, nativeCallback);

        return new Closure(id, nativeCallback);
    }

    /**
     * Get the native callback function pointer
     */
    public MemorySegment getNativeCallback() {
        return nativeCallback;
    }

    /**
     * Clean up the closure
     */
    public void dispose() {
        Object removed = ACTIVE_CLOSURES.remove(id);
        if (removed != null) {
            log.debug("Disposed closure {}", id);
        }
        // Native callback cleanup will happen when GClosure is freed
    }

    public long getId() {
        return id;
    }

    /**
     * Handle signal dispatch from native code
     */
    public static void dispatchSignal(long closureId, String signalName, Object... args) {
        Object callback = ACTIVE_CLOSURES.get(closureId);
        if (callback == null) {
            log.trace("No callback found for closure {} signal '{}'", closureId, signalName);
            return;
        }

        log.trace("Dispatching signal '{}' to closure {}", signalName, closureId);

        try {
            switch (signalName) {
                case "detached":
                case "lost":
                    if (callback instanceof Runnable) {
                        ((Runnable) callback).run();
                    }
                    break;
                case "message":
                    if (callback instanceof SignalCallbacks.MessageCallback && args.length >= 2) {
                        String message = (String) args[0];
                        byte[] data = (byte[]) args[1];
                        ((SignalCallbacks.MessageCallback) callback).onMessage(message, data);
                    }
                    break;
                case "spawn_added":
                case "spawn_removed":
                    // Handle spawn events if needed
                    break;
                case "output":
                    // Handle output events if needed
                    break;
                default:
                    // Unknown signal - silently ignore
                    log.trace("Unknown signal '{}' dispatched to closure {}", signalName, closureId);
                    break;
            }
        } catch (Exception e) {
            // Cannot propagate exceptions through native callback boundary
            log.error("Callback failed for signal '{}': {}", signalName, e.getMessage(), e);

            // Notify error handler if registered
            SignalCallbacks.ErrorHandler handler = errorHandler;
            if (handler != null) {
                try {
                    handler.onCallbackError(signalName, e);
                } catch (Exception handlerError) {
                    log.error("Error handler itself threw exception: {}", handlerError.getMessage(), handlerError);
                }
            }
        }
    }

    private static MemorySegment createNativeCallback(long closureId, String signalName) {
        try {
            Linker linker = Linker.nativeLinker();
            Arena arena = Arena.ofShared(); // Use shared arena for callbacks that need to persist

            return switch (signalName) {
                case "detached", "lost" -> {
                    // GObject signal: void callback(GObject *object, gpointer user_data)
                    MethodHandle handler = createSimpleHandler(closureId, signalName);
                    FunctionDescriptor descriptor = FunctionDescriptor.ofVoid(
                            ValueLayout.ADDRESS,  // GObject *object
                            ValueLayout.ADDRESS   // gpointer user_data
                    );
                    yield linker.upcallStub(handler, descriptor, arena);
                }
                case "message" -> {
                    // Frida signal: void callback(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data)
                    MethodHandle handler = createMessageHandler(closureId, signalName);
                    FunctionDescriptor descriptor = FunctionDescriptor.ofVoid(
                            ValueLayout.ADDRESS,  // FridaScript *script
                            ValueLayout.ADDRESS,  // const gchar *message
                            ValueLayout.ADDRESS,  // GBytes *data
                            ValueLayout.ADDRESS   // gpointer user_data
                    );
                    yield linker.upcallStub(handler, descriptor, arena);
                }
                default -> {
                    // Generic handler for custom signals (Frida scripts can emit any signal)
                    MethodHandle handler = createGenericHandler(closureId, signalName);
                    FunctionDescriptor descriptor = FunctionDescriptor.ofVoid(
                            ValueLayout.ADDRESS,  // GObject *object
                            ValueLayout.ADDRESS   // gpointer user_data
                    );
                    yield linker.upcallStub(handler, descriptor, arena);
                }
            };
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to create native callback for signal: " + signalName, e);
        }
    }

    private static MethodHandle createSimpleHandler(long closureId, String signalName) {
        try {
            MethodHandle base = java.lang.invoke.MethodHandles.lookup()
                .findStatic(Closure.class, "handleSimpleSignal",
                    MethodType.methodType(void.class, long.class, String.class,
                        MemorySegment.class, MemorySegment.class));
            return java.lang.invoke.MethodHandles.insertArguments(base, 0, closureId, signalName);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to create simple handler", e);
        }
    }

    private static MethodHandle createMessageHandler(long closureId, String signalName) {
        try {
            MethodHandle base = java.lang.invoke.MethodHandles.lookup()
                .findStatic(Closure.class, "handleMessageSignal",
                    MethodType.methodType(void.class, long.class, String.class,
                        MemorySegment.class, MemorySegment.class, MemorySegment.class, MemorySegment.class));
            return java.lang.invoke.MethodHandles.insertArguments(base, 0, closureId, signalName);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to create message handler", e);
        }
    }

    private static MethodHandle createGenericHandler(long closureId, String signalName) {
        try {
            MethodHandle base = java.lang.invoke.MethodHandles.lookup()
                .findStatic(Closure.class, "handleGenericSignal",
                    MethodType.methodType(void.class, long.class, String.class,
                        MemorySegment.class, MemorySegment.class));
            return java.lang.invoke.MethodHandles.insertArguments(base, 0, closureId, signalName);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to create generic handler", e);
        }
    }

    // Native callback handlers
    public static void handleSimpleSignal(long closureId, String signalName,
                                          MemorySegment object, MemorySegment userData) {
        dispatchSignal(closureId, signalName);
    }

    public static void handleMessageSignal(long closureId, String signalName,
                                          MemorySegment script, MemorySegment messagePtr,
                                          MemorySegment dataPtr, MemorySegment userData) {
        try {
            // Read the message JSON string from the native pointer
            String message = FridaNativeUtils.memorySegmentToString(messagePtr);

            // Extract binary data from GBytes if present (for send(message, data) calls)
            byte[] data = GBytesUtil.toByteArray(dataPtr);

            dispatchSignal(closureId, signalName, message, data);
        } catch (Exception e) {
            // Cannot propagate through native callback boundary - log only
            log.error("Failed to handle message signal: {}", e.getMessage(), e);

            // Notify error handler if registered
            SignalCallbacks.ErrorHandler handler = errorHandler;
            if (handler != null) {
                try {
                    handler.onCallbackError(signalName, e);
                } catch (Exception handlerError) {
                    log.error("Error handler itself threw exception: {}", handlerError.getMessage(), handlerError);
                }
            }
        }
    }

    public static void handleGenericSignal(long closureId, String signalName, MemorySegment object, MemorySegment userData) {
        dispatchSignal(closureId, signalName, object);
    }

    /**
     * Connect a closure to a script signal using GLib's signal system.
     * This connects the closure's native callback to receive actual script messages.
     *
     * @param object The script object
     * @param signalName The signal name (typically "message")
     * @param callback The callback to register
     * @return Handler ID for the connection, or 0 if failed
     */
    public static long connectClosure(MemorySegment object, String signalName, Object callback) {
        log.debug("Connecting script signal: {}", signalName);

        try {
            // Create closure with native callback stub
            Closure closure = Closure.create(callback, signalName);
            MemorySegment nativeCallback = closure.getNativeCallback();

            // Create GClosure in native code that will call the native callback stub
            MemorySegment gClosure = createGClosure(nativeCallback);

            // Use GSignalUtil to handle the actual GLib signal connection
            long handlerId = GSignalUtil.connectSignal(object, signalName, nativeCallback);

            log.debug("Connected script signal '{}' with handler ID {}", signalName, handlerId);
            return handlerId;
        } catch (Exception e) {
            log.error("Failed to connect script signal '{}': {}", signalName, e.getMessage(), e);
            throw new FridaException("Failed to connect script signal: " + signalName, e);
        }
    }

    /**
     * Create a GClosure from a function pointer
     */
    private static MemorySegment createGClosure(MemorySegment callback) {
        try {
            // Use g_cclosure_new to create a GClosure from function pointer
            MethodHandle gClosureNew = FridaLibraryLoader.findFunction("g_cclosure_new",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            // Create closure: g_cclosure_new(callback_func, user_data, destroy_notify)
            return (MemorySegment) gClosureNew.invoke(
                    callback,           // callback function
                    MemorySegment.NULL, // user_data (not needed)
                    MemorySegment.NULL  // destroy_notify (not needed for now)
            );
        } catch (Throwable e) {
            throw new FridaException("Failed to create GClosure", e);
        }
    }
}
