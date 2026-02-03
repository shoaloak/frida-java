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

import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GBytesUtil;

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
    private static final AtomicLong CLOSURE_ID_GENERATOR = new AtomicLong(1);
    private static final ConcurrentHashMap<Long, Object> ACTIVE_CLOSURES = new ConcurrentHashMap<>();

    private final long id;
    private final Object callback; // accessible through ACTIVE_CLOSURES
    private final String signalName; // for reference
    private final MemorySegment nativeCallback;

    private Closure(long id, Object callback, String signalName, MemorySegment nativeCallback) {
        this.id = id;
        this.callback = callback;
        this.signalName = signalName;
        this.nativeCallback = nativeCallback;
    }

    /**
     * Create a new closure for a Java callback
     */
    public static Closure create(Object callback, String signalName) {
        long id = CLOSURE_ID_GENERATOR.getAndIncrement();

        // Create native callback stub that will call back to Java
        MemorySegment nativeCallback = createNativeCallback(id, signalName);

        Closure closure = new Closure(id, callback, signalName, nativeCallback);
        ACTIVE_CLOSURES.put(id, callback);

        return closure;
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
        ACTIVE_CLOSURES.remove(id);
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
            return;
        }

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
                    break;
            }
        } catch (Exception e) {
            throw new FridaException("Error dispatching signal '" + signalName + "' to callback", e);
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
            //TODO this gets called from  C.... danger
//            throw new FridaException("Failed to handle message signal", e);
        }
    }

    public static void handleGenericSignal(long closureId, String signalName, MemorySegment object, MemorySegment userData) {
        dispatchSignal(closureId, signalName, object);
    }
}
