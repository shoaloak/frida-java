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
import nl.axelkoolhaas.frida_java.util.GErrorUtils;
import nl.axelkoolhaas.frida_java.util.GSignalUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.concurrent.*;

/**
 * Represents a Frida script
 */
public class Script implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(Script.class);

    private final MemorySegment scriptPtr;
    private boolean hasMessageHandler = false;
    private SignalCallbacks.MessageCallback messageCallback;
    private volatile boolean closed = false;

    private static final MethodHandle FRIDA_SCRIPT_LOAD_SYNC;
    private static final MethodHandle FRIDA_SCRIPT_UNLOAD_SYNC;
    private static final MethodHandle FRIDA_SCRIPT_IS_DESTROYED;
    private static final MethodHandle FRIDA_SCRIPT_ETERNALIZE_SYNC;
    private static final MethodHandle FRIDA_SCRIPT_POST;
    private static final MethodHandle FRIDA_SCRIPT_ENABLE_DEBUGGER_SYNC;
    private static final MethodHandle FRIDA_SCRIPT_DISABLE_DEBUGGER_SYNC;

    static {
        Frida.ensureInitialized();

        FRIDA_SCRIPT_LOAD_SYNC = FridaLibraryLoader.findFunction("frida_script_load_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SCRIPT_UNLOAD_SYNC = FridaLibraryLoader.findFunction("frida_script_unload_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SCRIPT_IS_DESTROYED = FridaLibraryLoader.findFunction("frida_script_is_destroyed",
                FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
        FRIDA_SCRIPT_ETERNALIZE_SYNC = FridaLibraryLoader.findFunction("frida_script_eternalize_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SCRIPT_POST = FridaLibraryLoader.findFunction("frida_script_post",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SCRIPT_ENABLE_DEBUGGER_SYNC = FridaLibraryLoader.findFunction("frida_script_enable_debugger_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_SHORT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SCRIPT_DISABLE_DEBUGGER_SYNC = FridaLibraryLoader.findFunction("frida_script_disable_debugger_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    public Script(MemorySegment scriptPtr) {
        this.scriptPtr = FridaNativeUtils.requireValidPointer(scriptPtr, "Script pointer");
        log.debug("Script object created");
    }

    /**
     * Load the script
     */
    public void load() {
        log.debug("Loading script");
        // Set up default message handler if none exists for RPC functionality
        if (!hasMessageHandler) {
            on("message", (SignalCallbacks.MessageCallback) (_, _) -> {
                // Default empty handler for RPC functionality
            });
        }

        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            log.trace("Native call: frida_script_load_sync()");
            // Load the script (script, cancellable=NULL, error)
            FRIDA_SCRIPT_LOAD_SYNC.invokeExact(scriptPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "load script");
            log.debug("Script loaded successfully");
        } catch (Throwable e) {
            log.debug("Failed to load script: {}", e.getMessage());
            throw new FridaException("Failed to load script", e);
        }
    }

    /**
     * Unload the script
     */
    public void unload() {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Unload the script (script, cancellable=NULL, error)
            FRIDA_SCRIPT_UNLOAD_SYNC.invokeExact(scriptPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "unload script");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to unload script", e);
        }
    }


    /**
     * Check if the script is destroyed
     * @return true if the script is destroyed, false otherwise
     */
    public boolean isDestroyed() {
        try {
            return (boolean) FRIDA_SCRIPT_IS_DESTROYED.invokeExact(scriptPtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to check if script is destroyed", e);
        }
    }

    /**
     * Eternalize the script - keep it loaded even after detaching from process
     */
    public void eternalize() {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Eternalize the script (script, cancellable=NULL, error)
            FRIDA_SCRIPT_ETERNALIZE_SYNC.invoke(scriptPtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "eternalize script");
        } catch (Throwable e) {
            throw new FridaException("Failed to eternalize script", e);
        }
    }

    /**
     * Post a message to the script
     * @param jsonString JSON message to send
     * @param data Optional binary data (can be null)
     */
    public void post(String jsonString, byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment jsonPtr = arena.allocateFrom(jsonString);
            MemorySegment dataPtr = MemorySegment.NULL;

            if (data != null && data.length > 0) {
                // Convert to GBytes for proper binary data handling
                dataPtr = GBytesUtil.fromByteArray(data, arena);
            }

            // Post to script (script, json, data)
            FRIDA_SCRIPT_POST.invoke(scriptPtr, jsonPtr, dataPtr);
        } catch (Throwable e) {
            throw new FridaException("Failed to post message to script", e);
        }
    }

    /**
     * Post a JSON message to the script without binary data
     * @param jsonString JSON message to send
     */
    public void post(String jsonString) {
        post(jsonString, null);
    }

    /**
     * Enable debugger on the specified port
     * @param port Port number for debugging
     */
    public void enableDebugger(short port) {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Enable debugger (script, port, cancellable=NULL, error)
            FRIDA_SCRIPT_ENABLE_DEBUGGER_SYNC.invoke(scriptPtr, port, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "enable debugger on port: " + port);
        } catch (Throwable e) {
            throw new FridaException("Failed to enable debugger on port: " + port, e);
        }
    }

    /**
     * Disable debugger
     */
    public void disableDebugger() {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Disable debugger (script, cancellable=NULL, error)
            FRIDA_SCRIPT_DISABLE_DEBUGGER_SYNC.invoke(scriptPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "disable debugger");
        } catch (Throwable e) {
            throw new FridaException("Failed to disable debugger", e);
        }
    }

    /**
     * Register callbacks for script events. Available signals:
     * - "message" with callback as MessageCallback
     * - "destroyed" with callback as VoidCallback or Runnable
     *
     * @param signalName Name of the signal to register for
     * @param callback Callback object to handle the signal
     */
    public void on(String signalName, Object callback) {
        log.debug("Registering callback for script signal: {}", signalName);

        if ("message".equals(signalName)) {
            if (!(callback instanceof SignalCallbacks.MessageCallback)) {
                throw new IllegalArgumentException("Callback must be a MessageCallback for 'message' signal");
            }
            this.messageCallback = (SignalCallbacks.MessageCallback) callback;
            hasMessageHandler = true;

            // Wire up hijackMessage instead of user callback to intercept RPC responses
            try {
                SignalCallbacks.MessageCallback hijackCallback = this::hijackMessage;
                long handlerId = Closure.connectClosure(scriptPtr, signalName, hijackCallback);

                if (handlerId > 0) {
                    log.trace("Connected script message signal with handler ID {}", handlerId);
                } else {
                    log.warn("Failed to connect script message signal - no handler ID returned");
                }
            } catch (Exception e) {
                log.debug("Failed to connect script message signal: {}", e.getMessage());
                throw new FridaException("Failed to connect script message signal", e);
            }
        } else if ("destroyed".equals(signalName)) {
            if (!(callback instanceof SignalCallbacks.VoidCallback) && !(callback instanceof Runnable)) {
                throw new IllegalArgumentException("Callback must be a VoidCallback or Runnable for 'destroyed' signal");
            }

            try {
                long handlerId = Closure.connectClosure(scriptPtr, signalName, callback);

                if (handlerId > 0) {
                    log.trace("Connected script destroyed signal with handler ID {}", handlerId);
                } else {
                    log.warn("Failed to connect script destroyed signal - no handler ID returned");
                }
            } catch (Exception e) {
                log.debug("Failed to connect script destroyed signal: {}", e.getMessage());
                throw new FridaException("Failed to connect script destroyed signal", e);
            }
        } else {
            throw new IllegalArgumentException("Unknown signal: " + signalName);
        }

        log.trace("Registered callback for script signal '{}'", signalName);
    }

    /**
     * Call a function exported by the script's RPC interface
     * @param functionName Name of the function to call
     * @param args Arguments to pass to the function
     * @return The result returned by the function
     */
    public Object exportsCall(String functionName, Object... args) {
        CompletableFuture<Object> future = makeExportsCall(functionName, args);

        try {
            return future.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FridaException("RPC call was interrupted", e);
        } catch (ExecutionException e) {
            throw new FridaException("RPC call failed", e.getCause());
        }
    }

    /**
     * Call a function exported by the script's RPC interface with timeout and cancellation support
     * @param context CompletableFuture that can be used for cancellation
     * @param functionName Name of the function to call
     * @param args Arguments to pass to the function
     * @return The result returned by the function
     * @throws FridaException if the context is cancelled
     */
    public Object exportsCallWithContext(CompletableFuture<Void> context, String functionName, Object... args) {
        CompletableFuture<Object> rpcFuture = makeExportsCall(functionName, args);

        // Race between RPC call and context cancellation
        CompletableFuture<Object> result = rpcFuture.applyToEither(
                context.thenApply(v -> {
                    throw new FridaException("RPC call was cancelled");
                }),
                value -> value
        );

        try {
            return result.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FridaException("RPC call was interrupted", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof FridaException) {
                throw (FridaException) cause;
            }
            throw new FridaException("RPC call failed", cause);
        }
    }


    /**
     * Call a function exported by the script's RPC interface with timeout
     * @param functionName Name of the function to call
     * @param timeoutMs Timeout in milliseconds
     * @param args Arguments to pass to the function
     * @return The result returned by the function
     * @throws TimeoutException if the call times out
     */
    public Object exportsCallWithTimeout(String functionName, long timeoutMs, Object... args)
            throws TimeoutException {
        CompletableFuture<Object> future = makeExportsCall(functionName, args);

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FridaException("RPC call was interrupted", e);
        } catch (ExecutionException e) {
            throw new FridaException("RPC call failed", e.getCause());
        }
    }

    /**
     * Internal method to create and execute RPC calls
     * <hr>
     * Note: Unlike the Go implementation which uses sync.Pool for channel pooling,
     * we don't pool CompletableFuture objects here. Modern Java's JVM (especially Java 11+)
     * handles short-lived object allocation extremely efficiently through:
     * - Escape analysis (stack allocation for thread-local objects)
     * - TLAB (Thread-Local Allocation Buffers) for near-zero cost allocation
     * - Efficient GC (G1/ZGC) that handles high allocation rates with minimal pause times
     * <br>
     * Pooling would only be beneficial if profiling shows >10,000 RPC calls/second
     * causing GC pressure, which is extremely rare in typical Frida workflows.
     */
    private CompletableFuture<Object> makeExportsCall(String functionName, Object... args) {
        Object[] rpcCall = RpcManager.createRpcCall(functionName, args);
        String rpcId = (String) rpcCall[1]; // Extract RPC ID

        // Register the call before sending
        CompletableFuture<Object> future = RpcManager.registerRpcCall(rpcId);

        // Send the RPC call
        String jsonMessage = RpcManager.toJsonString(rpcCall);
        post(jsonMessage);

        return future;
    }

    /**
     * Hijack message handling to intercept RPC responses
     */
    private void hijackMessage(String message, byte[] data) {
        // Check if this is an RPC response
        RpcManager.RpcResult rpcResult = RpcManager.extractRpcResult(message);

        if (rpcResult != null) {
            // This is an RPC response, complete the corresponding future
            RpcManager.completeRpcCall(rpcResult.getRpcId(), rpcResult.getResult());
        } else {
            // This is a regular message, forward to user callback
            if (messageCallback != null) {
                messageCallback.onMessage(message, data);
            }
        }
    }

    public void clean() {
        if (closed) {
            return; // Already cleaned up
        }

        try {
            if (!scriptPtr.equals(MemorySegment.NULL)) {
                FridaNativeUtils.fridaUnref(this.scriptPtr);
            }
            closed = true;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to cleanup Script", e);
        }
    }

    /**
     * Automatically unload when used in try-with-resources
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }

        try {
            unload();
        } catch (FridaException e) {
            // Unload might fail if script is already unloaded, that's OK
            log.debug("Unload failed during close (may be normal): {}", e.getMessage());
        }
        clean();
    }
}
