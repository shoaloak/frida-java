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

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Represents a Frida script
 */
public class Script implements AutoCloseable {
    private final MemorySegment scriptPtr;
    private boolean hasMessageHandler = false;
    private Closure.MessageCallback messageCallback;
    private Closure messageClosure; // TODO: REVIEW

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
    }

    /**
     * Load the script
     */
    public void load() {
        // Set up default message handler if none exists for RPC functionality
        if (!hasMessageHandler) {
            on("message", new Closure.MessageCallback() {
                @Override
                public void onMessage(String message, byte[] data) {
                    // Default empty handler for RPC functionality
                }
            });
        }

        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Load the script (script, cancellable=NULL, error)
            FRIDA_SCRIPT_LOAD_SYNC.invoke(scriptPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.checkAndThrow(error, "load script");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to load script", e);
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
            FRIDA_SCRIPT_UNLOAD_SYNC.invoke(scriptPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.checkAndThrow(error, "unload script");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to unload script", e);
        }
    }


    /**
     * Check if the script is destroyed
     * @return true if the script is destroyed, false otherwise
     */
    public boolean isDestroyed() {
        try {
            return (boolean) FRIDA_SCRIPT_IS_DESTROYED.invoke(scriptPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to check if script is destroyed", e);
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
            GErrorUtils.checkAndThrow(error, "eternalize script");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to eternalize script", e);
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
                dataPtr = FridaNativeUtils.bytesToGBytes(data, arena);
            }

            // Post to script (script, json, data)
            FRIDA_SCRIPT_POST.invoke(scriptPtr, jsonPtr, dataPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to post message to script", e);
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
            GErrorUtils.checkAndThrow(error, "enable debugger on port: " + port);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to enable debugger on port: " + port, e);
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
            GErrorUtils.checkAndThrow(error, "disable debugger");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to disable debugger", e);
        }
    }

    /**
     * Connect to script signals. Available signals:
     * - "destroyed" with callback as Runnable
     * - "message" with callback as MessageCallback
     *
     * @param signalName Name of the signal to connect to
     * @param callback Callback object to handle the signal
     */
    public void on(String signalName, Object callback) {
        hasMessageHandler = true;

        if ("message".equals(signalName)) {
            // Set up message hijacking for RPC functionality
            this.messageCallback = (callback instanceof Closure.MessageCallback) ?
                (Closure.MessageCallback) callback :
                (message, data) -> {
                    if (callback instanceof Closure.MessageCallback) {
                        ((Closure.MessageCallback) callback).onMessage(message, data);
                    }
                };

            // Create hijacking message handler
            Closure.MessageCallback hijackingHandler = this::hijackMessage;
            this.messageClosure = Closure.create(hijackingHandler, signalName);
            FridaNativeUtils.connectSignal(scriptPtr, signalName, hijackingHandler);
        } else {
            // For other signals, connect directly
            FridaNativeUtils.connectSignal(scriptPtr, signalName, callback);
        }
    }

    /**
     * Call a function exported by the script's RPC interface
     * @param functionName Name of the function to call
     * @param args Arguments to pass to the function
     * @return The result returned by the function
     */
    public Object exportsCall(String functionName, Object... args) {
        try {
            CompletableFuture<Object> future = makeExportsCall(functionName, args);
            return future.get(); // Block until result is available
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("RPC call was interrupted", e);
        } catch (ExecutionException e) {
            throw new RuntimeException("RPC call failed", e.getCause());
        }
    }

    /**
     * Call a function exported by the script's RPC interface with timeout and cancellation support
     * @param context CompletableFuture that can be used for cancellation
     * @param functionName Name of the function to call
     * @param args Arguments to pass to the function
     * @return The result returned by the function
     * @throws ContextCancelledException if the context is cancelled
     */
    public Object exportsCallWithContext(CompletableFuture<Void> context, String functionName, Object... args) {
        try {
            CompletableFuture<Object> rpcFuture = makeExportsCall(functionName, args);

            // Race between the RPC call and context cancellation
            CompletableFuture<Object> result = rpcFuture.applyToEither(
                context.thenApply(v -> {
                    throw new ContextCancelledException();
                }),
                value -> value
            );

            return result.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("RPC call was interrupted", e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof ContextCancelledException) {
                throw (ContextCancelledException) e.getCause();
            }
            throw new RuntimeException("RPC call failed", e.getCause());
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
        try {
            CompletableFuture<Object> future = makeExportsCall(functionName, args);
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("RPC call was interrupted", e);
        } catch (ExecutionException e) {
            throw new RuntimeException("RPC call failed", e.getCause());
        }
    }

    /**
     * Internal method to create and execute RPC calls
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
        try {
            FridaNativeUtils.fridaUnref(this.scriptPtr);
        } catch (Throwable e) {
            // Log error but don't throw, cleanup should be safe
            System.err.println("Warning: Failed to cleanup Script: " + e.getMessage());
        }
    }

    /**
     * Automatically unload when used in try-with-resources
     */
    @Override
    public void close() {
        unload();
        clean();
    }
}
