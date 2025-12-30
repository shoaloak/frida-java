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

/**
 * Represents a Frida script
 */
public class Script implements AutoCloseable {
    private final MemorySegment scriptPtr;

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
                // For now, we'll implement basic data posting without GBytes conversion
                // This can be enhanced later with proper GBytes handling
                dataPtr = arena.allocate(data.length);
                dataPtr.copyFrom(MemorySegment.ofArray(data));
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

    // TODO: Implement RPC functionality (ExportsCall, On, event handling)
    // This would require implementing:
    // - Event handling infrastructure
    // - JSON RPC call mechanism
    // - Message hijacking for RPC responses
    // - UUID generation for RPC calls
    // - Concurrent RPC call management

    /**
     * Automatically unload when used in try-with-resources
     */
    @Override
    public void close() {
        unload();
    }
}
