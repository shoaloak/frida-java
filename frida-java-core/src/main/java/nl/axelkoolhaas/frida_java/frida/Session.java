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
 * Represents a Frida session with a target process
 */
public class Session implements AutoCloseable {
    private final MemorySegment sessionPtr;

    private static final MethodHandle FRIDA_SESSION_IS_DETACHED;
    private static final MethodHandle FRIDA_SESSION_DETACH_SYNC;
    private static final MethodHandle FRIDA_SESSION_RESUME_SYNC;
    private static final MethodHandle FRIDA_SESSION_GET_PID;
    private static final MethodHandle FRIDA_SESSION_ENABLE_CHILD_GATING_SYNC;
    private static final MethodHandle FRIDA_SESSION_DISABLE_CHILD_GATING_SYNC;
    private static final MethodHandle FRIDA_SESSION_CREATE_SCRIPT_SYNC;

    static {
        Frida.ensureInitialized();

        FRIDA_SESSION_IS_DETACHED = FridaLibraryLoader.findFunction("frida_session_is_detached",
                FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
        FRIDA_SESSION_DETACH_SYNC = FridaLibraryLoader.findFunction("frida_session_detach_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SESSION_RESUME_SYNC = FridaLibraryLoader.findFunction("frida_session_resume_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SESSION_GET_PID = FridaLibraryLoader.findFunction("frida_session_get_pid",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_SESSION_ENABLE_CHILD_GATING_SYNC = FridaLibraryLoader.findFunction("frida_session_enable_child_gating_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SESSION_DISABLE_CHILD_GATING_SYNC = FridaLibraryLoader.findFunction("frida_session_disable_child_gating_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SESSION_CREATE_SCRIPT_SYNC = FridaLibraryLoader.findFunction("frida_session_create_script_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    public Session(MemorySegment sessionPtr) {
        this.sessionPtr = FridaNativeUtils.requireValidPointer(sessionPtr, "Session pointer");
    }

    /**
     * Check if the session is detached
     * @return true if the session is detached, false otherwise
     */
    public boolean isDetached() {
        try {
            return (boolean) FRIDA_SESSION_IS_DETACHED.invoke(sessionPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to check if session is detached", e);
        }
    }

    /**
     * Get the PID of the process this session is attached to
     * @return process ID
     */
    public int getPid() {
        try {
            return (int) FRIDA_SESSION_GET_PID.invoke(sessionPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get session PID", e);
        }
    }

    /**
     * Detach the session from the target process
     */
    public void detach() {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Detach the session (session, cancellable=NULL, error)
            FRIDA_SESSION_DETACH_SYNC.invoke(sessionPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.checkAndThrow(error, "detach session");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to detach session", e);
        }
    }

    /**
     * Resume the session
     */
    public void resume() {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Resume the session (session, cancellable=NULL, error)
            FRIDA_SESSION_RESUME_SYNC.invoke(sessionPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.checkAndThrow(error, "resume session");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to resume session", e);
        }
    }

    /**
     * Enable child gating for this session
     */
    public void enableChildGating() {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Enable child gating (session, cancellable=NULL, error)
            FRIDA_SESSION_ENABLE_CHILD_GATING_SYNC.invoke(sessionPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.checkAndThrow(error, "enable child gating");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to enable child gating", e);
        }
    }

    /**
     * Disable child gating for this session
     */
    public void disableChildGating() {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Disable child gating (session, cancellable=NULL, error)
            FRIDA_SESSION_DISABLE_CHILD_GATING_SYNC.invoke(sessionPtr, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.checkAndThrow(error, "disable child gating");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to disable child gating", e);
        }
    }

    /**
     * Create a script in this session
     * @param script JavaScript source code
     * @return Script object
     */
    public Script createScript(String script) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment scriptPtr = arena.allocateFrom(script);

            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Create script (session, script, options=NULL, cancellable=NULL, error)
            MemorySegment scriptObjPtr = (MemorySegment) FRIDA_SESSION_CREATE_SCRIPT_SYNC.invoke(
                    sessionPtr, scriptPtr, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.checkAndThrow(error, "create script");

            return new Script(scriptObjPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to create script", e);
        }
    }

    /**
     * Automatically detach when used in try-with-resources
     */
    @Override
    public void close() {
        if (!isDetached()) {
            detach();
        }
    }
}
