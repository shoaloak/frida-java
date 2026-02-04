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

package nl.axelkoolhaas.frida_java;

import nl.axelkoolhaas.frida_java.frida.Closure;
import nl.axelkoolhaas.frida_java.frida.FridaException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.foreign.Arena;
import java.lang.invoke.MethodHandle;
import java.util.Objects;

public class FridaNativeUtils {
    private static final Logger log = LoggerFactory.getLogger(FridaNativeUtils.class);

    private static final MethodHandle FRIDA_UNREF;
    private static final MethodHandle G_SIGNAL_LOOKUP;
    private static final MethodHandle G_SIGNAL_CONNECT_DATA;
    private static final MethodHandle G_SIGNAL_HANDLER_DISCONNECT;

    // Type getter functions for different Frida object types
    private static final MethodHandle FRIDA_SCRIPT_GET_TYPE;
    private static final MethodHandle FRIDA_SESSION_GET_TYPE;
    private static final MethodHandle FRIDA_DEVICE_GET_TYPE;
    private static final MethodHandle FRIDA_DEVICE_MANAGER_GET_TYPE;
    private static final MethodHandle FRIDA_COMPILER_GET_TYPE;
    private static final MethodHandle FRIDA_BUS_GET_TYPE;

    static {
        FRIDA_UNREF = FridaLibraryLoader.findFunction("frida_unref",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        G_SIGNAL_LOOKUP = FridaLibraryLoader.findFunction("g_signal_lookup",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
        G_SIGNAL_CONNECT_DATA = FridaLibraryLoader.findFunction("g_signal_connect_data",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        G_SIGNAL_HANDLER_DISCONNECT = FridaLibraryLoader.findFunction("g_signal_handler_disconnect",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

        // Type getter functions - these are exported by Frida
        FRIDA_SCRIPT_GET_TYPE = FridaLibraryLoader.findFunction("frida_script_get_type",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG));
        FRIDA_SESSION_GET_TYPE = FridaLibraryLoader.findFunction("frida_session_get_type",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG));
        FRIDA_DEVICE_GET_TYPE = FridaLibraryLoader.findFunction("frida_device_get_type",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG));
        FRIDA_DEVICE_MANAGER_GET_TYPE = FridaLibraryLoader.findFunction("frida_device_manager_get_type",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG));
        FRIDA_COMPILER_GET_TYPE = FridaLibraryLoader.findFunction("frida_compiler_get_type",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG));
        FRIDA_BUS_GET_TYPE = FridaLibraryLoader.findFunction("frida_bus_get_type",
                FunctionDescriptor.of(ValueLayout.JAVA_LONG));
    }

    /**
     * Validate that a native pointer is not null or NULL
     * @param ptr The memory segment to validate
     * @param name The name for error messages
     * @return The validated pointer
     * @throws IllegalArgumentException if pointer is null or NULL
     */
    public static MemorySegment requireValidPointer(MemorySegment ptr, String name) {
        Objects.requireNonNull(ptr, name + " cannot be null");
        if (ptr.equals(MemorySegment.NULL)) {
            throw new IllegalArgumentException(name + " cannot be NULL");
        }
        return ptr;
    }

    /**
     * Helper method to safely convert a MemorySegment to a UTF-8 string
     * @param segment the memory segment to convert
     * @return the string value, or empty string if segment is NULL
     */
    public static String memorySegmentToString(MemorySegment segment) {
        if (segment.equals(MemorySegment.NULL)) {
            return "";
        }
        // Read the C string using UTF-8 encoding, searching for null terminator
        return segment.reinterpret(Long.MAX_VALUE)
                .getString(0, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Call frida_unref on a pointer
     * Note that this will call g_object_unref under the hood
     * @param object the GObject memory segment
     */
    public static void fridaUnref(MemorySegment object) {
        try {
            FRIDA_UNREF.invoke(object);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to unref pointer", e);
        }
    }

    /**
     * Get the GType for FridaScript objects.
     */
    public static long getScriptType() {
        try {
            return (long) FRIDA_SCRIPT_GET_TYPE.invoke();
        } catch (Throwable e) {
            throw new FridaException("Failed to get script type", e);
        }
    }

    /**
     * Get the GType for FridaSession objects.
     */
    public static long getSessionType() {
        try {
            return (long) FRIDA_SESSION_GET_TYPE.invoke();
        } catch (Throwable e) {
            throw new FridaException("Failed to get session type", e);
        }
    }

    /**
     * Get the GType for FridaDevice objects.
     */
    public static long getDeviceType() {
        try {
            return (long) FRIDA_DEVICE_GET_TYPE.invoke();
        } catch (Throwable e) {
            throw new FridaException("Failed to get device type", e);
        }
    }

    /**
     * Get the GType for FridaDeviceManager objects.
     */
    public static long getDeviceManagerType() {
        try {
            return (long) FRIDA_DEVICE_MANAGER_GET_TYPE.invoke();
        } catch (Throwable e) {
            throw new FridaException("Failed to get device manager type", e);
        }
    }

    /**
     * Get the GType for FridaCompiler objects.
     */
    public static long getCompilerType() {
        try {
            return (long) FRIDA_COMPILER_GET_TYPE.invoke();
        } catch (Throwable e) {
            throw new FridaException("Failed to get compiler type", e);
        }
    }

    /**
     * Get the GType for FridaBus objects.
     */
    public static long getBusType() {
        try {
            return (long) FRIDA_BUS_GET_TYPE.invoke();
        } catch (Throwable e) {
            throw new FridaException("Failed to get bus type", e);
        }
    }

    /**
     * Connect a Java callback to a GObject signal.
     * This is the Java equivalent of the Go connectClosure function.
     *
     * @param object GObject pointer to connect to
     * @param signalName Name of the signal to connect to
     * @param callback Java callback object
     * @param objectType The GType of the object (use getScriptType(), getCompilerType(), etc.)
     * @return Handler ID that can be used to disconnect the signal later
     */
    public static long connectSignal(MemorySegment object, String signalName, Object callback, long objectType) {
        log.debug("Connecting signal '{}' to object", signalName);
        try (Arena arena = Arena.ofConfined()) {
            Closure closure = Closure.create(callback, signalName);
            MemorySegment signalNamePtr = arena.allocateFrom(signalName);

            log.trace("Object type: {}", objectType);

            int signalId = (int) G_SIGNAL_LOOKUP.invoke(signalNamePtr, objectType);
            log.trace("Signal ID for '{}': {}", signalName, signalId);

            // Do nothing if signal is 0 meaning not found (matching Go behavior)
            if (signalId == 0) {
                log.debug("Signal '{}' not found on object type {}", signalName, objectType);
                return 0;
            }

            long handlerId = (long) G_SIGNAL_CONNECT_DATA.invoke(
                    object,                          // instance
                    signalNamePtr,                   // detailed_signal
                    closure.getNativeCallback(),     // c_handler
                    MemorySegment.NULL,              // data
                    MemorySegment.NULL,              // destroy_data
                    0                                // connect_flags (0 = G_CONNECT_DEFAULT)
            );
            log.debug("Connected signal '{}' with handler ID {}", signalName, handlerId);
            return handlerId;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.error("Failed to connect signal '{}': {}", signalName, e.getMessage());
            throw new FridaException("Failed to connect signal: " + signalName, e);
        }
    }

    /**
     * Disconnect a signal handler
     *
     * @param object GObject pointer that the signal is connected to
     * @param handlerId Handler ID returned from connectSignal
     */
    public static void disconnectSignal(MemorySegment object, long handlerId) {
        log.debug("Disconnecting signal handler {}", handlerId);
        try {
            G_SIGNAL_HANDLER_DISCONNECT.invoke(object, handlerId);
            log.trace("Successfully disconnected handler {}", handlerId);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.error("Failed to disconnect signal handler {}: {}", handlerId, e.getMessage());
            throw new FridaException("Failed to disconnect signal handler: " + handlerId, e);
        }
    }
}
