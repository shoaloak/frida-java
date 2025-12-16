package nl.axelkoolhaas.frida_java.frida;

import nl.axelkoolhaas.frida_java.FridaJava;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

public class Application implements AutoCloseable {
    private final MemorySegment applicationPtr;

    private static final MethodHandle FRIDA_APPLICATION_GET_IDENTIFIER;
    private static final MethodHandle FRIDA_APPLICATION_GET_NAME;
    private static final MethodHandle FRIDA_APPLICATION_GET_PID;

    static {
        FRIDA_APPLICATION_GET_IDENTIFIER = FridaJava.findFunction("frida_application_get_identifier",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_APPLICATION_GET_NAME = FridaJava.findFunction("frida_application_get_name",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_APPLICATION_GET_PID = FridaJava.findFunction("frida_application_get_pid",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    }

    /**
     * Create an Application wrapper around a native application pointer
     * @param applicationPtr Native application pointer
     */
    public Application(MemorySegment applicationPtr) {
        this.applicationPtr = FridaJava.requireValidPointer(applicationPtr, "Application pointer");
    }

    public String getIdentifier() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_APPLICATION_GET_IDENTIFIER.invoke(applicationPtr);
            return FridaJava.memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get application identifier", e);
        }
    }

    public String getName() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_APPLICATION_GET_NAME.invoke(applicationPtr);
            return FridaJava.memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get application name", e);
        }
    }

    public int getPid() {
        try {
            return (int) FRIDA_APPLICATION_GET_PID.invoke(applicationPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get application PID", e);
        }
    }

    @Override
    public String toString() {
        return String.format("Application{identifier='%s', name='%s', pid=%d}",
                getIdentifier(), getName(), getPid());
    }

    public void clean() {
        try {
            FridaJava.g_object_unref(applicationPtr);
        } catch (Throwable e) {
            // Log error but don't throw, cleanup should be safe
            System.err.println("Warning: Failed to cleanup Application: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        clean();
    }
}
