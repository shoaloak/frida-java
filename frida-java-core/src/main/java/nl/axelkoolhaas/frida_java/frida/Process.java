package nl.axelkoolhaas.frida_java.frida;

import nl.axelkoolhaas.frida_java.FridaJava;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * Represents a process on a Frida device
 */
public class Process {
    private final MemorySegment processPtr;

    private static final MethodHandle FRIDA_PROCESS_GET_PID;
    private static final MethodHandle FRIDA_PROCESS_GET_NAME;

    static {
        FRIDA_PROCESS_GET_PID = FridaJava.findFunction("frida_process_get_pid",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_PROCESS_GET_NAME = FridaJava.findFunction("frida_process_get_name",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /**
     * Create a Process wrapper around a native process pointer
     * @param processPtr Native process pointer
     */
    public Process(MemorySegment processPtr) {
        this.processPtr = FridaJava.requireValidPointer(processPtr, "Process pointer");
    }

    /**
     * Get the process ID
     * @return Process ID (PID)
     */
    public int getPid() {
        try {
            return (int) FRIDA_PROCESS_GET_PID.invoke(processPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get process PID", e);
        }
    }

    /**
     * Get the process name
     * @return Process name
     */
    public String getName() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_PROCESS_GET_NAME.invoke(processPtr);
            return FridaJava.memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get process name", e);
        }
    }

    @Override
    public String toString() {
        return String.format("Process{pid=%d, name='%s'}", getPid(), getName());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Process other))
            return false;
        return getPid() == other.getPid();
    }

    @Override
    public int hashCode() {
        return Integer.hashCode(getPid());
    }
}
