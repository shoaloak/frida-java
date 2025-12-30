package nl.axelkoolhaas.frida_java.frida;

import nl.axelkoolhaas.frida_java.FridaJava;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

/**
 * Options for spawning processes
 */
public class SpawnOptions implements AutoCloseable {
    private final MemorySegment optionsPtr;

    private static final MethodHandle FRIDA_SPAWN_OPTIONS_NEW;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_SET_ARGV;

    static {
        Frida.ensureInitialized();

        FRIDA_SPAWN_OPTIONS_NEW = FridaJava.findFunction("frida_spawn_options_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_SPAWN_OPTIONS_SET_ARGV = FridaJava.findFunction("frida_spawn_options_set_argv",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    }

    public SpawnOptions() {
        try {
            this.optionsPtr = (MemorySegment) FRIDA_SPAWN_OPTIONS_NEW.invoke();
            FridaJava.requireValidPointer(optionsPtr, "SpawnOptions pointer");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to create SpawnOptions", e);
        }
    }

    /**
     * Set arguments for the spawned process
     * @param args Array of arguments (including program name as first argument)
     */
    public void setArgv(String[] args) {
        try (Arena arena = Arena.ofConfined()) {
            // Create array of string pointers
            MemorySegment argvArray = arena.allocate(ValueLayout.ADDRESS, args.length);

            for (int i = 0; i < args.length; i++) {
                MemorySegment argPtr = arena.allocateFrom(args[i]);
                argvArray.setAtIndex(ValueLayout.ADDRESS, i, argPtr);
            }

            FRIDA_SPAWN_OPTIONS_SET_ARGV.invoke(optionsPtr, argvArray, args.length);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to set argv", e);
        }
    }

    MemorySegment getPointer() {
        return optionsPtr;
    }

    public void clean() {
        try {
            FridaJava.fridaUnref(optionsPtr);
        } catch (Throwable e) {
            System.err.println("Warning: Failed to cleanup SpawnOptions: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        clean();
    }
}
