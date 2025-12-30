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
import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.util.GHashTableUtil;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Options for spawning processes
 */
public class SpawnOptions implements AutoCloseable {
    private final MemorySegment optionsPtr;

    private static final MethodHandle FRIDA_SPAWN_OPTIONS_NEW;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_SET_ARGV;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_GET_ARGV;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_SET_ENVP;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_GET_ENVP;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_SET_ENV;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_GET_ENV;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_SET_CWD;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_GET_CWD;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_SET_STDIO;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_GET_STDIO;
    private static final MethodHandle FRIDA_SPAWN_OPTIONS_GET_AUX;

    static {
        Frida.ensureInitialized();

        FRIDA_SPAWN_OPTIONS_NEW = FridaLibraryLoader.findFunction("frida_spawn_options_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_SPAWN_OPTIONS_SET_ARGV = FridaLibraryLoader.findFunction("frida_spawn_options_set_argv",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_SPAWN_OPTIONS_GET_ARGV = FridaLibraryLoader.findFunction("frida_spawn_options_get_argv",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SPAWN_OPTIONS_SET_ENVP = FridaLibraryLoader.findFunction("frida_spawn_options_set_envp",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_SPAWN_OPTIONS_GET_ENVP = FridaLibraryLoader.findFunction("frida_spawn_options_get_envp",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SPAWN_OPTIONS_SET_ENV = FridaLibraryLoader.findFunction("frida_spawn_options_set_env",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_SPAWN_OPTIONS_GET_ENV = FridaLibraryLoader.findFunction("frida_spawn_options_get_env",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SPAWN_OPTIONS_SET_CWD = FridaLibraryLoader.findFunction("frida_spawn_options_set_cwd",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SPAWN_OPTIONS_GET_CWD = FridaLibraryLoader.findFunction("frida_spawn_options_get_cwd",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SPAWN_OPTIONS_SET_STDIO = FridaLibraryLoader.findFunction("frida_spawn_options_set_stdio",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_SPAWN_OPTIONS_GET_STDIO = FridaLibraryLoader.findFunction("frida_spawn_options_get_stdio",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_SPAWN_OPTIONS_GET_AUX = FridaLibraryLoader.findFunction("frida_spawn_options_get_aux",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    public SpawnOptions() {
        try {
            this.optionsPtr = (MemorySegment) FRIDA_SPAWN_OPTIONS_NEW.invoke();
            FridaNativeUtils.requireValidPointer(optionsPtr, "SpawnOptions pointer");
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

    /**
     * Get arguments for the spawned process
     * @return List of arguments
     */
    public List<String> getArgv() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment countPtr = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment argvPtr = (MemorySegment) FRIDA_SPAWN_OPTIONS_GET_ARGV.invoke(optionsPtr, countPtr);

            if (argvPtr.equals(MemorySegment.NULL)) {
                return new ArrayList<>();
            }

            int count = countPtr.get(ValueLayout.JAVA_INT, 0);
            List<String> args = new ArrayList<>(count);

            for (int i = 0; i < count; i++) {
                MemorySegment strPtr = argvPtr.getAtIndex(ValueLayout.ADDRESS, i);
                args.add(FridaNativeUtils.memorySegmentToString(strPtr));
            }

            return args;
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get argv", e);
        }
    }


    /**
     * Set environment variables for the spawned process (envp format)
     * @param envp Map of environment variables
     */
    public void setEnvp(Map<String, String> envp) {
        try (Arena arena = Arena.ofConfined()) {
            String[] envArray = new String[envp.size()];
            int i = 0;
            for (Map.Entry<String, String> entry : envp.entrySet()) {
                envArray[i++] = entry.getKey() + "=" + entry.getValue();
            }

            MemorySegment envpArray = arena.allocate(ValueLayout.ADDRESS, envArray.length);
            for (i = 0; i < envArray.length; i++) {
                MemorySegment envPtr = arena.allocateFrom(envArray[i]);
                envpArray.setAtIndex(ValueLayout.ADDRESS, i, envPtr);
            }

            FRIDA_SPAWN_OPTIONS_SET_ENVP.invoke(optionsPtr, envpArray, envArray.length);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to set envp", e);
        }
    }

    /**
     * Get environment variables (envp format)
     * @return List of environment strings in key=value format
     */
    public List<String> getEnvp() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment countPtr = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment envpPtr = (MemorySegment) FRIDA_SPAWN_OPTIONS_GET_ENVP.invoke(optionsPtr, countPtr);

            if (envpPtr.equals(MemorySegment.NULL)) {
                return new ArrayList<>();
            }

            int count = countPtr.get(ValueLayout.JAVA_INT, 0);
            List<String> envp = new ArrayList<>(count);

            for (int i = 0; i < count; i++) {
                MemorySegment strPtr = envpPtr.getAtIndex(ValueLayout.ADDRESS, i);
                envp.add(FridaNativeUtils.memorySegmentToString(strPtr));
            }

            return envp;
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get envp", e);
        }
    }

    /**
     * Set environment variables for the spawned process (env format)
     * @param env Map of environment variables
     */
    public void setEnv(Map<String, String> env) {
        try (Arena arena = Arena.ofConfined()) {
            String[] envArray = new String[env.size()];
            int i = 0;
            for (Map.Entry<String, String> entry : env.entrySet()) {
                envArray[i++] = entry.getKey() + "=" + entry.getValue();
            }

            MemorySegment envArrayPtr = arena.allocate(ValueLayout.ADDRESS, envArray.length);
            for (i = 0; i < envArray.length; i++) {
                MemorySegment envPtr = arena.allocateFrom(envArray[i]);
                envArrayPtr.setAtIndex(ValueLayout.ADDRESS, i, envPtr);
            }

            FRIDA_SPAWN_OPTIONS_SET_ENV.invoke(optionsPtr, envArrayPtr, envArray.length);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to set env", e);
        }
    }

    /**
     * Get environment variables (env format)
     * @return List of environment strings in key=value format
     */
    public List<String> getEnv() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment countPtr = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment envPtr = (MemorySegment) FRIDA_SPAWN_OPTIONS_GET_ENV.invoke(optionsPtr, countPtr);

            if (envPtr.equals(MemorySegment.NULL)) {
                return new ArrayList<>();
            }

            int count = countPtr.get(ValueLayout.JAVA_INT, 0);
            List<String> env = new ArrayList<>(count);

            for (int i = 0; i < count; i++) {
                MemorySegment strPtr = envPtr.getAtIndex(ValueLayout.ADDRESS, i);
                env.add(FridaNativeUtils.memorySegmentToString(strPtr));
            }

            return env;
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get env", e);
        }
    }

    /**
     * Set current working directory for the spawned process
     * @param cwd Working directory path
     */
    public void setCwd(String cwd) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment cwdPtr = arena.allocateFrom(cwd);
            FRIDA_SPAWN_OPTIONS_SET_CWD.invoke(optionsPtr, cwdPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to set cwd", e);
        }
    }

    /**
     * Get current working directory for the spawned process
     * @return Working directory path
     */
    public String getCwd() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_SPAWN_OPTIONS_GET_CWD.invoke(optionsPtr);
            return FridaNativeUtils.memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get cwd", e);
        }
    }

    /**
     * Set standard I/O configuration for the spawned process
     * @param stdio Standard I/O configuration
     */
    public void setStdio(Stdio stdio) {
        try {
            FRIDA_SPAWN_OPTIONS_SET_STDIO.invoke(optionsPtr, stdio.getValue());
        } catch (Throwable e) {
            throw new RuntimeException("Failed to set stdio", e);
        }
    }

    /**
     * Get standard I/O configuration for the spawned process
     * @return Standard I/O configuration
     */
    public Stdio getStdio() {
        try {
            int stdioValue = (int) FRIDA_SPAWN_OPTIONS_GET_STDIO.invoke(optionsPtr);
            return Stdio.fromValue(stdioValue);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get stdio", e);
        }
    }

    /**
     * Get auxiliary data for the spawn options
     * @return Map of auxiliary data
     */
    public Map<String, Object> getAux() {
        try {
            MemorySegment auxPtr = (MemorySegment) FRIDA_SPAWN_OPTIONS_GET_AUX.invoke(optionsPtr);
            return GHashTableUtil.toMap(auxPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get aux", e);
        }
    }

    MemorySegment getPointer() {
        return optionsPtr;
    }

    public void clean() {
        try {
            FridaNativeUtils.fridaUnref(optionsPtr);
        } catch (Throwable e) {
            System.err.println("Warning: Failed to cleanup SpawnOptions: " + e.getMessage());
        }
    }

    @Override
    public void close() {
        clean();
    }
}
