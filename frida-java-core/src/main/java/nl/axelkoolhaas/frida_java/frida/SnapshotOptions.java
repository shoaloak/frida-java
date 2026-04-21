/*
 * Copyright (C) 2026 Axel Koolhaas
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

/**
 * Options for script snapshot creation
 */
public class SnapshotOptions implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(SnapshotOptions.class);
    private final MemorySegment optionsPtr;

    private static final MethodHandle FRIDA_SNAPSHOT_OPTIONS_NEW;
    private static final MethodHandle FRIDA_SNAPSHOT_OPTIONS_SET_WARMUP_SCRIPT;
    private static final MethodHandle FRIDA_SNAPSHOT_OPTIONS_SET_RUNTIME;
    private static final MethodHandle FRIDA_SNAPSHOT_OPTIONS_GET_WARMUP_SCRIPT;
    private static final MethodHandle FRIDA_SNAPSHOT_OPTIONS_GET_RUNTIME;

    static {
        Frida.ensureInitialized();

        FRIDA_SNAPSHOT_OPTIONS_NEW = FridaLibraryLoader.findFunction("frida_snapshot_options_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_SNAPSHOT_OPTIONS_SET_WARMUP_SCRIPT = FridaLibraryLoader.findFunction("frida_snapshot_options_set_warmup_script",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SNAPSHOT_OPTIONS_SET_RUNTIME = FridaLibraryLoader.findFunction("frida_snapshot_options_set_runtime",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_SNAPSHOT_OPTIONS_GET_WARMUP_SCRIPT = FridaLibraryLoader.findFunction("frida_snapshot_options_get_warmup_script",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SNAPSHOT_OPTIONS_GET_RUNTIME = FridaLibraryLoader.findFunction("frida_snapshot_options_get_runtime",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    }

    /**
     * Create new snapshot options with default settings
     */
    public SnapshotOptions() {
        try {
            this.optionsPtr = (MemorySegment) FRIDA_SNAPSHOT_OPTIONS_NEW.invoke();
            log.debug("SnapshotOptions created");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to create SnapshotOptions: {}", e.getMessage());
            throw new FridaException("Failed to create SnapshotOptions", e);
        }
    }

    /**
     * Set the warmup script to execute before snapshot
     * @param warmupScript JavaScript code to warm up the runtime
     */
    public void setWarmupScript(String warmupScript) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment warmupPtr = arena.allocateFrom(warmupScript);
            FRIDA_SNAPSHOT_OPTIONS_SET_WARMUP_SCRIPT.invoke(optionsPtr, warmupPtr);
            log.trace("Set warmup script ({} bytes)", warmupScript.length());
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to set warmup script: {}", e.getMessage());
            throw new FridaException("Failed to set warmup script", e);
        }
    }

    /**
     * Set the runtime engine for snapshot
     * @param runtime Runtime engine
     */
    public void setRuntime(ScriptRuntime runtime) {
        try {
            FRIDA_SNAPSHOT_OPTIONS_SET_RUNTIME.invoke(optionsPtr, runtime.getValue());
            log.trace("Set snapshot runtime: {}", runtime);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to set snapshot runtime: {}", e.getMessage());
            throw new FridaException("Failed to set snapshot runtime", e);
        }
    }

    /**
     * Get the warmup script
     * @return Warmup script code
     */
    public String getWarmupScript() {
        try {
            MemorySegment warmupPtr = (MemorySegment) FRIDA_SNAPSHOT_OPTIONS_GET_WARMUP_SCRIPT.invoke(optionsPtr);
            String warmup = FridaNativeUtils.memorySegmentToString(warmupPtr);
            log.trace("Got warmup script ({} bytes)", warmup.length());
            return warmup;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to get warmup script: {}", e.getMessage());
            throw new FridaException("Failed to get warmup script", e);
        }
    }

    /**
     * Get the runtime engine setting
     * @return Runtime engine
     */
    public ScriptRuntime getRuntime() {
        try {
            int value = (int) FRIDA_SNAPSHOT_OPTIONS_GET_RUNTIME.invoke(optionsPtr);
            ScriptRuntime runtime = ScriptRuntime.fromValue(value);
            log.trace("Got snapshot runtime: {}", runtime);
            return runtime;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to get snapshot runtime: {}", e.getMessage());
            throw new FridaException("Failed to get snapshot runtime", e);
        }
    }

    /**
     * Get the native pointer to the options struct
     * Used internally when passing options to session methods
     */
    MemorySegment getPointer() {
        return optionsPtr;
    }

    @Override
    public void close() {
        try {
            FridaNativeUtils.fridaUnref(optionsPtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to cleanup SnapshotOptions", e);
        }
    }
}

