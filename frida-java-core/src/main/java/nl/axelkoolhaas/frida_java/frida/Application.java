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

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Application {
    private static final Logger log = LoggerFactory.getLogger(Application.class);
    private final MemorySegment applicationPtr;

    private static final MethodHandle FRIDA_APPLICATION_GET_IDENTIFIER;
    private static final MethodHandle FRIDA_APPLICATION_GET_NAME;
    private static final MethodHandle FRIDA_APPLICATION_GET_PID;

    static {
        Frida.ensureInitialized();
        FRIDA_APPLICATION_GET_IDENTIFIER = FridaLibraryLoader.findFunction("frida_application_get_identifier",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_APPLICATION_GET_NAME = FridaLibraryLoader.findFunction("frida_application_get_name",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_APPLICATION_GET_PID = FridaLibraryLoader.findFunction("frida_application_get_pid",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    }

    /**
     * Create an Application wrapper around a native application pointer
     * @param applicationPtr Native application pointer
     */
    public Application(MemorySegment applicationPtr) {
        this.applicationPtr = FridaNativeUtils.requireValidPointer(applicationPtr, "Application pointer");
        log.debug("Application created");
    }

    public String getIdentifier() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_APPLICATION_GET_IDENTIFIER.invoke(applicationPtr);
            String identifier = FridaNativeUtils.memorySegmentToString(result);
            log.trace("Got application identifier: {}", identifier);
            return identifier;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to get application identifier: {}", e.getMessage());
            throw new FridaException("Failed to get application identifier", e);
        }
    }

    public String getName() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_APPLICATION_GET_NAME.invoke(applicationPtr);
            String name = FridaNativeUtils.memorySegmentToString(result);
            log.trace("Got application name: {}", name);
            return name;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to get application name: {}", e.getMessage());
            throw new FridaException("Failed to get application name", e);
        }
    }

    public int getPid() {
        try {
            int pid = (int) FRIDA_APPLICATION_GET_PID.invoke(applicationPtr);
            log.trace("Got application PID: {}", pid);
            return pid;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to get application PID: {}", e.getMessage());
            throw new FridaException("Failed to get application PID", e);
        }
    }

    @Override
    public String toString() {
        return String.format("Application{identifier='%s', name='%s', pid=%d}",
                getIdentifier(), getName(), getPid());
    }
}
