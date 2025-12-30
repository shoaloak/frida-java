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

import nl.axelkoolhaas.frida_java.FridaJava;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a device that Frida connects to
 */
public class Device implements AutoCloseable {
    private final MemorySegment devicePtr;

    private static final MethodHandle FRIDA_DEVICE_GET_DTYPE;
    private static final MethodHandle FRIDA_DEVICE_GET_ID;
    private static final MethodHandle FRIDA_DEVICE_GET_NAME;
    private static final MethodHandle FRIDA_DEVICE_IS_LOST;
    private static final MethodHandle FRIDA_DEVICE_ENUMERATE_PROCESSES;
    private static final MethodHandle FRIDA_PROCESS_LIST_SIZE;
    private static final MethodHandle FRIDA_PROCESS_LIST_GET;

    // Spawn, kill, and resume method handles
    private static final MethodHandle FRIDA_DEVICE_SPAWN_SYNC;
    private static final MethodHandle FRIDA_DEVICE_KILL_SYNC;
    private static final MethodHandle FRIDA_DEVICE_RESUME_SYNC;
    private static final MethodHandle FRIDA_DEVICE_ATTACH_SYNC;

    private static final MethodHandle FRIDA_APPLICATION_QUERY_OPTIONS_NEW;
    private static final MethodHandle FRIDA_APPLICATION_QUERY_OPTIONS_SET_SCOPE;
    private static final MethodHandle FRIDA_APPLICATION_QUERY_OPTIONS_SELECT_IDENTIFIER;
    private static final MethodHandle FRIDA_DEVICE_ENUMERATE_APPLICATIONS;
    private static final MethodHandle FRIDA_APPLICATION_LIST_SIZE;
    private static final MethodHandle FRIDA_APPLICATION_LIST_GET;

    static {
        Frida.ensureInitialized();

        FRIDA_DEVICE_GET_DTYPE = FridaJava.findFunction("frida_device_get_dtype",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_DEVICE_GET_ID = FridaJava.findFunction("frida_device_get_id",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_GET_NAME = FridaJava.findFunction("frida_device_get_name",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_IS_LOST = FridaJava.findFunction("frida_device_is_lost",
                FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
        FRIDA_DEVICE_ENUMERATE_PROCESSES = FridaJava.findFunction("frida_device_enumerate_processes_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_PROCESS_LIST_SIZE = FridaJava.findFunction("frida_process_list_size",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_PROCESS_LIST_GET = FridaJava.findFunction("frida_process_list_get",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        // Spawn, kill, and resume method handles
        FRIDA_DEVICE_SPAWN_SYNC = FridaJava.findFunction("frida_device_spawn_sync",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_KILL_SYNC = FridaJava.findFunction("frida_device_kill_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_RESUME_SYNC = FridaJava.findFunction("frida_device_resume_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_ATTACH_SYNC = FridaJava.findFunction("frida_device_attach_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        FRIDA_APPLICATION_QUERY_OPTIONS_NEW = FridaJava.findFunction("frida_application_query_options_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_APPLICATION_QUERY_OPTIONS_SET_SCOPE = FridaJava.findFunction("frida_application_query_options_set_scope",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_APPLICATION_QUERY_OPTIONS_SELECT_IDENTIFIER = FridaJava.findFunction("frida_application_query_options_select_identifier",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_ENUMERATE_APPLICATIONS = FridaJava.findFunction("frida_device_enumerate_applications_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_APPLICATION_LIST_SIZE = FridaJava.findFunction("frida_application_list_size",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_APPLICATION_LIST_GET = FridaJava.findFunction("frida_application_list_get",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    }

    public Device(MemorySegment devicePtr) {
        this.devicePtr = FridaJava.requireValidPointer(devicePtr, "Device pointer");
    }

    /**
     * Get the device ID
     * @return device ID string, or empty string if device is null
     */
    public String getId() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_DEVICE_GET_ID.invoke(devicePtr);
            return FridaJava.memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get device ID", e);
        }
    }

    /**
     * Get the device name
     * @return device name string, or empty string if device is null
     */
    public String getName() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_DEVICE_GET_NAME.invoke(devicePtr);
            return FridaJava.memorySegmentToString(result);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get device name", e);
        }
    }

    /**
     * Get the device type
     * @return device type
     */
    public DeviceType getType() {
        try {
            int typeValue = (int) FRIDA_DEVICE_GET_DTYPE.invoke(devicePtr);
            return DeviceType.fromValue(typeValue);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get device type", e);
        }
    }

    /**
     * Check if the device is lost
     * @return true if the device is lost, false otherwise
     */
    public boolean isLost() {
        try {
            return (boolean) FRIDA_DEVICE_IS_LOST.invoke(devicePtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to check if device is lost", e);
        }
    }

    /**
     * Enumerate processes running on this device
     * @return List of Process objects
     */
    public List<Process> enumerateProcesses() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment processList = (MemorySegment) FRIDA_DEVICE_ENUMERATE_PROCESSES
                    .invoke(devicePtr, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                throw new RuntimeException("Failed to enumerate processes");
            }

            if (processList.equals(MemorySegment.NULL)) {
                return new ArrayList<>();
            }

            return extractProcessesFromList(processList);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to enumerate processes", e);
        }
    }

    /**
     * Extract Process objects from the native process list
     */
    private List<Process> extractProcessesFromList(MemorySegment processList) throws Throwable {
        int processCount = (int) FRIDA_PROCESS_LIST_SIZE.invoke(processList);
        List<Process> processes = new ArrayList<>(processCount);

        for (int i = 0; i < processCount; i++) {
            MemorySegment processPtr = (MemorySegment) FRIDA_PROCESS_LIST_GET.invoke(processList, i);
            if (!processPtr.equals(MemorySegment.NULL)) {
                processes.add(new Process(processPtr));
            }
        }

        return processes;
    }

    /**
     * Enumerate applications running on this device
     * @param identifier Optional identifier to filter by (null for all)
     * @param scope Scope for enumeration
     * @return List of Application objects
     */
    public List<Application> enumerateApplications(String identifier, Scope scope) {
        try (Arena arena = Arena.ofConfined()) {
            // Create query options
            MemorySegment queryOpts = (MemorySegment) FRIDA_APPLICATION_QUERY_OPTIONS_NEW.invoke();

            // Set scope
            FRIDA_APPLICATION_QUERY_OPTIONS_SET_SCOPE.invoke(queryOpts, scope.getValue());

            // Set identifier if provided
            if (identifier != null && !identifier.isEmpty()) {
                byte[] identifierBytes = identifier.getBytes(StandardCharsets.UTF_8);
                MemorySegment identifierPtr = arena.allocate(identifierBytes.length + 1); // +1 for null terminator
                identifierPtr.copyFrom(MemorySegment.ofArray(identifierBytes));
                identifierPtr.set(ValueLayout.JAVA_BYTE, identifierBytes.length, (byte) 0); // null terminator
                FRIDA_APPLICATION_QUERY_OPTIONS_SELECT_IDENTIFIER.invoke(queryOpts, identifierPtr);
            }

            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Enumerate applications
            MemorySegment appList = (MemorySegment) FRIDA_DEVICE_ENUMERATE_APPLICATIONS
                    .invoke(devicePtr, queryOpts, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                FridaJava.fridaUnref(queryOpts);
                throw new RuntimeException("Failed to enumerate applications");
            }

            if (appList.equals(MemorySegment.NULL)) {
                FridaJava.fridaUnref(queryOpts);
                return new ArrayList<>();
            }

            try {
                List<Application> applications = extractApplicationsFromList(appList);
                // Sort by PID descending, mimicking Go Bindings
                applications.sort((a, b) -> Integer.compare(b.getPid(), a.getPid()));
                return applications;
            } finally {
                // Clean up native resources
                FridaJava.fridaUnref(queryOpts);
                FridaJava.fridaUnref(appList);
            }

        } catch (Throwable e) {
            System.err.println("Failed to enumerate applications: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Extract Application objects from the native application list
     */
    private List<Application> extractApplicationsFromList(MemorySegment appList) throws Throwable {
        int appCount = (int) FRIDA_APPLICATION_LIST_SIZE.invoke(appList);
        List<Application> applications = new ArrayList<>(appCount);

        for (int i = 0; i < appCount; i++) {
            MemorySegment appPtr = (MemorySegment) FRIDA_APPLICATION_LIST_GET.invoke(appList, i);
            if (!appPtr.equals(MemorySegment.NULL)) {
                applications.add(new Application(appPtr));
            }
        }

        return applications;
    }

    /**
     * Enumerate all applications on this device
     * @return List of Application objects
     */
    public List<Application> enumerateApplications() {
        return enumerateApplications(null, Scope.MINIMAL);
    }

    /**
     * Spawn a new process
     * @param program Path to the executable to spawn
     * @return PID of the spawned process
     */
    public int spawn(String program) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment programPtr = arena.allocateFrom(program);

            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Spawn the process (program, options=NULL, cancellable=NULL, error)
            int pid = (int) FRIDA_DEVICE_SPAWN_SYNC.invoke(devicePtr, programPtr, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                throw new RuntimeException("Failed to spawn process: " + program);
            }

            return pid;
        } catch (Throwable e) {
            throw new RuntimeException("Failed to spawn process: " + program, e);
        }
    }

    /**
     * Spawn a new process with arguments
     * @param program Path to the executable to spawn
     * @param args Arguments to pass to the process
     * @return PID of the spawned process
     */
    public int spawn(String program, List<String> args) {
        try (SpawnOptions options = new SpawnOptions();
             Arena arena = Arena.ofConfined()) {

            // Prepend program name to arguments
            String[] fullArgs = new String[args.size() + 1];
            fullArgs[0] = program;
            String[] argsArray = args.toArray(new String[0]);
            System.arraycopy(argsArray, 0, fullArgs, 1, args.size());

            options.setArgv(fullArgs);

            MemorySegment programPtr = arena.allocateFrom(program);

            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Spawn the process with options
            int pid = (int) FRIDA_DEVICE_SPAWN_SYNC.invoke(devicePtr, programPtr, options.getPointer(), MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                throw new RuntimeException("Failed to spawn process: " + program);
            }

            return pid;
        } catch (Throwable e) {
            throw new RuntimeException("Failed to spawn process: " + program, e);
        }
    }

    /**
     * Kill a process
     * @param pid PID of the process to kill
     */
    public void kill(int pid) {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Kill the process (device, pid, cancellable=NULL, error)
            FRIDA_DEVICE_KILL_SYNC.invoke(devicePtr, pid, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                throw new RuntimeException("Failed to kill process with PID: " + pid);
            }
        } catch (Throwable e) {
            throw new RuntimeException("Failed to kill process with PID: " + pid, e);
        }
    }

    /**
     * Resume a suspended process
     * @param pid PID of the process to resume
     */
    public void resume(int pid) {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Resume the process (device, pid, cancellable=NULL, error)
            FRIDA_DEVICE_RESUME_SYNC.invoke(devicePtr, pid, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                throw new RuntimeException("Failed to resume process with PID: " + pid);
            }
        } catch (Throwable e) {
            throw new RuntimeException("Failed to resume process with PID: " + pid, e);
        }
    }

    /**
     * Attach to a running process
     * @param pid PID of the process to attach to
     * @return Session object representing the attached session
     */
    public Session attach(int pid) {
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Attach to the process (device, pid, options=NULL, cancellable=NULL, error)
            MemorySegment sessionPtr = (MemorySegment) FRIDA_DEVICE_ATTACH_SYNC.invoke(
                    devicePtr, pid, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                throw new RuntimeException("Failed to attach to process with PID: " + pid);
            }

            return new Session(sessionPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to attach to process with PID: " + pid, e);
        }
    }

    public void clean() {
        try {
            FridaJava.fridaUnref(devicePtr);
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
