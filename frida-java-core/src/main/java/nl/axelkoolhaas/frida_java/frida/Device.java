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
import nl.axelkoolhaas.frida_java.model.Icon;
import nl.axelkoolhaas.frida_java.util.GHashTableUtil;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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

    private static final MethodHandle FRIDA_DEVICE_GET_BUS;
    private static final MethodHandle FRIDA_DEVICE_GET_ICON;
    private static final MethodHandle FRIDA_DEVICE_QUERY_SYSTEM_PARAMETERS_SYNC;
    private static final MethodHandle FRIDA_FRONTMOST_QUERY_OPTIONS_NEW;
    private static final MethodHandle FRIDA_FRONTMOST_QUERY_OPTIONS_SET_SCOPE;
    private static final MethodHandle FRIDA_DEVICE_GET_FRONTMOST_APPLICATION_SYNC;

    static {
        Frida.ensureInitialized();

        FRIDA_DEVICE_GET_DTYPE = FridaLibraryLoader.findFunction("frida_device_get_dtype",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_DEVICE_GET_ID = FridaLibraryLoader.findFunction("frida_device_get_id",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_GET_NAME = FridaLibraryLoader.findFunction("frida_device_get_name",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_IS_LOST = FridaLibraryLoader.findFunction("frida_device_is_lost",
                FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
        FRIDA_DEVICE_ENUMERATE_PROCESSES = FridaLibraryLoader.findFunction("frida_device_enumerate_processes_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_PROCESS_LIST_SIZE = FridaLibraryLoader.findFunction("frida_process_list_size",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_PROCESS_LIST_GET = FridaLibraryLoader.findFunction("frida_process_list_get",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        // Spawn, kill, and resume method handles
        FRIDA_DEVICE_SPAWN_SYNC = FridaLibraryLoader.findFunction("frida_device_spawn_sync",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_KILL_SYNC = FridaLibraryLoader.findFunction("frida_device_kill_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_RESUME_SYNC = FridaLibraryLoader.findFunction("frida_device_resume_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_ATTACH_SYNC = FridaLibraryLoader.findFunction("frida_device_attach_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        FRIDA_APPLICATION_QUERY_OPTIONS_NEW = FridaLibraryLoader.findFunction("frida_application_query_options_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_APPLICATION_QUERY_OPTIONS_SET_SCOPE = FridaLibraryLoader.findFunction("frida_application_query_options_set_scope",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_APPLICATION_QUERY_OPTIONS_SELECT_IDENTIFIER = FridaLibraryLoader.findFunction("frida_application_query_options_select_identifier",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_ENUMERATE_APPLICATIONS = FridaLibraryLoader.findFunction("frida_device_enumerate_applications_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_APPLICATION_LIST_SIZE = FridaLibraryLoader.findFunction("frida_application_list_size",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_APPLICATION_LIST_GET = FridaLibraryLoader.findFunction("frida_application_list_get",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        FRIDA_DEVICE_GET_BUS = FridaLibraryLoader.findFunction("frida_device_get_bus",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_GET_ICON = FridaLibraryLoader.findFunction("frida_device_get_icon",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_QUERY_SYSTEM_PARAMETERS_SYNC = FridaLibraryLoader.findFunction("frida_device_query_system_parameters_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_FRONTMOST_QUERY_OPTIONS_NEW = FridaLibraryLoader.findFunction("frida_frontmost_query_options_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_FRONTMOST_QUERY_OPTIONS_SET_SCOPE = FridaLibraryLoader.findFunction("frida_frontmost_query_options_set_scope",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_DEVICE_GET_FRONTMOST_APPLICATION_SYNC = FridaLibraryLoader.findFunction("frida_device_get_frontmost_application_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    public Device(MemorySegment devicePtr) {
        this.devicePtr = FridaNativeUtils.requireValidPointer(devicePtr, "Device pointer");
    }

    /**
     * Get the device ID
     * @return device ID string, or empty string if device is null
     */
    public String getId() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_DEVICE_GET_ID.invoke(devicePtr);
            return FridaNativeUtils.memorySegmentToString(result);
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
            return FridaNativeUtils.memorySegmentToString(result);
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
            GErrorUtils.handleError(error, "enumerate processes");

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

            // Check for errors - need to cleanup queryOpts before throwing
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                FridaNativeUtils.fridaUnref(queryOpts);
                GErrorUtils.handleError(error, "enumerate applications");
            }

            if (appList.equals(MemorySegment.NULL)) {
                FridaNativeUtils.fridaUnref(queryOpts);
                return new ArrayList<>();
            }

            try {
                List<Application> applications = extractApplicationsFromList(appList);
                // Sort by PID descending, mimicking Go Bindings
                applications.sort((a, b) -> Integer.compare(b.getPid(), a.getPid()));
                return applications;
            } finally {
                // Clean up native resources
                FridaNativeUtils.fridaUnref(queryOpts);
                FridaNativeUtils.fridaUnref(appList);
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
     * @param programPath Path to the executable to spawn
     * @return Optional containing PID of the spawned process, or empty if spawn failed
     */
    public Optional<Integer> spawn(String programPath) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment programPtr = arena.allocateFrom(programPath);

            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Spawn the process (program, options=NULL, cancellable=NULL, error)
            int pid = (int) FRIDA_DEVICE_SPAWN_SYNC.invoke(devicePtr, programPtr, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "spawn process: " + programPath);

            return Optional.of(pid);
        } catch (Throwable e) {
            // Log all failures internally but don't re-throw
            System.err.println("Failed to spawn process '" + programPath + "': " + e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Spawn a new process with arguments
     * @param programPath Full path of the executable to spawn
     * @param args Arguments to pass to the process
     * @return Optional containing PID of the spawned process, or empty if spawn failed
     */
    public Optional<Integer> spawn(String programPath, List<String> args) {
        try (SpawnOptions options = new SpawnOptions();
             Arena arena = Arena.ofConfined()) {

            // Prepend program name to arguments
            String[] fullArgs = new String[args.size() + 1];
            fullArgs[0] = programPath;
            String[] argsArray = args.toArray(new String[0]);
            System.arraycopy(argsArray, 0, fullArgs, 1, args.size());

            options.setArgv(fullArgs);

            MemorySegment programPtr = arena.allocateFrom(programPath);

            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            // Spawn the process with options
            int pid = (int) FRIDA_DEVICE_SPAWN_SYNC.invoke(devicePtr, programPtr, options.getPointer(), MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "spawn process: " + programPath);

            return Optional.of(pid);
        } catch (Throwable e) {
            // Log all failures internally but don't re-throw
            System.err.println("Failed to spawn process '" + programPath + "' with args " + args + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Helper method to spawn by program name (searches PATH)
     * @param programName name of the program to spawn
     * @return Optional containing PID of the spawned process, or empty if spawn failed
     */
    public Optional<Integer> spawnName(String programName) {
        String programPath = findBinary(programName);
        if (programPath == null) {
            System.err.println("Executable not found in PATH: " + programName);
            return Optional.empty();
        }
        return spawn(programPath);
    }

    /**
     * Helper method to spawn by program name (searches PATH)
     * @param programName name of the program to spawn
     * @param args Arguments to pass to the process
     * @return Optional containing PID of the spawned process, or empty if spawn failed
     */
    public Optional<Integer> spawnName(String programName, List<String> args) {
        String programPath = findBinary(programName);
        if (programPath == null) {
            System.err.println("Executable not found in PATH: " + programName);
            return Optional.empty();
        }
        return spawn(programPath, args);
    }

    public static String findBinary(String name) {
        String pathEnv = System.getenv("PATH");
        for (String dir : pathEnv.split(":")) {
            Path p = Paths.get(dir, name);
            if (Files.isExecutable(p)) {
                return p.toAbsolutePath().toString();
            }
        }
        return null;
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
            GErrorUtils.handleError(error, "kill process: " + pid);
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
            GErrorUtils.handleError(error, "resume process: " + pid);
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
            GErrorUtils.handleError(error, "attach process: " + pid);

            return new Session(sessionPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to attach to process with PID: " + pid, e);
        }
    }

    /**
     * Get the device icon
     * Returns a GVariant pointer representing the icon data.
     * The icon is typically in a platform-specific format (e.g., PNG data).
     *
     * Note: This is an advanced feature. Most applications don't need the device icon.
     * The returned pointer is a GVariant that needs to be parsed according to GLib semantics.
     *
     * @return Icon object wrapping the native GVariant pointer, or null if not available
     */
    public Icon getIcon() {
        try {
            MemorySegment iconVariant = (MemorySegment) FRIDA_DEVICE_GET_ICON.invoke(devicePtr);
            if (iconVariant.equals(MemorySegment.NULL)) {
                return null;
            }
            // Return the GVariant pointer wrapped in an Icon object
            // Users can access the raw pointer if they need to parse the icon data
            return new Icon(iconVariant);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get device icon", e);
        }
    }

    /**
     * Get the device bus
     * @return Bus object representing the device bus
     */
    public Bus getBus() {
        try {
            MemorySegment bus = (MemorySegment) FRIDA_DEVICE_GET_BUS.invoke(devicePtr);
            if (bus.equals(MemorySegment.NULL)) {
                return null;
            }
            return new Bus(bus);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get device bus", e);
        }
    }

    /**
     * Get system parameters of the device
     * @return Map of system parameters
     */
    public Map<String, Object> getParams() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment hashTable = (MemorySegment) FRIDA_DEVICE_QUERY_SYSTEM_PARAMETERS_SYNC
                    .invoke(devicePtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "get params");

            return GHashTableUtil.toMap(hashTable);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get device parameters", e);
        }
    }

    /**
     * Get the frontmost application
     * @param scope Scope for the query
     * @return Frontmost Application, or null if none
     */
    public Application getFrontmostApplication(Scope scope) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment queryOpts = (MemorySegment) FRIDA_FRONTMOST_QUERY_OPTIONS_NEW.invoke();
            FRIDA_FRONTMOST_QUERY_OPTIONS_SET_SCOPE.invoke(queryOpts, scope.getValue());

            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment appPtr = (MemorySegment) FRIDA_DEVICE_GET_FRONTMOST_APPLICATION_SYNC
                    .invoke(devicePtr, queryOpts, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                FridaNativeUtils.fridaUnref(queryOpts);
                GErrorUtils.handleError(error, "get frontmost application");
                throw new RuntimeException("Failed to get frontmost application");
            }

            FridaNativeUtils.fridaUnref(queryOpts);

            if (appPtr.equals(MemorySegment.NULL)) {
                return null;
            }

            return new Application(appPtr);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get frontmost application", e);
        }
    }

    public void clean() {
        try {
            FridaNativeUtils.fridaUnref(devicePtr);
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
