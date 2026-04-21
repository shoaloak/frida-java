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
import nl.axelkoolhaas.frida_java.util.GBytesUtil;
import nl.axelkoolhaas.frida_java.util.GHashTableUtil;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
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
import java.util.regex.Pattern;

/**
 * Represents a device that Frida connects to
 *
 * <p><b>Note:</b> Some recently added methods have limited test coverage:
 * <ul>
 *   <li>{@link #input(int, byte[])} - Input to spawned process</li>
 *   <li>{@link #injectLibraryFile(int, String, String, String)} - Library file injection</li>
 *   <li>{@link #injectLibraryBlob(int, byte[], String, String)} - Library blob injection</li>
 *   <li>{@link #openChannel(String)} - I/O channel operations</li>
 *   <li>{@link #openService(String)} - Service connection operations</li>
 * </ul>
 * These methods have basic tests verifying API availability, but comprehensive integration tests
 * (especially for Windows platform) are pending. The implementations follow the Frida C API
 * specifications and should work correctly, but edge cases may not be fully validated.
 * </p>
 */
public class Device implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(Device.class);
    private final MemorySegment devicePtr;

    private static final MethodHandle FRIDA_DEVICE_GET_DTYPE;
    private static final MethodHandle FRIDA_DEVICE_GET_ID;
    private static final MethodHandle FRIDA_DEVICE_GET_NAME;
    private static final MethodHandle FRIDA_DEVICE_IS_LOST;
    private static final MethodHandle FRIDA_DEVICE_ENUMERATE_PROCESSES;
    private static final MethodHandle FRIDA_PROCESS_QUERY_OPTIONS_NEW;
    private static final MethodHandle FRIDA_PROCESS_QUERY_OPTIONS_SET_SCOPE;
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

    // Spawn gating
    private static final MethodHandle FRIDA_DEVICE_ENABLE_SPAWN_GATING_SYNC;
    private static final MethodHandle FRIDA_DEVICE_DISABLE_SPAWN_GATING_SYNC;
    private static final MethodHandle FRIDA_DEVICE_ENUMERATE_PENDING_SPAWN_SYNC;
    private static final MethodHandle FRIDA_DEVICE_ENUMERATE_PENDING_CHILDREN_SYNC;
    private static final MethodHandle FRIDA_SPAWN_LIST_SIZE;
    private static final MethodHandle FRIDA_SPAWN_LIST_GET;
    private static final MethodHandle FRIDA_CHILD_LIST_SIZE;
    private static final MethodHandle FRIDA_CHILD_LIST_GET;

    // Input and injection
    private static final MethodHandle FRIDA_DEVICE_INPUT_SYNC;
    private static final MethodHandle FRIDA_DEVICE_INJECT_LIBRARY_FILE_SYNC;
    private static final MethodHandle FRIDA_DEVICE_INJECT_LIBRARY_BLOB_SYNC;

    // Channels and services
    private static final MethodHandle FRIDA_DEVICE_OPEN_CHANNEL_SYNC;
    private static final MethodHandle FRIDA_DEVICE_OPEN_SERVICE_SYNC;

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
        FRIDA_PROCESS_QUERY_OPTIONS_NEW = FridaLibraryLoader.findFunction("frida_process_query_options_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS));
        FRIDA_PROCESS_QUERY_OPTIONS_SET_SCOPE = FridaLibraryLoader.findFunction("frida_process_query_options_set_scope",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
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

        // Spawn gating
        FRIDA_DEVICE_ENABLE_SPAWN_GATING_SYNC = FridaLibraryLoader.findFunction("frida_device_enable_spawn_gating_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_DISABLE_SPAWN_GATING_SYNC = FridaLibraryLoader.findFunction("frida_device_disable_spawn_gating_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_ENUMERATE_PENDING_SPAWN_SYNC = FridaLibraryLoader.findFunction("frida_device_enumerate_pending_spawn_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_ENUMERATE_PENDING_CHILDREN_SYNC = FridaLibraryLoader.findFunction("frida_device_enumerate_pending_children_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_SPAWN_LIST_SIZE = FridaLibraryLoader.findFunction("frida_spawn_list_size",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_SPAWN_LIST_GET = FridaLibraryLoader.findFunction("frida_spawn_list_get",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        FRIDA_CHILD_LIST_SIZE = FridaLibraryLoader.findFunction("frida_child_list_size",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_CHILD_LIST_GET = FridaLibraryLoader.findFunction("frida_child_list_get",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        // Input and injection
        FRIDA_DEVICE_INPUT_SYNC = FridaLibraryLoader.findFunction("frida_device_input_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_INJECT_LIBRARY_FILE_SYNC = FridaLibraryLoader.findFunction("frida_device_inject_library_file_sync",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_INJECT_LIBRARY_BLOB_SYNC = FridaLibraryLoader.findFunction("frida_device_inject_library_blob_sync",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // Channels and services
        FRIDA_DEVICE_OPEN_CHANNEL_SYNC = FridaLibraryLoader.findFunction("frida_device_open_channel_sync",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_DEVICE_OPEN_SERVICE_SYNC = FridaLibraryLoader.findFunction("frida_device_open_service_sync",
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
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get device ID", e);
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
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get device name", e);
        }
    }

    /**
     * Get the device type
     * @return device type
     */
    public DeviceType getType() {
        try {
            int deviceType = (int) FRIDA_DEVICE_GET_DTYPE.invoke(devicePtr);
            return DeviceType.fromValue(deviceType);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get device type", e);
        }
    }

    /**
     * Check if the device is lost
     * @return true if the device is lost, false otherwise
     */
    public boolean isLost() {
        try {
            return (boolean) FRIDA_DEVICE_IS_LOST.invoke(devicePtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to check if device is lost", e);
        }
    }

    /**
     * Enumerate processes running on this device
     * @return List of Process objects
     */
    public List<Process> enumerateProcesses() {
        return enumerateProcesses(Scope.MINIMAL);
    }

    /**
     * Enumerate processes running on this device with specified scope
     * @param scope Scope for process enumeration
     * @return List of Process objects
     */
    public List<Process> enumerateProcesses(Scope scope) {
        try (Arena arena = Arena.ofConfined()) {
            // Create query options
            MemorySegment queryOpts = (MemorySegment) FRIDA_PROCESS_QUERY_OPTIONS_NEW.invoke();
            
            // Set scope
            FRIDA_PROCESS_QUERY_OPTIONS_SET_SCOPE.invoke(queryOpts, scope.getValue());
            
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment processList = (MemorySegment) FRIDA_DEVICE_ENUMERATE_PROCESSES
                    .invoke(devicePtr, queryOpts, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (!error.equals(MemorySegment.NULL)) {
                FridaNativeUtils.fridaUnref(queryOpts);
                GErrorUtils.handleError(error, "enumerate processes");
            }

            if (processList.equals(MemorySegment.NULL)) {
                FridaNativeUtils.fridaUnref(queryOpts);
                return new ArrayList<>();
            }

            try {
                return extractProcessesFromList(processList);
            } finally {
                FridaNativeUtils.fridaUnref(queryOpts);
                FridaNativeUtils.fridaUnref(processList);
            }
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to enumerate processes", e);
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
     * Find a process by PID
     * @param pid Process ID to find
     * @return Optional containing the Process if found, empty otherwise
     */
    public Optional<Process> findProcessByPid(int pid) {
        List<Process> processes = enumerateProcesses();
        return processes.stream()
                .filter(p -> p.getPid() == pid)
                .findFirst();
    }

    /**
     * Find a process by name
     * @param name Process name to find (case-sensitive)
     * @return Optional containing the Process if found, empty otherwise
     */
    public Optional<Process> findProcessByName(String name) {
        List<Process> processes = enumerateProcesses();
        return processes.stream()
                .filter(p -> p.getName().equals(name))
                .findFirst();
    }

    /**
     * Get a process by PID (throws if not found)
     * @param pid Process ID to get
     * @return Process object
     * @throws RuntimeException if process not found
     */
    public Process getProcessByPid(int pid) {
        return findProcessByPid(pid)
                .orElseThrow(() -> new FridaException("Process with PID " + pid + " not found"));
    }

    /**
     * Get a process by name (throws if not found)
     * @param name Process name to get
     * @return Process object
     * @throws RuntimeException if process not found
     */
    public Process getProcessByName(String name) {
        return findProcessByName(name)
                .orElseThrow(() -> new FridaException("Process with name '" + name + "' not found"));
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

        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to enumerate applications", e);
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
     * @return PID of the spawned process
     * @throws FridaException if spawning fails
     */
    public int spawn(String programPath) {
        log.debug("Spawning process: {}", programPath);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment programPtr = arena.allocateFrom(programPath);

            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            log.trace("Native call: frida_device_spawn_sync(program={})", programPath);
            // Spawn the process (program, options=NULL, cancellable=NULL, error)
            int pid = (int) FRIDA_DEVICE_SPAWN_SYNC.invoke(devicePtr, programPtr, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "spawn process: " + programPath);

            log.debug("Successfully spawned process: {} with pid={}", programPath, pid);
            return pid;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to spawn process '{}': {}", programPath, e.getMessage());
            throw new FridaException("Failed to spawn process: " + programPath, e);
        }
    }

    /**
     * Spawn a new process with arguments
     * @param programPath Full path of the executable to spawn
     * @param args Arguments to pass to the process
     * @return PID of the spawned process
     * @throws FridaException if spawning fails
     */
    public int spawn(String programPath, List<String> args) {
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

            return pid;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to spawn process '" + programPath + "' with args " + args, e);
        }
    }

    /**
     * Spawn a new process with spawn options
     * @param programPath Full path of the executable to spawn
     * @param options SpawnOptions containing argv, stdio, cwd, env, etc.
     * @return PID of the spawned process
     * @throws FridaException if spawning fails
     */
    public int spawn(String programPath, SpawnOptions options) {
        log.debug("Spawning process: {} with options", programPath);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment programPtr = arena.allocateFrom(programPath);

            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            log.trace("Native call: frida_device_spawn_sync(program={}, options={})", programPath, options.getPointer());
            // Spawn the process with options
            int pid = (int) FRIDA_DEVICE_SPAWN_SYNC.invoke(devicePtr, programPtr, options.getPointer(), MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "spawn process: " + programPath);

            log.debug("Successfully spawned process: {} with pid={}", programPath, pid);
            return pid;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to spawn process '{}': {}", programPath, e.getMessage());
            throw new FridaException("Failed to spawn process: " + programPath, e);
        }
    }

    /**
     * Helper method to spawn by program name (searches PATH)
     * @param programName name of the program to spawn
     * @return PID of the spawned process
     * @throws FridaException if executable not found or spawning fails
     */
    public int spawnName(String programName) {
        String programPath = findBinary(programName);
        if (programPath == null) {
            throw new FridaException("Executable not found in PATH: " + programName);
        }
        return spawn(programPath);
    }

    /**
     * Helper method to spawn by program name (searches PATH)
     * @param programName name of the program to spawn
     * @param args Arguments to pass to the process
     * @return PID of the spawned process
     * @throws FridaException if executable not found or spawning fails
     */
    public int spawnName(String programName, List<String> args) {
        String programPath = findBinary(programName);
        if (programPath == null) {
            throw new FridaException("Executable not found in PATH: " + programName);
        }
        return spawn(programPath, args);
    }

    /**
     * Helper method to spawn by program name with spawn options (searches PATH)
     * @param programName name of the program to spawn
     * @param options SpawnOptions containing argv, stdio, cwd, env, etc.
     * @return PID of the spawned process
     * @throws FridaException if executable not found or spawning fails
     */
    public int spawnName(String programName, SpawnOptions options) {
        String programPath = findBinary(programName);
        if (programPath == null) {
            throw new FridaException("Executable not found in PATH: " + programName);
        }
        return spawn(programPath, options);
    }

    public static String findBinary(String name) {
        String pathEnv = System.getenv("PATH");
        if (pathEnv == null) {
            return null;
        }
        // Use File.pathSeparator which is ":" on Unix and ";" on Windows
        for (String dir : pathEnv.split(Pattern.quote(File.pathSeparator))) {
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
            GErrorUtils.handleError(error, "kill process");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to kill process with PID: " + pid, e);
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
            GErrorUtils.handleError(error, "resume process");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to resume process with PID: " + pid, e);
        }
    }

    /**
     * Attach to a running process
     * @param pid PID of the process to attach to
     * @return Session object representing the attached session
     */
    public Session attach(int pid) {
        log.debug("Attaching to process pid={}", pid);
        try (Arena arena = Arena.ofConfined()) {
            // Error handling
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            log.trace("Native call: frida_device_attach_sync(pid={})", pid);
            // Attach to the process (device, pid, options=NULL, cancellable=NULL, error)
            MemorySegment sessionPtr = (MemorySegment) FRIDA_DEVICE_ATTACH_SYNC.invoke(
                    devicePtr, pid, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

            // Check for errors
            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "attach to process");

            log.debug("Successfully attached to pid={}", pid);
            return new Session(sessionPtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.debug("Failed to attach to pid={}: {}", pid, e.getMessage());
            throw new FridaException("Failed to attach to process with PID: " + pid, e);
        }
    }

    /**
     * Enable spawn gating.
     * When enabled, spawned processes will be suspended until resume() is called.
     * This allows you to instrument processes from the very beginning.
     */
    public void enableSpawnGating() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            FRIDA_DEVICE_ENABLE_SPAWN_GATING_SYNC.invoke(devicePtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "enable spawn gating");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to enable spawn gating", e);
        }
    }

    /**
     * Disable spawn gating.
     */
    public void disableSpawnGating() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            FRIDA_DEVICE_DISABLE_SPAWN_GATING_SYNC.invoke(devicePtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "disable spawn gating");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to disable spawn gating", e);
        }
    }

    /**
     * Enumerate pending spawns (processes waiting due to spawn gating).
     * @return List of Spawn objects representing pending spawns
     */
    public List<Spawn> enumeratePendingSpawn() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment spawnList = (MemorySegment) FRIDA_DEVICE_ENUMERATE_PENDING_SPAWN_SYNC
                    .invoke(devicePtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "enumerate pending spawn");

            if (spawnList.equals(MemorySegment.NULL)) {
                return new ArrayList<>();
            }

            int spawnCount = (int) FRIDA_SPAWN_LIST_SIZE.invoke(spawnList);
            List<Spawn> spawns = new ArrayList<>(spawnCount);

            for (int i = 0; i < spawnCount; i++) {
                MemorySegment spawnPtr = (MemorySegment) FRIDA_SPAWN_LIST_GET.invoke(spawnList, i);
                if (!spawnPtr.equals(MemorySegment.NULL)) {
                    spawns.add(new Spawn(spawnPtr));
                }
            }

            FridaNativeUtils.fridaUnref(spawnList);
            return spawns;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to enumerate pending spawn", e);
        }
    }

    /**
     * Enumerate pending children (child processes waiting due to spawn gating).
     * @return List of Child objects representing pending children
     */
    public List<Child> enumeratePendingChildren() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment childList = (MemorySegment) FRIDA_DEVICE_ENUMERATE_PENDING_CHILDREN_SYNC
                    .invoke(devicePtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "enumerate pending children");

            if (childList.equals(MemorySegment.NULL)) {
                return new ArrayList<>();
            }

            int childCount = (int) FRIDA_CHILD_LIST_SIZE.invoke(childList);
            List<Child> children = new ArrayList<>(childCount);

            for (int i = 0; i < childCount; i++) {
                MemorySegment childPtr = (MemorySegment) FRIDA_CHILD_LIST_GET.invoke(childList, i);
                if (!childPtr.equals(MemorySegment.NULL)) {
                    children.add(new Child(childPtr));
                }
            }

            FridaNativeUtils.fridaUnref(childList);
            return children;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to enumerate pending children", e);
        }
    }

    /**
     * Send input data to a spawned process (typically stdin).
     * @param pid Process ID
     * @param data Input data to send
     */
    public void input(int pid, byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment gBytesData = GBytesUtil.fromByteArray(data, arena);

            FRIDA_DEVICE_INPUT_SYNC.invoke(devicePtr, pid, gBytesData, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "send input to process");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to send input to process with PID: " + pid, e);
        }
    }

    /**
     * Inject a library file into a running process.
     * @param pid Target process ID
     * @param path Path to the library file
     * @param entrypoint Entrypoint function name (or null)
     * @param data Optional data to pass to entrypoint (or null)
     * @return Injection ID
     */
    public int injectLibraryFile(int pid, String path, String entrypoint, String data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment pathPtr = arena.allocateFrom(path);
            MemorySegment entrypointPtr = entrypoint != null ? arena.allocateFrom(entrypoint) : MemorySegment.NULL;
            MemorySegment dataPtr = data != null ? arena.allocateFrom(data) : MemorySegment.NULL;

            int injectionId = (int) FRIDA_DEVICE_INJECT_LIBRARY_FILE_SYNC.invoke(
                    devicePtr, pid, pathPtr, entrypointPtr, dataPtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "inject library file");

            return injectionId;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to inject library file into process with PID: " + pid, e);
        }
    }

    /**
     * Inject a library blob (in-memory bytes) into a running process.
     * @param pid Target process ID
     * @param blob Library bytes
     * @param entrypoint Entrypoint function name (or null)
     * @param data Optional data to pass to entrypoint (or null)
     * @return Injection ID
     */
    public int injectLibraryBlob(int pid, byte[] blob, String entrypoint, String data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment gBytesBlob = GBytesUtil.fromByteArray(blob, arena);
            MemorySegment entrypointPtr = entrypoint != null ? arena.allocateFrom(entrypoint) : MemorySegment.NULL;
            MemorySegment dataPtr = data != null ? arena.allocateFrom(data) : MemorySegment.NULL;

            int injectionId = (int) FRIDA_DEVICE_INJECT_LIBRARY_BLOB_SYNC.invoke(
                    devicePtr, pid, gBytesBlob, entrypointPtr, dataPtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "inject library blob");

            return injectionId;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to inject library blob into process with PID: " + pid, e);
        }
    }

    /**
     * Open an I/O channel to communicate with the device.
     * @param address Channel address (e.g., "tcp:host=127.0.0.1,port=27042")
     * @return IOStream pointer (requires further wrapping for I/O operations)
     */
    public MemorySegment openChannel(String address) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment addressPtr = arena.allocateFrom(address);

            MemorySegment ioStream = (MemorySegment) FRIDA_DEVICE_OPEN_CHANNEL_SYNC.invoke(
                    devicePtr, addressPtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "open channel");

            return ioStream;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to open channel: " + address, e);
        }
    }

    /**
     * Open a service connection to the device.
     * @param address Service address
     * @return Service pointer (requires further wrapping for service operations)
     */
    public MemorySegment openService(String address) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            MemorySegment addressPtr = arena.allocateFrom(address);

            MemorySegment service = (MemorySegment) FRIDA_DEVICE_OPEN_SERVICE_SYNC.invoke(
                    devicePtr, addressPtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "open service");

            return service;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to open service: " + address, e);
        }
    }

    /**
     * Get the device icon
     * Returns a GVariant pointer representing the icon data.
     * The icon is typically in a platform-specific format (e.g., PNG data).
     * <br>
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
            return new Icon(iconVariant);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get device icon", e);
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
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get device bus", e);
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
            GErrorUtils.handleError(error, "query system parameters");

            return GHashTableUtil.toMap(hashTable);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get device parameters", e);
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
            GErrorUtils.handleError(error, "get frontmost application");

            FridaNativeUtils.fridaUnref(queryOpts);

            if (appPtr.equals(MemorySegment.NULL)) {
                return null;
            }

            return new Application(appPtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to get frontmost application", e);
        }
    }

    public void clean() {
        try {
            FridaNativeUtils.fridaUnref(devicePtr);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            throw new FridaException("Failed to cleanup Device", e);
        }
    }

    /**
     * Register an event handler for device signals.
     *
     * @param signal DeviceSignal to listen for
     * @param callback Callback function for the signal
     * @throws IllegalArgumentException if callback type does not match signal contract
     * @throws FridaException on registration failure
     */
    public void on(DeviceSignal signal, Object callback) {
        if (callback == null) {
            throw new IllegalArgumentException("Callback cannot be null");
        }

        // TODO: do we need this check?
        // Validate callback type against the SignalCallbacks contract
        switch (signal) {
            case OUTPUT -> {
                if (!(callback instanceof SignalCallbacks.DeviceOutputCallback)) {
                    throw new IllegalArgumentException("Signal 'output' requires a SignalCallbacks.DeviceOutputCallback");
                }
            }
            case SPAWN_ADDED, SPAWN_REMOVED -> {
                if (!(callback instanceof SignalCallbacks.SpawnCallback)) {
                    throw new IllegalArgumentException("Signal '" + signal.getName() + "' requires a SignalCallbacks.SpawnCallback");
                }
            }
            case CHILD_ADDED, CHILD_REMOVED -> {
                if (!(callback instanceof SignalCallbacks.ChildCallback)) {
                    throw new IllegalArgumentException("Signal '" + signal.getName() + "' requires a SignalCallbacks.ChildCallback");
                }
            }
            case PROCESS_ADDED, PROCESS_REMOVED -> {
                if (!(callback instanceof SignalCallbacks.ProcessCallback)) {
                    throw new IllegalArgumentException("Signal '" + signal.getName() + "' requires a SignalCallbacks.ProcessCallback");
                }
            }
            case PROCESS_CRASHED -> {
                if (!(callback instanceof SignalCallbacks.CrashCallback)) {
                    throw new IllegalArgumentException("Signal 'crashed' requires a SignalCallbacks.CrashCallback");
                }
            }
            case UNINJECTED -> {
                if (!(callback instanceof SignalCallbacks.UninjectedCallback)) {
                    throw new IllegalArgumentException("Signal 'uninjected' requires a SignalCallbacks.UninjectedCallback");
                }
            }
            case LOST -> {
                if (!(callback instanceof SignalCallbacks.VoidCallback || callback instanceof Runnable)) {
                    throw new IllegalArgumentException("Signal 'lost' requires a SignalCallbacks.VoidCallback or Runnable");
                }
            }
            default -> throw new IllegalArgumentException("Unknown signal: " + signal);
        }

        log.debug("Registering event handler for device signal: {}", signal.getName());

        try {
            long handlerId = Closure.connectClosure(devicePtr, signal.getName(), callback);

            if (handlerId > 0) {
                log.debug("Successfully registered handler for native signal '{}' with handler ID: {}",
                        signal.getName(), handlerId);
            } else {
                log.warn("Failed to connect signal '{}' - native lookup failed", signal.getName());
            }
        } catch (Exception e) {
            log.debug("Failed to register event handler for signal '{}': {}", signal.getName(), e.getMessage());
            throw new FridaException("Failed to register event handler for signal: " + signal.getName(), e);
        }
    }

    @Override
    public void close() {
        clean();
    }
}
