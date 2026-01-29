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

package nl.axelkoolhaas.examples;

import nl.axelkoolhaas.frida_java.frida.Device;
import nl.axelkoolhaas.frida_java.frida.DeviceManager;
import nl.axelkoolhaas.frida_java.frida.Frida;
import nl.axelkoolhaas.frida_java.frida.Process;
import nl.axelkoolhaas.frida_java.frida.Session;
import nl.axelkoolhaas.frida_java.frida.Script;
import nl.axelkoolhaas.frida_java.frida.Closure;

import java.util.List;

/**
 * Basic example demonstrating Frida Java bindings usage.
 * This example shows version information, device enumeration, and process listing.
 */
public class BasicExample {

    public static void main(String[] args) {
        System.out.println("Frida Java Bindings - Basic Example");
        System.out.println("===================================");

        try {
            // Frida is automatically initialized when the class is loaded in v2
            System.out.println("Frida initialized automatically");

            // Get version information
            String version = Frida.getVersion();
            System.out.println("Frida version: " + version);

            // Use try-with-resources for proper cleanup
            try (DeviceManager deviceManager = new DeviceManager()) {
                System.out.println("Device manager created");

                // Enumerate devices
                System.out.println("\n--- Device Enumeration ---");
                List<Device> devices = deviceManager.enumerateDevices();
                System.out.println("Found " + devices.size() + " device(s):");

                for (Device device : devices) {
                    System.out.printf("  - %s (Type: %s, ID: %s)%n",
                        device.getName(), device.getType(), device.getId());
                }

                // Get local device
                Device localDevice = deviceManager.getLocalDevice();
                if (localDevice != null) {
                    System.out.println("\nLocal device: " + localDevice.getName());

                    // Enumerate processes
                    System.out.println("\n--- Process Enumeration ---");
                    List<Process> processes = localDevice.enumerateProcesses();
                    System.out.println("Found " + processes.size() + " running processes");

                    // Show first 5 processes as example
                    System.out.println("Sample processes:");
                    int limit = Math.min(5, processes.size());
                    for (int i = 0; i < limit; i++) {
                        Process process = processes.get(i);
                        System.out.printf("  PID %d: %s%n", process.getPid(), process.getName());
                    }

                    // Demonstrate process spawning and script injection
                    System.out.println("\n--- Process Spawning and Script Injection ---");
                    System.out.println("Spawning 'sleep 300' process...");

                    // Spawn a simple process that we can inject into
                    List<String> sleepArgs = List.of("300");  // Sleep for 300 seconds
                    int spawnedPid = localDevice.spawn("sleep", sleepArgs);
                    System.out.println("Spawned process with PID: " + spawnedPid);

                    // Attach to the spawned process
                    try (Session session = localDevice.attach(spawnedPid)) {
                        System.out.println("Attached to process");

                        // Create a simple script to get the process arguments
                        // language=JavaScript
                        String scriptSource = """
                            const libcStartMain = Module.findGlobalExportByName("__libc_start_main")
                            
                            if (!libcStartMain) {
                                console.log("__libc_start_main not found")
                                send({ error: "__libc_start_main not found" })
                            } else {
                                Interceptor.attach(libcStartMain, {
                                    onEnter(args) {
                                        const mainFunc = args[0]
                            
                                        Interceptor.attach(mainFunc, {
                                            onEnter(args) {
                                                const argc = args[0].toInt32()
                                                const argv = args[1]
                            
                                                const argList = []
                            
                                                for (let i = 0; i < argc; i++) {
                                                    const argPtr = argv.add(i * Process.pointerSize).readPointer()
                                                    const argStr = argPtr.readCString()
                                                    argList.push(argStr)
                                                }
                            
                                                console.log("argc =", argc)
                                                console.log("argv =", argList)
                            
                                                send({
                                                    type: "argv",
                                                    argc: argc,
                                                    argv: argList
                                                })
                                            }
                                        })
                                    }
                                })
                            }
                            """;

                        // Create and load the script
                        try (Script script = session.createScript(scriptSource)) {
                            // Set up message handler to receive messages from the script
                            script.on("message", (Closure.MessageCallback) (message, data) ->
                                System.out.println("Message from script: " + message)
                            );

                            script.load();
                            System.out.println("Script loaded successfully");

                            // Resume the spawned process
                            localDevice.resume(spawnedPid);
                            System.out.println("Resumed spawned process");

                            // Give the script some time to intercept and capture arguments
                            System.out.println("Waiting for script to capture arguments...");
                            Thread.sleep(2000);  // Wait 2 seconds for the interception to happen

                            // Clean up - kill the spawned process
                            System.out.println("Cleaning up spawned process...");
                            localDevice.kill(spawnedPid);
                            System.out.println("Process terminated");

                        } catch (Exception scriptEx) {
                            System.err.println("Script error: " + scriptEx.getMessage());
                            // Make sure to clean up the process
                            try {
                                localDevice.kill(spawnedPid);
                            } catch (Exception killEx) {
                                System.err.println("Failed to kill process: " + killEx.getMessage());
                            }
                        }
                    } catch (Exception sessionEx) {
                        System.err.println("Session error: " + sessionEx.getMessage());
                        // Make sure to clean up the process
                        try {
                            localDevice.kill(spawnedPid);
                        } catch (Exception killEx) {
                            System.err.println("Failed to kill process: " + killEx.getMessage());
                        }
                    }
                } else {
                    System.out.println("No local device found");
                }

                // Clean up devices
                for (Device device : devices) {
                    device.close();
                }

                System.out.println("Device manager will be closed automatically");
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            if (e.getCause() != null) {
                System.err.println("Caused by: " + e.getCause().getMessage());
            }
        }

        System.out.println("Example completed");
    }
}
