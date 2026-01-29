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

import nl.axelkoolhaas.frida_java.frida.*;
import nl.axelkoolhaas.frida_java.frida.Process;

import java.nio.file.*;
import java.util.List;

/**
 * Basic example demonstrating Frida Java bindings usage.
 * This example shows version information, device enumeration, and process listing.
 */
public class BasicExample {
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

    public static void main(String[] args) {
        System.out.println("Frida Java Bindings - Basic Example");
        System.out.println("===================================");

        try {
            String version = Frida.getVersion();
            System.out.println("Frida version: " + version);

            // Use try-with-resources for proper cleanup
            try (DeviceManager deviceManager = new DeviceManager()) {
                System.out.println("Device manager created");

                System.out.println("\n--- Device Enumeration ---");
                List<Device> devices = deviceManager.enumerateDevices();
                System.out.println("Found " + devices.size() + " device(s):");

                for (Device device : devices) {
                    System.out.printf("  - %s (Type: %s, ID: %s)%n",
                        device.getName(), device.getType(), device.getId());
                }

                Device localDevice = deviceManager.getLocalDevice();
                if (localDevice != null) {
                    System.out.println("\nLocal device: " + localDevice.getName());

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
                    System.out.println("Spawning 'bash --help' process...");

                    // Spawn bash with --help argument
                    List<String> bashArgs = List.of("--help");
                    int spawnedPid = localDevice.spawn(findBinary("bash"), bashArgs);
                    System.out.println("Spawned process with PID: " + spawnedPid);

                    // Attach to the spawned process
                    try (Session session = localDevice.attach(spawnedPid)) {
                        System.out.println("Attached to process");

                        // Create a simple script to get the process arguments
                        // language=JavaScript
                        String scriptSource = """
                            (function () {
                                function sendInfo(obj) {
                                    send({ type: "info", data: obj })
                                }

                                const mainModule = Process.enumerateModules()[0]

                                sendInfo({
                                    name: mainModule.name,
                                    path: mainModule.path,
                                    base: mainModule.base.toString(),
                                    size: mainModule.size
                                })
                            })();
                            """;

                        // Create and load the script
                        try (Script script = session.createScript(scriptSource)) {
                            // Set up message handler to receive messages from the script
                            script.on("message", (Closure.MessageCallback) (message, data) -> {
                                System.out.println("Message from script: " + message);

                                // Try to parse the message for binary info
                                if (message.contains("\"type\":\"info\"")) {
                                    System.out.println("Binary info from agent:");
                                    // For demonstration, just print the raw message
                                    // In a real implementation, you'd parse the JSON properly
                                }
                            });

                            script.load();
                            System.out.println("Script loaded successfully");

                            // Resume the spawned process
                            localDevice.resume(spawnedPid);
                            System.out.println("Resumed spawned process");

                            // Give the script some time to execute and send info
                            System.out.println("Waiting for script to send binary info...");
                            Thread.sleep(1000);  // Wait 1 second for the script to execute

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
