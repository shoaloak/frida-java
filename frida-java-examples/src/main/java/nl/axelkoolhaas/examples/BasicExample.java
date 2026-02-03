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

                @SuppressWarnings("resource")
                Device localDevice = deviceManager.getLocalDevice()
                        .orElseThrow(() -> new RuntimeException("No local device found"));

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
                int spawnedPid = localDevice.spawnName("bash", bashArgs);
                System.out.println("Spawned process with PID: " + spawnedPid);

                try {
                    // Attach to the spawned process
                    try (Session session = localDevice.attach(spawnedPid);
                         Script script = session.createScript("""
                             (function () {
                                 const mainModule = Process.enumerateModules()[0]
                                 console.log({
                                     name: mainModule.name,
                                     path: mainModule.path,
                                     base: mainModule.base.toString(),
                                     size: mainModule.size
                                 })
                             })();
                             """)) {

                        System.out.println("Attached to process");
                        System.out.println("Loading script...");

                        script.load();
                        System.out.println("Script loaded successfully");

                        // Resume the spawned process
                        localDevice.resume(spawnedPid);
                        System.out.println("Resumed spawned process");

                        // Give the script some time to execute
                        System.out.println("Waiting for script to execute...");
                        Thread.sleep(1000);
                    }
                } finally {
                    // Always clean up the spawned process
                    try {
                        System.out.println("Cleaning up spawned process...");
                        localDevice.kill(spawnedPid);
                        System.out.println("Process terminated");
                    } catch (Exception killEx) {
                        System.err.println("Failed to kill process: " + killEx.getMessage());
                    }
                }

                System.out.println("\nDevice manager will be closed automatically");
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
