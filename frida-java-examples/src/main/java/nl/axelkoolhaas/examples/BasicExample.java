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
            e.printStackTrace();
        }

        System.out.println("Example completed");
    }
}
