package nl.axelkoolhaas.examples;

import nl.axelkoolhaas.*;

/**
 * Basic example demonstrating Frida Java bindings usage.
 * This example shows initialization, version information, and device enumeration.
 */
public class BasicExample {

    public static void main(String[] args) {
        System.out.println("Frida Java Bindings - Basic Example");
        System.out.println("===================================");

        try {
            // Initialize Frida
            Frida.init();
            System.out.println("Frida initialized");

            // Get version information
            String versionString = Frida.getVersionString();
            int[] version = Frida.getVersion();
            System.out.println("Frida version: " + versionString);
            System.out.printf("Version components: %d.%d.%d.%d%n",
                version[0], version[1], version[2], version[3]);

            // Use try-with-resources for proper cleanup
            try (DeviceManager deviceManager = new DeviceManager()) {
                System.out.println("Device manager created");

                // Enumerate devices
                System.out.println("\n--- Device Enumeration ---");
                Device[] devices = deviceManager.enumerateDevices();
                System.out.println("Found " + devices.length + " device(s):");

                for (Device device : devices) {
                    System.out.printf("  - %s (Type: %s, ID: %s)%n",
                        device.getName(), device.getType(), device.getId());
                }

                // Get local device
                Device localDevice = deviceManager.getLocalDevice();
                System.out.println("\nLocal device: " + localDevice.getName());

                // Enumerate processes
                System.out.println("\n--- Process Enumeration ---");
                ProcessInfo[] processes = localDevice.enumerateProcesses();
                System.out.println("Found " + processes.length + " running processes");

                // Show first 5 processes as example
                System.out.println("Sample processes:");
                for (int i = 0; i < Math.min(5, processes.length); i++) {
                    ProcessInfo process = processes[i];
                    System.out.printf("  PID %d: %s%n", process.getPid(), process.getName());
                }

                System.out.println("Device manager closed");
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            Frida.deinit();
            System.out.println("Frida deinitialized");
        }
    }
}
