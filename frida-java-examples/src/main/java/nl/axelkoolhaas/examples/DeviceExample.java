package nl.axelkoolhaas.examples;

import nl.axelkoolhaas.*;

/**
 * Advanced example demonstrating Frida Device bindings usage.
 * This example shows device enumeration, process listing, and basic script injection.
 */
public class DeviceExample {

    public static void main(String[] args) {
        System.out.println("Frida Java Device Bindings - Advanced Example");
        System.out.println("==============================================");

        DeviceManager deviceManager = null;

        try {
            // Initialize Frida
            Frida.init();
            System.out.println("✓ Frida initialized");

            // Create device manager
            deviceManager = new DeviceManager();
            System.out.println("✓ Device manager created");

            // Enumerate devices
            System.out.println("\n--- Enumerating Devices ---");
            Device[] devices = deviceManager.enumerateDevices();
            System.out.println("Found " + devices.length + " device(s):");

            for (Device device : devices) {
                System.out.printf("  - %s (Type: %s, ID: %s)%n",
                    device.getName(), device.getType(), device.getId());
            }

            // Get local device
            System.out.println("\n--- Working with Local Device ---");
            Device localDevice = deviceManager.getLocalDevice();
            System.out.println("Local device: " + localDevice.getName());

            // Enumerate processes
            System.out.println("\n--- Enumerating Processes ---");
            ProcessInfo[] processes = localDevice.enumerateProcesses();
            System.out.println("Found " + processes.length + " running processes");

            // Show some interesting processes
            System.out.println("Sample processes:");
            int count = 0;
            for (ProcessInfo process : processes) {
                String name = process.getName();
                // Show some common system processes or user applications
                if (name.contains("java") || name.contains("python") ||
                    name.contains("node") || name.contains("Terminal") ||
                    name.contains("finder") || name.contains("safari") ||
                    count < 3) {
                    System.out.printf("  PID %d: %s%n", process.getPid(), name);
                    count++;
                }
                if (count >= 10) break; // Limit output
            }

            // Example: Try to attach to a process (safely)
            if (args.length > 0) {
                try {
                    int targetPid = Integer.parseInt(args[0]);
                    System.out.println("\n--- Attaching to Process ---");
                    System.out.println("Attempting to attach to PID: " + targetPid);

                    Session session = localDevice.attach(targetPid);
                    System.out.println("✓ Successfully attached to process " + session.getPid());

                    // Create a simple script
                    String scriptSource =
                        "console.log('Hello from Frida!');\n" +
                        "console.log('Process PID: ' + Process.id);\n" +
                        "console.log('Process arch: ' + Process.arch);\n" +
                        "console.log('Process platform: ' + Process.platform);";

                    Script script = session.createScript(scriptSource);
                    System.out.println("✓ Script created");

                    script.load();
                    System.out.println("✓ Script loaded and executed");

                    // Give script some time to run
                    Thread.sleep(1000);

                    // Cleanup
                    script.unload();
                    System.out.println("✓ Script unloaded");

                    session.detach();
                    System.out.println("✓ Detached from process");

                } catch (NumberFormatException e) {
                    System.err.println("Invalid PID: " + args[0]);
                } catch (Exception e) {
                    System.err.println("Failed to attach to process: " + e.getMessage());
                }
            } else {
                System.out.println("\nTo attach to a specific process, run:");
                System.out.println("java -cp <classpath> " + DeviceExample.class.getName() + " <pid>");
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Clean up
            if (deviceManager != null) {
                try {
                    deviceManager.close();
                    System.out.println("✓ Device manager closed");
                } catch (Exception e) {
                    System.err.println("Error closing device manager: " + e.getMessage());
                }
            }
            Frida.deinit();
            System.out.println("✓ Frida deinitialized");
        }
    }
}
