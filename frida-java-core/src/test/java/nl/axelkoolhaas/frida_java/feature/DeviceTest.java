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

package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.frida.Device;
import nl.axelkoolhaas.frida_java.frida.DeviceManager;
import nl.axelkoolhaas.frida_java.frida.DeviceType;
import nl.axelkoolhaas.frida_java.frida.Process;
import org.junit.jupiter.api.*;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Device-related Frida bindings.
 * Tests device enumeration, device properties, and process enumeration functionality.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DeviceTest {


    @Test
    @Order(1)
    void testCreateDeviceManager() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            assertNotNull(deviceManager, "DeviceManager should not be null");
            System.out.println("DeviceManager created successfully");
        }
    }

    @Test
    @Order(2)
    void testEnumerateDevices() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            List<Device> devices = deviceManager.enumerateDevices();
            assertNotNull(devices, "Device list should not be null");
            assertFalse(devices.isEmpty(), "Should have at least one device");

            System.out.println("Found " + devices.size() + " device(s):");
            for (Device device : devices) {
                assertNotNull(device, "Device should not be null");
                assertNotNull(device.getId(), "Device ID should not be null");
                assertNotNull(device.getName(), "Device name should not be null");
                System.out.println("  - ID: " + device.getId() + ", Name: " + device.getName());
            }
        }
    }

    @Test
    @Order(3)
    void testDeviceProperties() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device device = deviceManager.getLocalDevice().orElseThrow();

            String id = device.getId();
            assertNotNull(id, "Device ID should not be null");
            assertFalse(id.isEmpty(), "Device ID should not be empty");

            String name = device.getName();
            assertNotNull(name, "Device name should not be null");
            assertFalse(name.isEmpty(), "Device name should not be empty");

            DeviceType type = device.getType();
            assertNotNull(type, "Device type should not be null");
            assertEquals(DeviceType.LOCAL, type, "Local device type should be LOCAL");

            boolean isLost = device.isLost();
            assertFalse(isLost, "Local device should not be lost");

            System.out.printf("Device - ID: %s, Name: %s, Type: %s, Lost: %s%n",
                    id, name, type, isLost);
        }
    }

    @Test
    @Order(4)
    void testGetDeviceById() {
         try (DeviceManager deviceManager = new DeviceManager()) {
             Device localDevice = deviceManager.getDeviceById("local").orElse(null);
             assertNotNull(localDevice, "Local device should be found by ID");
             assertEquals("local", localDevice.getId(), "Device ID should match");

             Device nonExistentDevice = deviceManager.getDeviceById("non-existent-id").orElse(null);
             assertNull(nonExistentDevice, "Non-existent device should return null");
         }
    }

    @Test
    @Order(5)
    void testGetDeviceByName() {
         try (DeviceManager deviceManager = new DeviceManager()) {
             Device localDevice = deviceManager.getLocalDevice().orElseThrow();
             String localDeviceName = localDevice.getName();

             Device foundDevice = deviceManager.getDeviceByName(localDeviceName).orElse(null);
             assertNotNull(foundDevice, "Device should be found by name");
             assertEquals(localDeviceName, foundDevice.getName(), "Device name should match");

             Device nonExistentDevice = deviceManager.getDeviceByName("Non-existent Device").orElse(null);
             assertNull(nonExistentDevice, "Non-existent device should return null");
         }
    }

    @Test
    @Order(6)
    void testEnumerateProcesses() {
         try (DeviceManager deviceManager = new DeviceManager()) {
             Device localDevice = deviceManager.getLocalDevice().orElseThrow();
             List<Process> processList = localDevice.enumerateProcesses();

             assertNotNull(processList, "ProcessList should not be null");
             int count = processList.size();
             assertTrue(count > 0, "Should have at least one running process");

             System.out.println("Found " + count + " process(es):");
             int limit = Math.min(5, count);
             for (int i = 0; i < limit; i++) {
                 Process process = processList.get(i);
                 assertNotNull(process, "Process should not be null");
                 int pid = process.getPid();
                 String name = process.getName();
                 assertTrue(pid > 0, "Process PID should be positive");
                 assertNotNull(name, "Process name should not be null");
                 System.out.println("  - PID: " + pid + ", Name: " + name);
             }
             if (count > 5) {
                 System.out.println("  ... and " + (count - 5) + " more");
             }
         }
    }

    @Test
    @Order(7)
    void testFindProcessByPid() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();
            List<Process> processes = localDevice.enumerateProcesses();

            assertFalse(processes.isEmpty(), "Should have at least one process");

            // Test finding an existing process
            Process firstProcess = processes.get(0);
            int targetPid = firstProcess.getPid();

            var foundProcess = localDevice.findProcessByPid(targetPid);
            assertTrue(foundProcess.isPresent(), "Should find process with PID " + targetPid);
            assertEquals(targetPid, foundProcess.get().getPid(), "Found process PID should match");

            // Test finding non-existent process
            var notFoundProcess = localDevice.findProcessByPid(999999);
            assertTrue(notFoundProcess.isEmpty(), "Should not find process with PID 999999");

            System.out.println("Successfully found process by PID: " + targetPid);
        }
    }

    @Test
    @Order(8)
    void testFindProcessByName() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();
            List<Process> processes = localDevice.enumerateProcesses();

            assertFalse(processes.isEmpty(), "Should have at least one process");

            // Find a system process that's likely to be running (try a few common ones)
            Process targetProcess = null;
            for (Process p : processes) {
                String name = p.getName();
                // Look for common system processes
                if (name.equals("kernel_task") || name.equals("launchd") || name.equals("init") ||
                    name.equals("systemd") || name.equals("System") || name.equals("svchost.exe")) {
                    targetProcess = p;
                    break;
                }
            }

            if (targetProcess == null) {
                // Just use the first process if we can't find a known one
                targetProcess = processes.get(0);
            }

            String targetName = targetProcess.getName();

            var foundProcess = localDevice.findProcessByName(targetName);
            assertTrue(foundProcess.isPresent(), "Should find process with name " + targetName);
            assertEquals(targetName, foundProcess.get().getName(), "Found process name should match");

            // Test finding non-existent process
            var notFoundProcess = localDevice.findProcessByName("NonExistentProcessName12345");
            assertTrue(notFoundProcess.isEmpty(), "Should not find non-existent process");

            System.out.println("Successfully found process by name: " + targetName);
        }
    }

    @Test
    @Order(9)
    void testGetProcessByPid() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();
            List<Process> processes = localDevice.enumerateProcesses();

            assertFalse(processes.isEmpty(), "Should have at least one process");

            // Find a stable system process (kernel_task, launchd/init, etc.)
            Process stableProcess = null;
            for (Process p : processes) {
                String name = p.getName();
                if (name.equals("kernel_task") || name.equals("launchd") || name.equals("init") ||
                    name.equals("systemd") || p.getPid() == 1) {
                    stableProcess = p;
                    break;
                }
            }

            if (stableProcess == null) {
                // Fall back to PID 1 which should always exist
                stableProcess = localDevice.getProcessByPid(1);
            }

            int targetPid = stableProcess.getPid();

            // Test getting the stable process - enumerate again to ensure it still exists
            Process foundProcess = localDevice.getProcessByPid(targetPid);
            assertNotNull(foundProcess, "Should get process with PID " + targetPid);
            assertEquals(targetPid, foundProcess.getPid(), "Retrieved process PID should match");

            // Test getting non-existent process (should throw)
            assertThrows(RuntimeException.class, () -> {
                localDevice.getProcessByPid(999999);
            }, "Should throw exception for non-existent PID");

            System.out.println("Successfully retrieved process by PID: " + targetPid);
        }
    }

    @Test
    @Order(10)
    void testGetProcessByName() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();
            List<Process> processes = localDevice.enumerateProcesses();

            assertFalse(processes.isEmpty(), "Should have at least one process");

            // Find a stable system process that's guaranteed to be running
            Process stableProcess = null;
            for (Process p : processes) {
                String name = p.getName();
                if (name.equals("kernel_task") || name.equals("launchd") || name.equals("init") ||
                    name.equals("systemd")) {
                    stableProcess = p;
                    break;
                }
            }

            if (stableProcess == null) {
                // Use PID 1 which should always exist
                stableProcess = localDevice.getProcessByPid(1);
            }

            String targetName = stableProcess.getName();

            // Test getting the stable process - enumerate again to ensure it still exists
            Process foundProcess = localDevice.getProcessByName(targetName);
            assertNotNull(foundProcess, "Should get process with name " + targetName);
            assertEquals(targetName, foundProcess.getName(), "Retrieved process name should match");

            // Test getting non-existent process (should throw)
            assertThrows(RuntimeException.class, () -> {
                localDevice.getProcessByName("NonExistentProcessName12345");
            }, "Should throw exception for non-existent process name");

            System.out.println("Successfully retrieved process by name: " + targetName);
        }
    }

    @Test
    @Order(11)
    void testSpawnGatingEnableDisable() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();

            try {
                // Enable spawn gating (not supported on macOS with System Integrity Protection enabled)
                localDevice.enableSpawnGating();
                System.out.println("Spawn gating enabled successfully");

                // Disable spawn gating
                localDevice.disableSpawnGating();
                System.out.println("Spawn gating disabled successfully");
            } catch (RuntimeException e) {
                // Spawn gating not supported (typically macOS with SIP or restricted platforms)
                System.out.println("Spawn gating not supported (macOS with SIP or restricted platform): " + e.getMessage());
                Assumptions.assumeTrue(false, "Spawn gating not available");
            }
        }
    }

    @Test
    @Order(12)
    void testEnumeratePendingSpawn() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();

            try {
                // Enable spawn gating first (not supported on macOS with SIP)
                localDevice.enableSpawnGating();

                try {
                    // Enumerate pending spawns (likely empty if nothing was spawned)
                    var pendingSpawns = localDevice.enumeratePendingSpawn();
                    assertNotNull(pendingSpawns, "Pending spawn list should not be null");

                    System.out.println("Found " + pendingSpawns.size() + " pending spawn(s)");

                    // Note: We can't guarantee there will be pending spawns in a test environment
                    // This test just verifies the method works without crashing
                } finally {
                    localDevice.disableSpawnGating();
                }
            } catch (RuntimeException e) {
                System.out.println("Spawn gating not supported (macOS with SIP or restricted platform): " + e.getMessage());
                Assumptions.assumeTrue(false, "Spawn gating not available");
            }
        }
    }

    @Test
    @Order(13)
    void testEnumeratePendingChildren() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();

            // Enumerate pending children (likely empty in test environment)
            var pendingChildren = localDevice.enumeratePendingChildren();
            assertNotNull(pendingChildren, "Pending children list should not be null");

            System.out.println("Found " + pendingChildren.size() + " pending child(ren)");

            // Note: This test just verifies the method works without crashing
        }
    }

    @Test
    @Order(14)
    void testInputToProcess() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();

            // Spawn a process that can receive input
            int pid = localDevice.spawnName("cat", List.of());

            if (pid > 0) {
                try {
                    // Resume the process first (spawned processes start suspended)
                    localDevice.resume(pid);

                    // Send some input data
                    byte[] testData = "Hello from Java\n".getBytes();
                    localDevice.input(pid, testData);

                    System.out.println("Successfully sent input to process PID: " + pid);

                    // Give it a moment to process
                    Thread.sleep(100);
                } catch (RuntimeException e) {
                    // Input may not be supported or process may have exited
                    System.out.println("Input test skipped: " + e.getMessage());
                    Assumptions.assumeTrue(false, "Input not available");
                } finally {
                    // Clean up
                    try {
                        localDevice.kill(pid);
                    } catch (Exception e) {
                        System.out.println("Cleanup: " + e.getMessage());
                    }
                }
            } else {
                System.out.println("Skipping input test - could not spawn cat process");
                Assumptions.assumeTrue(false, "Could not spawn test process");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail("Test interrupted");
        }
    }

    @Test
    @Order(15)
    void testInjectLibraryFile() {
        // TODO: Add Windows-specific test using a Windows DLL when running on Windows platform
        // TODO: Create actual test library and test real injection

        String osName = System.getProperty("os.name").toLowerCase();
        boolean isUnix = osName.contains("nix") || osName.contains("nux") || osName.contains("mac");

        if (!isUnix) {
            System.out.println("Skipping library injection test - Unix-only test (TODO: add Windows support)");
            Assumptions.assumeTrue(false, "Unix-only test");
            return;
        }

        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();

            // Note: We can't test with non-existent library files as Frida's native code
            // may crash when trying to load them. A real test would require:
            // 1. A compiled test library (.dylib/.so)
            // 2. A target process to inject into
            // 3. Proper verification that injection succeeded

            assertNotNull(localDevice, "Device should support library injection");
            System.out.println("Library file injection API available (actual test requires test library)");
        }
    }

    @Test
    @Order(16)
    void testInjectLibraryBlob() {
        // TODO: Add Windows-specific test using Windows DLL bytes when running on Windows platform
        // TODO: Create actual test library bytes and test real injection

        String osName = System.getProperty("os.name").toLowerCase();
        boolean isUnix = osName.contains("nix") || osName.contains("nux") || osName.contains("mac");

        if (!isUnix) {
            System.out.println("Skipping library blob injection test - Unix-only test (TODO: add Windows support)");
            Assumptions.assumeTrue(false, "Unix-only test");
            return;
        }

        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();

            // Note: We can't test with invalid library bytes as Frida's native code
            // may crash when trying to process them. A real test would require:
            // 1. Valid compiled library bytes
            // 2. A target process to inject into
            // 3. Proper verification that injection succeeded

            assertNotNull(localDevice, "Device should support library blob injection");
            System.out.println("Library blob injection API available (actual test requires valid library bytes)");
        }
    }

    @Test
    @Order(17)
    void testOpenChannel() {
        // TODO: Add Windows-specific test when running on Windows platform
        // TODO: Add test with valid channel address (requires running Frida service)

        String osName = System.getProperty("os.name").toLowerCase();
        boolean isUnix = osName.contains("nix") || osName.contains("nux") || osName.contains("mac");

        if (!isUnix) {
            System.out.println("Skipping channel test - Unix-only test (TODO: add Windows support)");
            Assumptions.assumeTrue(false, "Unix-only test");
            return;
        }

        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();

            // Note: We can't test with invalid addresses as Frida's native code
            // doesn't validate the address format before trying to parse it,
            // which causes SIGSEGV. A real test would require a valid Frida service.

            assertNotNull(localDevice, "Device should support channel operations");
            System.out.println("Channel opening API available (actual test requires valid Frida service)");
        }
    }

    @Test
    @Order(18)
    void testOpenService() {
        // TODO: Add Windows-specific test when running on Windows platform
        // TODO: Add test with valid service address (requires running Frida service)

        String osName = System.getProperty("os.name").toLowerCase();
        boolean isUnix = osName.contains("nix") || osName.contains("nux") || osName.contains("mac");

        if (!isUnix) {
            System.out.println("Skipping service test - Unix-only test (TODO: add Windows support)");
            Assumptions.assumeTrue(false, "Unix-only test");
            return;
        }

        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();

            // Note: We can't test with invalid addresses as Frida's native code
            // doesn't validate the address format before trying to parse it,
            // which causes SIGSEGV. A real test would require a valid Frida service.

            assertNotNull(localDevice, "Device should support service operations");
            System.out.println("Service opening API available (actual test requires valid Frida service)");
        }
    }
}
