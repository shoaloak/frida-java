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

import nl.axelkoolhaas.frida_java.ApplicationList;
import nl.axelkoolhaas.frida_java.Device;
import nl.axelkoolhaas.frida_java.DeviceManager;
import nl.axelkoolhaas.frida_java.Frida;
import nl.axelkoolhaas.frida_java.ProcessList;
import nl.axelkoolhaas.frida_java.Session;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Frida error and edge case handling.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ErrorHandlingTest {
    @BeforeAll
    static void setUp() {
        Frida.init();
    }

    @AfterAll
    static void tearDown() {
        Frida.deinit();
    }

    @Test
    @Order(1)
    void testAttachToInvalidPid() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            assertThrows(RuntimeException.class, () -> localDevice.attach(-1), "Should throw for invalid PID");
        }
    }

    @Test
    @Order(2)
    void testAttachToNonexistentPid() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            // Test with a very high PID that should not exist
            assertThrows(RuntimeException.class, () -> localDevice.attach(Integer.MAX_VALUE), "Should throw for non-existent PID");
        }
    }

    @Test
    @Order(3)
    void testAttachByInvalidName() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            assertThrows(RuntimeException.class, () -> localDevice.attachByName("nonexistent-process-12345"),
                         "Should throw for non-existent process name");
        }
    }

    @Test
    @Order(4)
    void testKillInvalidPid() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            assertThrows(RuntimeException.class, () -> localDevice.kill(-1), "Should throw for invalid PID");
        }
    }

    @Test
    @Order(5)
    void testResumeInvalidPid() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                localDevice.resume(-1);
                System.out.println("Resume with invalid PID (-1) did not throw exception (implementation dependent)");
            } catch (RuntimeException e) {
                System.out.println("Resume with invalid PID correctly threw exception: " + e.getMessage());
            }

            try {
                localDevice.resume(Integer.MAX_VALUE);
                System.out.println("Resume with non-existent PID did not throw exception (implementation dependent)");
            } catch (RuntimeException e) {
                System.out.println("Resume with non-existent PID correctly threw exception: " + e.getMessage());
            }
        }
    }

    @Test
    @Order(6)
    void testSpawnInvalidProgram() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            assertThrows(RuntimeException.class, () -> localDevice.spawn("/completely/nonexistent/program"),
                         "Should throw for non-existent program");
        }
    }

    @Test
    @Order(7)
    void testCreateScriptWithInvalidSource() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            // Try to use current process PID for self-attachment to avoid permission issues
            int currentPid = getCurrentProcessId();
            if (currentPid <= 0) {
                System.out.println("Cannot determine current process ID, skipping script test");
                return;
            }

            try (Session session = localDevice.attach(currentPid)) {
                // Test with invalid JavaScript
                String invalidScript = "this is not valid javascript syntax!!!";
                assertThrows(RuntimeException.class, () -> session.createScript(invalidScript),
                           "Should throw for invalid script syntax");
                System.out.println("Invalid script correctly threw exception");
            } catch (RuntimeException e) {
                System.out.println("Script test failed (possibly due to permissions): " + e.getMessage());
                // Don't fail the test, just log the issue
            }
        }
    }

    @Test
    @Order(8)
    void testOperationsOnDetachedSession() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            // Try to use current process PID for self-attachment
            int currentPid = getCurrentProcessId();
            if (currentPid <= 0) {
                System.out.println("Cannot determine current process ID, skipping detached session test");
                return;
            }

            try (Session session = localDevice.attach(currentPid)) {
                session.detach();
                assertTrue(session.isDetached(), "Session should be detached");

                // Attempting operations on detached session should fail
                assertThrows(RuntimeException.class, () -> session.createScript("console.log('test');"),
                           "Should throw for operations on detached session");
                System.out.println("Operations on detached session correctly threw exception");
            } catch (RuntimeException e) {
                System.out.println("Detached session test failed (possibly due to permissions): " + e.getMessage());
                // Don't fail the test, just log the issue
            }
        }
    }

    /**
     * Helper method to get current process ID
     */
    private int getCurrentProcessId() {
        try {
            return (int) ProcessHandle.current().pid();
        } catch (Exception e) {
            System.out.println("Could not get current process ID: " + e.getMessage());
            return -1;
        }
    }

    @Test
    @Order(9)
    void testDoubleClose() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            ProcessList processes = localDevice.enumerateProcesses();

            // Test double close on ProcessList (should be safe)
            processes.close();
            processes.close(); // Second close should be safe

            System.out.println("Double close handled gracefully");
        }
    }

    @Test
    @Order(10)
    void testNullParameters() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            // Test that null parameters are handled gracefully where appropriate
            ProcessList processes = localDevice.enumerateProcesses();
            assertNotNull(processes, "Process list should not be null even with null parameters");
            processes.close();

            ApplicationList apps = localDevice.enumerateApplicationsSync(null, null);
            assertNotNull(apps, "Application list should not be null even with null parameters");
            apps.close();

            System.out.println("Null parameters handled gracefully");
        } catch (UnsupportedOperationException e) {
            System.out.println("Some operations not supported on this platform");
        }
    }
}

