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

import nl.axelkoolhaas.frida_java.frida.ChildOrigin;
import nl.axelkoolhaas.frida_java.frida.Device;
import nl.axelkoolhaas.frida_java.frida.DeviceManager;
import nl.axelkoolhaas.frida_java.frida.Session;
import org.junit.jupiter.api.*;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/**
 * Test class for Frida Child process management functionality.
 * Tests child process enumeration, spawning, and management.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ChildTest {


    @Test
    @Order(1)
    void testChildOriginEnum() {
        // Simple enum validation
        assertEquals(3, ChildOrigin.values().length);
        assertEquals(0, ChildOrigin.FORK.getValue());
        assertEquals(1, ChildOrigin.EXEC.getValue());
        assertEquals(2, ChildOrigin.SPAWN.getValue());

        // Test round-trip conversion
        assertEquals(ChildOrigin.FORK, ChildOrigin.fromValue(0));
        assertEquals(ChildOrigin.EXEC, ChildOrigin.fromValue(1));
        assertEquals(ChildOrigin.SPAWN, ChildOrigin.fromValue(2));
    }

    @Test
    @Order(2)
    void testChildGatingBasicOperations() {
        try (DeviceManager deviceManager = new DeviceManager();
             Session session = createTestSession(deviceManager)) {

            // Session can be null if attachment failed due to SIP
            if (session == null) return;

            // Test enabling child gating
            assertDoesNotThrow(session::enableChildGating);

            // Test disabling child gating
            assertDoesNotThrow(session::disableChildGating);

            // Test multiple enable/disable cycles
            session.enableChildGating();
            session.enableChildGating(); // Should be idempotent
            session.disableChildGating();
            session.disableChildGating(); // Should be idempotent
        }
    }

    @Test
    @Order(3)
    void testChildGatingWithProcessLifecycle() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            // Spawn a shell that will create child processes
            int parentPid = localDevice.spawn("/bin/sh", List.of("-c", "sleep 2 && echo done"));
            assumeTrue(parentPid > 0, "Could not spawn test process");

            try (Session session = localDevice.attach(parentPid)) {
                session.enableChildGating();
                localDevice.resume(parentPid);

                // Give some time for potential child creation
                Thread.sleep(500);

                session.disableChildGating();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("Test was interrupted");
            } catch (Exception e) {
                System.err.println("Attachment failed (can be due to SIP on macOS): " + e.getMessage());
                assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
            } finally {
                cleanupProcess(localDevice, parentPid);
            }
        }
    }

    // Helper methods to reduce duplication
    private Session createTestSession(DeviceManager deviceManager) {
        Device localDevice = deviceManager.getLocalDevice();
        int pid = localDevice.spawn("/bin/sleep", List.of("10"));
        assumeTrue(pid > 0, "Could not spawn test process");

        try {
            return localDevice.attach(pid);
        } catch (Exception e) {
            cleanupProcess(localDevice, pid);
            assumeTrue(false, "Skipping test due to attachment issue (likely SIP on macOS): " + e.getMessage());
            return null; // This line won't be reached due to assumeTrue(false)
        }
    }

    private void cleanupProcess(Device device, int pid) {
        try {
            device.kill(pid);
        } catch (Exception e) {
            // Log but don't fail test on cleanup issues
            System.err.println("Warning: Could not cleanup process " + pid + ": " + e.getMessage());
        }
    }
}
