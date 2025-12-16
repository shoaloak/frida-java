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

import nl.axelkoolhaas.frida_java.frida.*;
import org.junit.jupiter.api.*;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Frida Application enumeration.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ApplicationTest {

    @Test
    @Order(1)
    void testEnumerateApplications() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            List<Application> appList = localDevice.enumerateApplications();
            if (appList == null) {
                System.err.println("Failed to enumerate applications");
                return;
            }

            System.out.println("Enumerated " + appList.size() + " applications");

            // Test individual application properties if we have any apps
            if (!appList.isEmpty()) {
                Application firstApp = appList.getFirst();
                assertNotNull(firstApp, "Application should not be null");
                assertNotNull(firstApp.getIdentifier(), "Application identifier should not be null");
                assertNotNull(firstApp.getName(), "Application name should not be null");
                System.out.println("First app: " + firstApp.getName() + " (" + firstApp.getIdentifier() + ")");

                // Clean up applications
                for (Application app : appList) {
                    app.clean();
                }
            }
        }
    }

    @Test
    @Order(2)
    void testEnumerateApplicationsWithScope() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            // Test with different scopes
            List<Application> minimalApps = localDevice.enumerateApplications(null, Scope.MINIMAL);
            List<Application> fullApps = localDevice.enumerateApplications(null, Scope.FULL);

            if (minimalApps != null) {
                System.out.println("Minimal scope: " + minimalApps.size() + " applications");
                for (Application app : minimalApps) {
                    app.clean();
                }
            }

            if (fullApps != null) {
                System.out.println("Full scope: " + fullApps.size() + " applications");
                for (Application app : fullApps) {
                    app.clean();
                }
            }
        }
    }

    @Test
    @Order(3)
    void testApplicationProperties() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            List<Application> appList = localDevice.enumerateApplications();
            if (appList == null) {
                System.err.println("Failed to enumerate applications");
                return;
            }

            if (!appList.isEmpty()) {
                // Test first few applications
                int testCount = Math.min(3, appList.size());
                for (int i = 0; i < testCount; i++) {
                    Application app = appList.get(i);

                    String identifier = app.getIdentifier();
                    String name = app.getName();
                    int pid = app.getPid();

                    assertNotNull(identifier, "Application identifier should not be null");
                    assertNotNull(name, "Application name should not be null");
                    assertFalse(identifier.isEmpty(), "Application identifier should not be empty");
                    assertFalse(name.isEmpty(), "Application name should not be empty");

                    System.out.printf("App %d: %s (%s) PID: %d%n", i, name, identifier, pid);
                }

                // Clean up applications
                for (Application app : appList) {
                    app.clean();
                }
            }
        }
    }

    @Test
    @Order(4)
    void testEnumerateSpecificApplication() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            // First get all apps to find a valid identifier
            List<Application> allApps = localDevice.enumerateApplications();
            if (allApps == null || allApps.isEmpty()) {
                System.out.println("No applications found to test specific enumeration");
                return;
            }

            String testIdentifier = allApps.getFirst().getIdentifier();
            System.out.println("Testing enumeration with identifier: " + testIdentifier);

            // Clean up the initial list
            for (Application app : allApps) {
                app.clean();
            }

            // Now test specific enumeration
            List<Application> specificApps = localDevice.enumerateApplications(testIdentifier, Scope.MINIMAL);
            if (specificApps != null) {
                System.out.println("Found " + specificApps.size() + " applications matching identifier");

                if (!specificApps.isEmpty()) {
                    assertEquals(testIdentifier, specificApps.getFirst().getIdentifier(),
                            "Returned application should match requested identifier");
                }

                // Clean up
                for (Application app : specificApps) {
                    app.clean();
                }
            }
        }
    }
}

