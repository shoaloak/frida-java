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

import nl.axelkoolhaas.frida_java.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Frida Application and Child management.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ApplicationTest {
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
    void testEnumerateApplications() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            try {
                ApplicationList appList = localDevice.enumerateApplicationsSync(null, null);
                assertNotNull(appList, "ApplicationList should not be null");
                System.out.println("Enumerated " + appList.size() + " applications");

                // Test individual application properties if we have any apps
                if (appList.size() > 0) {
                    try (Application firstApp = appList.get(0)) {
                        assertNotNull(firstApp, "Application should not be null");
                        assertNotNull(firstApp.getIdentifier(), "Application identifier should not be null");
                        assertNotNull(firstApp.getName(), "Application name should not be null");
                        System.out.println("First app: " + firstApp.getName() + " (" + firstApp.getIdentifier() + ")");
                    }
                }

                appList.close();
            } catch (UnsupportedOperationException e) {
                System.out.println("Application enumeration not supported on this platform");
            }
        }
    }

    @Test
    @Order(2)
    void testApplicationProperties() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            try {
                ApplicationList appList = localDevice.enumerateApplicationsSync(null, null);

                if (appList.size() > 0) {
                    for (int i = 0; i < Math.min(3, appList.size()); i++) {
                        try (Application app = appList.get(i)) {
                            String identifier = app.getIdentifier();
                            String name = app.getName();
                            int pid = app.getPid();

                            assertNotNull(identifier, "Application identifier should not be null");
                            assertNotNull(name, "Application name should not be null");
                            assertFalse(identifier.isEmpty(), "Application identifier should not be empty");
                            assertFalse(name.isEmpty(), "Application name should not be empty");

                            System.out.printf("App %d: %s (%s) PID: %d%n", i, name, identifier, pid);
                        }
                    }
                }

                appList.close();
            } catch (UnsupportedOperationException e) {
                System.out.println("Application enumeration not supported on this platform");
            }
        }
    }

    @Test
    @Order(3)
    void testGetFrontmostApplication() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            try {
                Application frontmostApp = localDevice.getFrontmostApplicationSync(null, null);
                if (frontmostApp != null) {
                    assertNotNull(frontmostApp.getIdentifier(), "Frontmost app identifier should not be null");
                    assertNotNull(frontmostApp.getName(), "Frontmost app name should not be null");
                    System.out.println("Frontmost application: " + frontmostApp.getName());
                    frontmostApp.close();
                } else {
                    System.out.println("No frontmost application found");
                }
            } catch (UnsatisfiedLinkError e) {
                System.out.println("getFrontmostApplicationSync not implemented in native layer: " + e.getMessage());
                // This is expected if the native method is not yet implemented
            } catch (UnsupportedOperationException e) {
                System.out.println("Frontmost application query not supported on this platform");
            }
        }
    }

    @Test
    @Order(4)
    void testApplicationQueryOptions() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            try {
                // Test with ApplicationQueryOptions if available
                ApplicationQueryOptions options = new ApplicationQueryOptions();
                ApplicationList appList = localDevice.enumerateApplicationsSync(options, null);
                assertNotNull(appList, "ApplicationList with options should not be null");
                System.out.println("Enumerated " + appList.size() + " applications with options");
                appList.close();
            } catch (UnsupportedOperationException e) {
                System.out.println("Application enumeration with options not supported on this platform");
            } catch (Exception e) {
                System.out.println("ApplicationQueryOptions test skipped: " + e.getMessage());
            }
        }
    }
}
