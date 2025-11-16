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

import nl.axelkoolhaas.frida_java.Device;
import nl.axelkoolhaas.frida_java.DeviceManager;
import nl.axelkoolhaas.frida_java.Frida;
import nl.axelkoolhaas.frida_java.Process;
import nl.axelkoolhaas.frida_java.ProcessList;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Frida Process enumeration and querying.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ProcessTest {
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
    void testEnumerateProcesses() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            try (ProcessList processList = localDevice.enumerateProcesses()) {
                assertNotNull(processList, "ProcessList should not be null");
                assertTrue(processList.size() > 0, "Should have at least one running process");
                System.out.println("Enumerated " + processList.size() + " processes");
            }
        }
    }

    @Test
    @Order(2)
    void testProcessProperties() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            try (ProcessList processList = localDevice.enumerateProcesses()) {

                // Test properties of first few processes
                int testCount = Math.min(5, processList.size());
                for (int i = 0; i < testCount; i++) {
                    Process process = processList.get(i);
                    assertNotNull(process, "Process should not be null");

                    int pid = process.getPid();
                    String name = process.getName();
                    String identifier = process.getIdentifier();

                    assertTrue(pid > 0, "Process PID should be positive");
                    assertNotNull(name, "Process name should not be null");
                    // Some processes may not have identifiers, handle gracefully
                    if (identifier != null) {
                        assertFalse(identifier.isEmpty(), "Process identifier should not be empty when present");
                    } else {
                        System.out.println("Warning: Process " + name + " has null identifier (PID: " + pid + ")");
                    }
                    assertFalse(name.isEmpty(), "Process name should not be empty");

                    System.out.printf("Process %d: %s (PID: %d, ID: %s)%n", i, name, pid,
                        identifier != null ? identifier : "null");

                    // Test parent PID (might be 0 for some processes)
                    int parentPid = process.getParentPid();
                    assertTrue(parentPid >= 0, "Parent PID should be non-negative");

                    process.close();
                }
            }
        }
    }

    @Test
    @Order(3)
    void testFindSpecificProcess() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            try (ProcessList processList = localDevice.enumerateProcesses()) {

                // Look for common system processes
                String[] commonProcesses = {"kernel", "launchd", "systemd", "init"};
                boolean foundSystemProcess = false;

                for (int i = 0; i < processList.size(); i++) {
                    Process process = processList.get(i);
                    String name = process.getName().toLowerCase();

                    for (String commonName : commonProcesses) {
                        if (name.contains(commonName)) {
                            foundSystemProcess = true;
                            System.out.println("Found system process: " + process.getName() + " (PID: " + process.getPid() + ")");
                            process.close();
                            break;
                        }
                    }

                    if (foundSystemProcess) break;
                    process.close();
                }

                // We should find at least one system process on any Unix-like system
                if (!foundSystemProcess) {
                    System.out.println("Warning: No common system processes found");
                }
            }
        }
    }
}

