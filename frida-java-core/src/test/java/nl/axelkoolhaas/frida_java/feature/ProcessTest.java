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
import nl.axelkoolhaas.frida_java.frida.Frida;
import nl.axelkoolhaas.frida_java.frida.Process;
import org.junit.jupiter.api.*;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Frida Process enumeration and querying.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ProcessTest {

    @Test
    @Order(1)
    void testEnumerateProcesses() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();
            List<Process> processList = localDevice.enumerateProcesses();

            assertNotNull(processList, "ProcessList should not be null");
            assertFalse(processList.isEmpty(), "Should have at least one running process");
            System.out.println("Enumerated " + processList.size() + " processes");
        }
    }

    @Test
    @Order(2)
    void testProcessProperties() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();
            List<Process> processList = localDevice.enumerateProcesses();

            // Test properties of first few processes
            int testCount = Math.min(5, processList.size());
            for (int i = 0; i < testCount; i++) {
                Process process = processList.get(i);
                assertNotNull(process, "Process should not be null");

                int pid = process.getPid();
                String name = process.getName();

                assertTrue(pid > 0, "Process PID should be positive");
                assertNotNull(name, "Process name should not be null");
                assertFalse(name.isEmpty(), "Process name should not be empty");

                System.out.printf("Process %d: %s (PID: %d)%n", i, name, pid);
            }
        }
    }

    @Test
    @Order(3)
    void testFindSpecificProcess() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();
            List<Process> processList = localDevice.enumerateProcesses();

            // Look for common system processes
            String[] commonProcesses = {"kernel", "launchd", "systemd", "init"};
            boolean foundSystemProcess = false;

            for (Process process : processList) {
                String name = process.getName().toLowerCase();

                for (String commonName : commonProcesses) {
                    if (name.contains(commonName)) {
                        foundSystemProcess = true;
                        System.out.println("Found system process: " + process.getName() + " (PID: " + process.getPid() + ")");
                        break;
                    }
                }

                if (foundSystemProcess) break;
            }

            // We should find at least one system process on any Unix-like system
            if (!foundSystemProcess) {
                System.out.println("Warning: No common system processes found");
            }
        }
    }

    @Test
    @Order(4)
    void testProcessToString() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice().orElseThrow();
            List<Process> processList = localDevice.enumerateProcesses();

            if (!processList.isEmpty()) {
                Process process = processList.getFirst();
                String processString = process.toString();

                assertNotNull(processString, "Process toString should not be null");
                assertTrue(processString.contains("Process{"), "toString should contain Process{");
                assertTrue(processString.contains("pid="), "toString should contain pid=");
                assertTrue(processString.contains("name="), "toString should contain name=");

                System.out.println("Process toString: " + processString);
            }
        }
    }
}

