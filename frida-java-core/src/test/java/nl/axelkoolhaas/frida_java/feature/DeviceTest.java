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
        DeviceManager deviceManager = new DeviceManager();
        assertNotNull(deviceManager, "DeviceManager should not be null");
        System.out.println("DeviceManager created successfully");
    }

    @Test
    @Order(2)
    void testEnumerateDevices() {
        DeviceManager deviceManager = new DeviceManager();
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

    @Test
    @Order(3)
    void testDeviceProperties() {
        DeviceManager deviceManager = new DeviceManager();
        Device device = deviceManager.getLocalDevice();

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

    @Test
    @Order(4)
    void testGetDeviceById() {
         DeviceManager deviceManager = new DeviceManager();
         Device localDevice = deviceManager.getDeviceById("local");
         assertNotNull(localDevice, "Local device should be found by ID");
         assertEquals("local", localDevice.getId(), "Device ID should match");

         Device nonExistentDevice = deviceManager.getDeviceById("non-existent-id");
         assertNull(nonExistentDevice, "Non-existent device should return null");
    }

    @Test
    @Order(5)
    void testGetDeviceByName() {
         DeviceManager deviceManager = new DeviceManager();
         Device localDevice = deviceManager.getLocalDevice();
         String localDeviceName = localDevice.getName();

         Device foundDevice = deviceManager.getDeviceByName(localDeviceName);
         assertNotNull(foundDevice, "Device should be found by name");
         assertEquals(localDeviceName, foundDevice.getName(), "Device name should match");

         Device nonExistentDevice = deviceManager.getDeviceByName("Non-existent Device");
         assertNull(nonExistentDevice, "Non-existent device should return null");
    }

    @Test
    @Order(6)
    void testEnumerateProcesses() {
         DeviceManager deviceManager = new DeviceManager();
         Device localDevice = deviceManager.getLocalDevice();
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
