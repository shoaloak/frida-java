package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.Device;
import nl.axelkoolhaas.frida_java.DeviceManager;
import nl.axelkoolhaas.frida_java.Frida;
import nl.axelkoolhaas.frida_java.Process;
import nl.axelkoolhaas.frida_java.ProcessList;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Device-related Frida bindings.
 * Tests device enumeration, device properties, and process enumeration functionality.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DeviceTest {

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
    void testCreateDeviceManager() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            assertNotNull(deviceManager, "DeviceManager should not be null");
            System.out.println("DeviceManager created successfully");
        }
        System.out.println("DeviceManager closed");
    }

    @Test
    @Order(2)
    void testEnumerateDevices() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device[] devices = deviceManager.enumerateDevices();
            assertNotNull(devices, "Device array should not be null");
            assertTrue(devices.length > 0, "Should have at least one device");

            System.out.println("Found " + devices.length + " device(s):");
            for (Device device : devices) {
                assertNotNull(device, "Device should not be null");
                assertNotNull(device.getId(), "Device ID should not be null");
                assertNotNull(device.getName(), "Device name should not be null");
                assertNotNull(device.getType(), "Device type should not be null");
                System.out.println("  - " + device);
            }
        }
    }

    @Test
    @Order(3)
    void testGetLocalDevice() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            assertNotNull(localDevice, "Local device should not be null");
            assertEquals(Device.Type.LOCAL, localDevice.getType(), "Device type should be LOCAL");
            assertNotNull(localDevice.getId(), "Device ID should not be null");
            assertNotNull(localDevice.getName(), "Device name should not be null");
            assertFalse(localDevice.getId().isEmpty(), "Device ID should not be empty");
            assertFalse(localDevice.getName().isEmpty(), "Device name should not be empty");
            assertFalse(localDevice.isLost(), "Local device should not be lost");

            System.out.println("Local device: " + localDevice);
        }
    }

    @Test
    @Order(4)
    void testDeviceProperties() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            String id = localDevice.getId();
            assertNotNull(id, "Device ID should not be null");
            assertFalse(id.isEmpty(), "Device ID should not be empty");

            String name = localDevice.getName();
            assertNotNull(name, "Device name should not be null");
            assertFalse(name.isEmpty(), "Device name should not be empty");

            Device.Type type = localDevice.getType();
            assertNotNull(type, "Device type should not be null");
            assertEquals(Device.Type.LOCAL, type, "Local device type should be LOCAL");

            boolean isLost = localDevice.isLost();
            assertFalse(isLost, "Local device should not be lost");

            System.out.printf("Device - ID: %s, Name: %s, Type: %s, Lost: %s%n",
                id, name, type, isLost);
        }
    }

    @Test
    @Order(5)
    void testEnumerateProcesses() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            try (ProcessList processList = localDevice.enumerateProcesses()) {
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
                    process.close();
                }
                if (count > 5) {
                    System.out.println("  ... and " + (count - 5) + " more");
                }
            }
        }
    }

    @Test
    @Order(6)
    void testDeviceToString() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            String deviceString = localDevice.toString();

            assertNotNull(deviceString, "Device toString should not be null");
            assertTrue(deviceString.contains("Device{"), "toString should contain class name");
            assertTrue(deviceString.contains("name="), "toString should contain name field");
            assertTrue(deviceString.contains("type="), "toString should contain type field");
            assertTrue(deviceString.contains("id="), "toString should contain id field");

            System.out.println("Device toString: " + deviceString);
        }
    }

    @Test
    @Order(7)
    void testGetDeviceById() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device[] devices = deviceManager.enumerateDevices();
            if (devices.length > 0) {
                Device firstDevice = devices[0];
                String deviceId = firstDevice.getId();

                Device foundDevice = deviceManager.getDeviceById(deviceId);
                assertNotNull(foundDevice, "Found device should not be null");
                assertEquals(deviceId, foundDevice.getId(), "Device IDs should match");

                System.out.println("Found device by ID: " + foundDevice);
            }
        }
    }

    @Test
    @Order(8)
    void testGetDeviceByName() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device[] devices = deviceManager.enumerateDevices();
            if (devices.length > 0) {
                Device firstDevice = devices[0];
                String deviceName = firstDevice.getName();

                Device foundDevice = deviceManager.getDeviceByName(deviceName);
                assertNotNull(foundDevice, "Found device should not be null");
                assertEquals(deviceName, foundDevice.getName(), "Device names should match");

                System.out.println("Found device by name: " + foundDevice);
            }
        }
    }

    @Test
    @Order(9)
    void testGetDeviceByIdNotFound() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            assertThrows(RuntimeException.class, () ->
                deviceManager.getDeviceById("nonexistent-device-id"),
                "Should throw RuntimeException for nonexistent device ID");
        }
    }

    @Test
    @Order(10)
    void testGetDeviceByNameNotFound() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            assertThrows(RuntimeException.class, () ->
                deviceManager.getDeviceByName("Nonexistent Device Name"),
                "Should throw RuntimeException for nonexistent device name");
        }
    }

    @Test
    @Order(11)
    void testMultipleDeviceManagerInstances() {
        // Test that multiple DeviceManager instances can be created and used concurrently
        try (DeviceManager dm1 = new DeviceManager();
             DeviceManager dm2 = new DeviceManager()) {

            Device[] devices1 = dm1.enumerateDevices();
            Device[] devices2 = dm2.enumerateDevices();

            assertNotNull(devices1, "First device manager should return devices");
            assertNotNull(devices2, "Second device manager should return devices");
            assertEquals(devices1.length, devices2.length, "Both managers should see same number of devices");

            System.out.println("Multiple DeviceManager instances work correctly");
        }
    }
}
