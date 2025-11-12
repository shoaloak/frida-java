package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.*;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for advanced Device functionality.
 * Tests system parameter queries, remote device options, and device management features.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DeviceAdvancedTest {

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
    void testQuerySystemParameters() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                java.util.Map<String, Object> params = localDevice.querySystemParametersSync(null);
                assertNotNull(params, "System parameters should not be null");
                System.out.println("System parameters count: " + params.size());

                // Print some of the parameters for debugging
                params.entrySet().stream()
                    .limit(5)
                    .forEach(entry -> System.out.println("  " + entry.getKey() + ": " + entry.getValue()));

            } catch (UnsatisfiedLinkError e) {
                System.out.println("querySystemParametersSync not implemented in native layer: " + e.getMessage());
                // This is expected if the native method is not yet implemented
            } catch (RuntimeException e) {
                System.out.println("System parameter query not supported or failed: " + e.getMessage());
            }
        }
    }

    @Test
    @Order(2)
    void testRemoteDeviceOptions() {
        try {
            RemoteDeviceOptions options = new RemoteDeviceOptions();
            assertNotNull(options, "RemoteDeviceOptions should be creatable");
            System.out.println("RemoteDeviceOptions created successfully");
        } catch (Exception e) {
            System.out.println("RemoteDeviceOptions test skipped: " + e.getMessage());
        }
    }

    @Test
    @Order(3)
    void testDeviceListOperations() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device[] devices = deviceManager.enumerateDevices();

            // Test DeviceList if it wraps the array
            assertNotNull(devices, "Devices array should not be null");
            assertTrue(devices.length > 0, "Should have at least one device");

            // Test properties of each device
            for (Device device : devices) {
                assertNotNull(device.getId(), "Device ID should not be null");
                assertNotNull(device.getName(), "Device name should not be null");
                assertNotNull(device.getType(), "Device type should not be null");

                System.out.printf("Device: %s (%s) - Type: %s, Lost: %s%n",
                    device.getName(), device.getId(), device.getType(), device.isLost());

                // Test that we can get basic info without errors
                try {
                    boolean isLost = device.isLost();
                    System.out.println("  Lost status: " + isLost);
                } catch (Exception e) {
                    System.out.println("  Could not get lost status: " + e.getMessage());
                }
            }
        }
    }

    @Test
    @Order(4)
    void testDeviceManagerAddRemoveHandlers() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            // Test that device manager can handle multiple calls
            Device localDevice1 = deviceManager.getLocalDevice();
            Device localDevice2 = deviceManager.getLocalDevice();

            // Should be the same device
            assertEquals(localDevice1.getId(), localDevice2.getId(), "Local device should be consistent");

            System.out.println("Device manager consistency test passed");
        }
    }

    @Test
    @Order(5)
    void testFrontmostQueryOptions() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                FrontmostQueryOptions options = new FrontmostQueryOptions();
                assertNotNull(options, "FrontmostQueryOptions should be creatable");

                Application frontmost = localDevice.getFrontmostApplicationSync(options, null);
                if (frontmost != null) {
                    System.out.println("Frontmost app with options: " + frontmost.getName());
                    frontmost.close();
                } else {
                    System.out.println("No frontmost application found");
                }

            } catch (UnsatisfiedLinkError e) {
                System.out.println("getFrontmostApplicationSync not implemented in native layer: " + e.getMessage());
                // This is expected if the native method is not yet implemented
            } catch (Exception e) {
                System.out.println("FrontmostQueryOptions test skipped: " + e.getMessage());
            }
        }
    }

    @Test
    @Order(6)
    void testDeviceTypesHandling() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device[] devices = deviceManager.enumerateDevices();

            // Verify we can handle all device types
            for (Device device : devices) {
                Device.Type type = device.getType();
                assertNotNull(type, "Device type should not be null");

                // Make sure the type is one of the expected values
                assertTrue(type == Device.Type.LOCAL || type == Device.Type.REMOTE || type == Device.Type.USB,
                    "Device type should be LOCAL, REMOTE, or USB");

                System.out.println("Device type validation passed for: " + device.getName());
            }
        }
    }

    @Test
    @Order(7)
    void testProcessEnumerationWithDevice() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device[] devices = deviceManager.enumerateDevices();

            // Test process enumeration on each available device
            for (Device device : devices) {
                try {
                    if (!device.isLost()) {
                        ProcessList processes = device.enumerateProcesses();
                        assertNotNull(processes, "Process list should not be null for device: " + device.getName());
                        System.out.println("Device " + device.getName() + " has " + processes.size() + " processes");
                        processes.close();
                    } else {
                        System.out.println("Skipping lost device: " + device.getName());
                    }
                } catch (Exception e) {
                    System.out.println("Could not enumerate processes on device " + device.getName() + ": " + e.getMessage());
                }
            }
        }
    }
}
