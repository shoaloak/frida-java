package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.Device;
import nl.axelkoolhaas.frida_java.DeviceManager;
import nl.axelkoolhaas.frida_java.Frida;
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

    // More error and edge case tests will be added here.
}

