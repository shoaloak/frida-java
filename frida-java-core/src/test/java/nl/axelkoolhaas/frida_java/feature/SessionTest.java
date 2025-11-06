package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.Device;
import nl.axelkoolhaas.frida_java.DeviceManager;
import nl.axelkoolhaas.frida_java.Frida;
import nl.axelkoolhaas.frida_java.Session;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Frida Session and Script functionality.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SessionTest {
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
    void testAttachToSelf() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();
            int pid = ProcessHandle.current().pid() > Integer.MAX_VALUE ? 0 : (int) ProcessHandle.current().pid();
            assertTrue(pid > 0, "Current process PID should be positive");
            try (Session session = localDevice.attach(pid)) {
                assertNotNull(session, "Session should not be null");
                assertFalse(session.isDetached(), "Session should not be detached");
                System.out.println("Attached to self with PID: " + pid);
            }
        }
    }

    // More tests for script loading, detaching, etc. will be added here.
}
