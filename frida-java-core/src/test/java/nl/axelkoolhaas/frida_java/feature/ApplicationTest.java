package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.ApplicationList;
import nl.axelkoolhaas.frida_java.Device;
import nl.axelkoolhaas.frida_java.DeviceManager;
import nl.axelkoolhaas.frida_java.Frida;
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
            } catch (UnsupportedOperationException e) {
                System.out.println("Application enumeration not supported on this platform");
            }
        }
    }

    // More tests for child management, spawning, etc. will be added here.
}
