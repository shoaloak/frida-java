package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.Device;
import nl.axelkoolhaas.frida_java.DeviceManager;
import nl.axelkoolhaas.frida_java.Frida;
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

    // More tests for process querying, matching, etc. will be added here.
}

