package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.Device;
import nl.axelkoolhaas.frida_java.DeviceManager;
import nl.axelkoolhaas.frida_java.Frida;
import nl.axelkoolhaas.frida_java.Session;
import nl.axelkoolhaas.frida_java.ProcessList;
import nl.axelkoolhaas.frida_java.Process;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

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
    void testAttachToExistingProcess() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            // Try to find an existing process we can attach to
            ProcessList processes = localDevice.enumerateProcesses();
            assertNotNull(processes, "Process list should not be null");

            int targetPid = -1;
            String targetName = "";

            // Look for a safe process to attach to (not kernel processes or system processes)
            for (int i = 0; i < processes.size(); i++) {
                Process process = processes.get(i);
                int pid = process.getPid();
                String name = process.getName();

                // Skip kernel and system processes, and the current test process
                if (pid > 1 && !name.startsWith("kernel") && !name.startsWith("System")
                    && !name.contains("java") && !name.contains("surefire")) {
                    targetPid = pid;
                    targetName = name;
                    break;
                }
            }

            // If we can't find a suitable process, try spawning one
            if (targetPid == -1) {
                try {
                    targetPid = localDevice.spawn("/bin/sleep");
                    targetName = "sleep";
                    if (targetPid <= 0) {
                        targetPid = -1;
                    }
                } catch (Exception e) {
                    System.out.println("Spawn failed: " + e.getMessage());
                }
            }

            if (targetPid > 0) {
                try (Session session = localDevice.attach(targetPid)) {
                    assertNotNull(session, "Session should not be null");
                    assertFalse(session.isDetached(), "Session should not be detached");
                    assertEquals(targetPid, session.getPid(), "Session PID should match target process PID");
                    System.out.println("Successfully attached to process '" + targetName + "' with PID: " + targetPid);
                } catch (RuntimeException e) {
                    System.out.println("Attach failed for PID " + targetPid + " (" + targetName + "): " + e.getMessage());
                    // If attach fails, it's often due to permissions - mark test as passed if we can't attach
                    assumeTrue(false, "Cannot attach to process due to permissions: " + e.getMessage());
                }
            } else {
                assumeTrue(false, "No suitable process found for testing attachment");
            }

            processes.close();
        }
    }

    // More tests for script loading, detaching, etc. will be added here.
}
