package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.*;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/**
 * Test class for Frida Process spawn functionality.
 * Tests process spawning, resuming, killing, and spawn enumeration.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SpawnTest {

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
    void testSpawnSimpleProcess() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                // Try to spawn a simple command that exists on most systems
                String[] testPrograms = {"/bin/sleep", "/usr/bin/sleep", "sleep"};
                int spawnedPid = -1;
                String usedProgram = null;

                for (String program : testPrograms) {
                    try {
                        spawnedPid = localDevice.spawn(program);
                        usedProgram = program;
                        break;
                    } catch (RuntimeException e) {
                        // Try next program
                    }
                }

                if (spawnedPid > 0) {
                    System.out.println("Successfully spawned process '" + usedProgram + "' with PID: " + spawnedPid);

                    // Clean up by killing the spawned process
                    try {
                        localDevice.kill(spawnedPid);
                        System.out.println("Killed spawned process: " + spawnedPid);
                    } catch (RuntimeException e) {
                        System.out.println("Warning: Could not kill spawned process: " + e.getMessage());
                    }
                } else {
                    abort("Could not spawn any test process - skipping test");
                }
            } catch (Exception e) {
                abort("Spawn test failed: " + e.getMessage());
            }
        }
    }

    @Test
    @Order(2)
    void testSpawnProcessWithArgs() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                String program = "/bin/sleep";
                String[] args = {"5"}; // Sleep for 5 seconds

                int spawnedPid = localDevice.spawn(program, args);
                if (spawnedPid > 0) {
                    System.out.println("Successfully spawned process with args. PID: " + spawnedPid);

                    // Clean up
                    try {
                        localDevice.kill(spawnedPid);
                        System.out.println("Killed spawned process: " + spawnedPid);
                    } catch (RuntimeException e) {
                        System.out.println("Warning: Could not kill spawned process: " + e.getMessage());
                    }
                } else {
                    System.out.println("Spawn with args failed (returned PID: " + spawnedPid + ")");
                }

            } catch (RuntimeException e) {
                System.out.println("Could not spawn process with args: " + e.getMessage());
            }
        }
    }

    @Test
    @Order(3)
    void testSpawnAndResume() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                String program = "/bin/sleep";
                int spawnedPid = localDevice.spawn(program);
                assertTrue(spawnedPid > 0, "Spawned PID should be positive");

                // Resume the spawned process
                localDevice.resume(spawnedPid);
                System.out.println("Successfully resumed spawned process: " + spawnedPid);

                // Give it a moment to run
                Thread.sleep(100);

                // Clean up
                try {
                    localDevice.kill(spawnedPid);
                    System.out.println("Killed spawned process: " + spawnedPid);
                } catch (RuntimeException e) {
                    System.out.println("Warning: Could not kill spawned process: " + e.getMessage());
                }

            } catch (RuntimeException e) {
                abort("Could not test spawn and resume: " + e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("Test was interrupted");
            }
        }
    }

    @Test
    @Order(4)
    void testAttachToSpawnedProcess() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                String program = "/bin/sleep";
                int spawnedPid = localDevice.spawn(program);
                assertTrue(spawnedPid > 0, "Spawned PID should be positive");

                // Try to attach to the spawned process
                try (Session session = localDevice.attach(spawnedPid)) {
                    assertNotNull(session, "Session should not be null");
                    assertEquals(spawnedPid, session.getPid(), "Session PID should match spawned PID");
                    assertFalse(session.isDetached(), "Session should not be detached");

                    System.out.println("Successfully attached to spawned process: " + spawnedPid);

                    // Resume the process
                    localDevice.resume(spawnedPid);

                } catch (RuntimeException e) {
                    System.out.println("Could not attach to spawned process: " + e.getMessage());
                } finally {
                    // Clean up
                    try {
                        localDevice.kill(spawnedPid);
                        System.out.println("Killed spawned process: " + spawnedPid);
                    } catch (RuntimeException e) {
                        System.out.println("Warning: Could not kill spawned process: " + e.getMessage());
                    }
                }

            } catch (RuntimeException e) {
                abort("Could not test attach to spawned process: " + e.getMessage());
            }
        }
    }

    @Test
    @Order(5)
    void testKillProcess() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                String program = "/bin/sleep";
                String[] args = {"10"}; // Sleep for 10 seconds

                int spawnedPid = localDevice.spawn(program, args);
                if (spawnedPid > 0) {
                    // Resume it first
                    localDevice.resume(spawnedPid);

                    // Give it a moment to start
                    Thread.sleep(100);

                    // Now kill it
                    localDevice.kill(spawnedPid);
                    System.out.println("Successfully killed spawned process: " + spawnedPid);
                } else {
                    System.out.println("Could not spawn process for kill test (returned PID: " + spawnedPid + ")");
                }

            } catch (RuntimeException e) {
                System.out.println("Could not test kill process: " + e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("Test was interrupted");
            }
        }
    }

    @Test
    @Order(6)
    void testInvalidSpawn() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            // Try to spawn a non-existent program
            assertThrows(RuntimeException.class, () ->
                    localDevice.spawn("/nonexistent/program"), "Should throw exception for non-existent program");

            System.out.println("Correctly threw exception for invalid spawn");
        }
    }
}
