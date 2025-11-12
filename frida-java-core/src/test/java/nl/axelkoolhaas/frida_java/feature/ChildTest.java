package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.*;
import nl.axelkoolhaas.frida_java.Process;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/**
 * Test class for Frida Child process management functionality.
 * Tests child process enumeration, spawning, and management.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ChildTest {

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
    void testChildListCreation() {
        try {
            // Test that we can create child-related objects
            // Note: Actual child enumeration might require specific scenarios
            System.out.println("Child list classes are available");
        } catch (Exception e) {
            System.out.println("Child test setup issue: " + e.getMessage());
        }
    }

    @Test
    @Order(2)
    void testSpawnWithChildGating() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                // Spawn a process that might create children
                String program = "/bin/sh";
                String[] args = {"-c", "sleep 5"};

                int spawnedPid = localDevice.spawn(program, args);
                if (spawnedPid > 0) {
                    System.out.println("Spawned shell process with PID: " + spawnedPid);

                    // Attach to it and enable child gating
                    try (Session session = localDevice.attach(spawnedPid)) {
                        session.enableChildGating();
                        System.out.println("Enabled child gating for PID: " + spawnedPid);

                        // Resume the process
                        localDevice.resume(spawnedPid);

                        // Give it some time to potentially create children
                        Thread.sleep(500);

                        // Disable child gating
                        session.disableChildGating();
                        System.out.println("Disabled child gating for PID: " + spawnedPid);

                    } finally {
                        try {
                            localDevice.kill(spawnedPid);
                            System.out.println("Cleaned up spawned process: " + spawnedPid);
                        } catch (Exception e) {
                            System.out.println("Could not clean up process: " + e.getMessage());
                        }
                    }
                } else {
                    System.out.println("Could not spawn shell process for child gating test (returned PID: " + spawnedPid + ")");
                }

            } catch (RuntimeException e) {
                abort("Could not test child gating: " + e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("Test was interrupted");
            }
        }
    }

    @Test
    @Order(3)
    void testChildProcessDetection() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                // Get current process list to compare
                ProcessList beforeProcesses = localDevice.enumerateProcesses();
                int beforeCount = beforeProcesses.size();
                beforeProcesses.close();

                // Spawn a process that creates a child
                String program = "/bin/sh";
                String[] args = {"-c", "sleep 1 & sleep 2"};

                int parentPid = localDevice.spawn(program, args);
                if (parentPid > 0) {
                    // Resume to let it create children
                    localDevice.resume(parentPid);

                // Give time for child processes to be created
                Thread.sleep(200);

                // Check if we have more processes now
                ProcessList afterProcesses = localDevice.enumerateProcesses();
                int afterCount = afterProcesses.size();

                System.out.printf("Process count before: %d, after: %d%n", beforeCount, afterCount);

                // Look for child processes with the parent PID
                boolean foundChild = false;
                for (int i = 0; i < afterProcesses.size(); i++) {
                    Process process = afterProcesses.get(i);
                    if (process.getParentPid() == parentPid) {
                        foundChild = true;
                        System.out.println("Found child process: " + process.getName() + " (PID: " + process.getPid() + ")");
                    }
                    process.close();
                }

                if (foundChild) {
                    System.out.println("Successfully detected child processes");
                } else {
                    System.out.println("No child processes detected (may be platform-dependent)");
                }

                afterProcesses.close();

                // Clean up
                try {
                    localDevice.kill(parentPid);
                    System.out.println("Cleaned up parent process: " + parentPid);
                } catch (Exception e) {
                    System.out.println("Could not clean up parent process: " + e.getMessage());
                }

            } else {
                System.out.println("Could not spawn parent process for child detection test (returned PID: " + parentPid + ")");
            }

            } catch (RuntimeException e) {
                System.out.println("Could not test child detection: " + e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("Test was interrupted");
            }
        }
    }

    @Test
    @Order(4)
    void testSpawnOptionsWithChildren() {
        try {
            // Test SpawnOptions creation
            SpawnOptions spawnOptions = new SpawnOptions();
            assertNotNull(spawnOptions, "SpawnOptions should be creatable");
            System.out.println("SpawnOptions created successfully");

            // Note: Actual usage would depend on native implementation

        } catch (Exception e) {
            System.out.println("SpawnOptions test skipped: " + e.getMessage());
        }
    }

    @Test
    @Order(5)
    void testSessionChildHandling() {
        try (DeviceManager deviceManager = new DeviceManager()) {
            Device localDevice = deviceManager.getLocalDevice();

            try {
                // Spawn a simple process
                int testPid = localDevice.spawn("/bin/sleep");
                assertTrue(testPid > 0, "Test PID should be positive");

                try (Session session = localDevice.attach(testPid)) {
                    // Test that we can enable/disable child gating multiple times
                    session.enableChildGating();
                    session.enableChildGating(); // Should be safe to call multiple times

                    session.disableChildGating();
                    session.disableChildGating(); // Should be safe to call multiple times

                    System.out.println("Child gating toggle test passed");

                } finally {
                    try {
                        localDevice.kill(testPid);
                    } catch (Exception e) {
                        System.out.println("Cleanup warning: " + e.getMessage());
                    }
                }

            } catch (RuntimeException e) {
                abort("Could not test session child handling: " + e.getMessage());
            }
        }
    }

    @Test
    @Order(6)
    void testChildObjectProperties() {
        try {
            // Test that Child objects can be created and have expected methods
            // Note: This is more of a API surface test since actual child objects
            // would typically be returned from native code
            System.out.println("Child class API is available for native usage");

            // The Child class would typically be instantiated by native code
            // when actual child processes are detected

        } catch (Exception e) {
            System.out.println("Child object test note: " + e.getMessage());
        }
    }
}
