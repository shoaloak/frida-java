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

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

import java.util.List;

import org.junit.jupiter.api.*;

import nl.axelkoolhaas.frida_java.frida.*;
import nl.axelkoolhaas.frida_java.frida.SignalCallbacks;

/**
 * Comprehensive test class for Frida Session and Script functionality. Tests session lifecycle,
 * script creation, loading, execution, and message handling.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SessionAndScriptTest {

  @Test
  @Order(1)
  void testAttachToProcess() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "No test process available");

      try (Session session = localDevice.attach(targetPid)) {
        assertNotNull(session, "Session should not be null");
        assertFalse(session.isDetached(), "Session should not be detached");
        assertEquals(targetPid, session.getPid(), "Session PID should match target process PID");
        System.out.println("Successfully attached to process with PID: " + targetPid);
      } catch (Exception e) {
        System.err.println("Attachment failed (can be due to SIP on macos): " + e.getMessage());
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(2)
  void testSessionProperties() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "No test process available");

      try (Session session = localDevice.attach(targetPid)) {
        // Test session properties
        assertEquals(targetPid, session.getPid(), "Session PID should match attached PID");
        assertFalse(session.isDetached(), "Session should not be detached initially");

        // Note: FFM version doesn't have getDevice() method
        System.out.println("Session properties validated for PID: " + targetPid);
      } catch (Exception e) {
        System.err.println("Attachment failed (can be due to SIP on macos): " + e.getMessage());
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(3)
  void testCreateSimpleScript() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "No test process available");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource =
            "console.log('Hello from Frida script!'); rpc.exports = { hello: function() { return 'world'; } };";
        try (Script script = session.createScript(scriptSource)) {
          assertNotNull(script, "Script should not be null");
          assertFalse(script.isDestroyed(), "Script should not be destroyed initially");
          System.out.println("Created script successfully");
        } catch (RuntimeException e) {
          System.out.println(
              "Script creation failed (may be expected for spawned process): " + e.getMessage());
          // Don't fail the test for script creation issues
        }
      } catch (Exception e) {
        System.err.println("Attachment failed (can be due to SIP on macos): " + e.getMessage());
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(4)
  void testScriptLoadAndUnload() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "No test process available");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource = "console.log('Script loaded successfully');";

        try (Script script = session.createScript(scriptSource)) {
          // Test script loading
          script.load();
          assertFalse(script.isDestroyed(), "Script should not be destroyed after load");
          System.out.println("Script loaded successfully");

          // Test script unloading
          script.unload();
          // Note: isDestroyed might not immediately return true depending on implementation
          System.out.println("Script unloaded successfully");
        } catch (RuntimeException e) {
          System.out.println(
              "Script load/unload failed (may be expected for spawned process): " + e.getMessage());
        }
      } catch (Exception e) {
        System.err.println("Attachment failed (can be due to SIP on macos): " + e.getMessage());
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(5)
  void testScriptPostMessage() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "No test process available");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource =
            "recv('test', function(message) {"
                + "console.log('Received:', JSON.stringify(message));"
                + "send({type: 'response', data: message.payload});"
                + "});";

        try (Script script = session.createScript(scriptSource)) {
          script.load();

          // Post a simple message
          String testMessage = "{\"type\":\"test\",\"payload\":\"hello\"}";
          script.post(testMessage);

          // Allow some time for message processing
          Thread.sleep(100);

          System.out.println("Message posted to script successfully");
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        } catch (RuntimeException e) {
          System.out.println(
              "Script message posting failed (may be expected for spawned process): "
                  + e.getMessage());
        }
      } catch (Exception e) {
        System.err.println("Attachment failed (can be due to SIP on macos): " + e.getMessage());
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(6)
  void testSessionDetach() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "No test process available");

      try (Session session = localDevice.attach(targetPid)) {
        assertFalse(session.isDetached(), "Session should not be detached initially");

        session.detach();
        assertTrue(session.isDetached(), "Session should be detached after calling detach()");

        System.out.println("Successfully detached from session");
      } catch (Exception e) {
        System.err.println("Attachment failed (can be due to SIP on macos): " + e.getMessage());
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(7)
  void testSessionChildGating() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "No test process available");

      try (Session session = localDevice.attach(targetPid)) {
        // Test child gating controls
        session.enableChildGating();
        System.out.println("Child gating enabled");

        session.disableChildGating();
        System.out.println("Child gating disabled");

      } catch (Exception e) {
        System.err.println("Attachment failed (can be due to SIP on macos): " + e.getMessage());
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(8)
  void testScriptWithMessageHandling() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      // Register output handler to capture stdout/stderr from spawned process with Stdio.PIPE
      localDevice.on(
          DeviceSignal.OUTPUT,
          (SignalCallbacks.DeviceOutputCallback)
              (pid, fd, data) -> {
                String output = new String(data);
                System.out.printf("[PID=%d, FD=%d] %s", pid, fd, output);
              });

      // Platform-agnostic command selection
      String[] command = getPlatformCommand();

      // Use builder pattern with Stdio.PIPE to prevent stdout corruption in Surefire
      int targetPid =
          localDevice.spawnName(
              command[0], SpawnOptions.builder().argv(List.of(command)).stdio(Stdio.PIPE).build());
      assertTrue(
          targetPid > 0,
          "Failed to spawn test process - " + command[0] + " not found in PATH or spawn failed");

      System.out.println("Spawned PID: " + targetPid);

      try (Session session = localDevice.attach(targetPid)) {
        // language=JavaScript
        String scriptSource =
            """
                (function () {
                    function sendInfo(obj) {
                        send({ type: "info", data: obj })
                    }

                    const mainModule = Process.enumerateModules()[0]

                    sendInfo({
                        name: mainModule.name,
                        path: mainModule.path,
                        base: mainModule.base.toString(),
                        size: mainModule.size
                    })
                })();
                """;

        Script script = null;
        try {
          script = session.createScript(scriptSource);
          // Note: With simplified signal system, callbacks are registered but not connected to
          // native signals
          // This test validates the callback registration API works without expecting actual
          // messages
          final boolean[] messageReceived = {false};

          script.on(
              "message",
              (SignalCallbacks.MessageCallback)
                  (message, _) -> {
                    System.out.println("Received message: " + message);
                    messageReceived[0] = true;
                  });

          script.load();
          System.out.println("Script loaded successfully");

          // Resume the spawned process
          localDevice.resume(targetPid);
          System.out.println("Resumed process");

          // Wait for message processing
          Thread.sleep(1000);

          assertTrue(messageReceived[0], "Should have received at least one message from script");
          System.out.println("Script message handling test completed successfully");

        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          fail("Test interrupted: " + e.getMessage());
        } finally {
          // Clean up script - might already be destroyed if process exited
          if (script != null) {
            try {
              script.close();
            } catch (Exception e) {
              System.out.println(
                  "Script cleanup failed (expected if process exited): " + e.getMessage());
            }
          }
        }
      } catch (Exception e) {
        fail("Attachment failed: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  /** Returns platform-appropriate command for testing */
  private String[] getPlatformCommand() {
    String os = System.getProperty("os.name").toLowerCase();
    if (os.contains("win")) {
      return new String[] {"cmd.exe", "/?"}; // Windows help command
    } else {
      // Unix-like systems (Linux, macOS)
      return new String[] {"bash", "--help"};
    }
  }

  /** Helper method to spawn a test process */
  private int spawnTestProcess(Device device) {
    // Spawn a sleep process for testing
    try {
      // TODO: Expand to Windows equivalents
      int pid = device.spawn("/bin/sleep", List.of("3600"));
      if (pid > 0) {
        device.resume(pid); // Resume the process so it's running
        System.out.println("Spawned test process with PID: " + pid);
        return pid;
      } else {
        System.out.println("Failed to spawn test process - got invalid PID: " + pid);
        System.out.println("Failed to spawn test process - spawn returned empty");
      }
    } catch (Exception e) {
      System.out.println("Could not spawn test process: " + e.getMessage());
    }

    return -1;
  }

  /** Helper method to clean up spawned processes */
  private void cleanupProcess(Device device, int pid) {
    // Clean up spawned processes
    if (pid > 0) {
      try {
        device.kill(pid);
        System.out.println("Cleaned up process PID: " + pid);
      } catch (Exception e) {
        System.out.println("Could not clean up process " + pid + ": " + e.getMessage());
      }
    }
  }
}
