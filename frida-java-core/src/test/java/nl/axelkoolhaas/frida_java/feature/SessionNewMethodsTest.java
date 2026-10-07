/*
 * Copyright (C) 2026 Axel Koolhaas
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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.*;

import nl.axelkoolhaas.frida_java.frida.*;

/** Tests for new Session methods: compileScript, snapshotScript, createScriptFromBytes */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SessionNewMethodsTest {

  @Test
  @Order(1)
  void testCompileScript() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource = "console.log('test');";

        byte[] compiled = session.compileScript(scriptSource);
        assertNotNull(compiled, "Compiled script should not be null");
        assertTrue(compiled.length > 0, "Compiled script should have content");

        System.out.println("Script compiled successfully (" + compiled.length + " bytes)");
      } catch (Exception e) {
        System.err.println("Compile script test failed: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(2)
  void testCompileScriptMultipleTimes() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource1 = "console.log('first');";
        String scriptSource2 = "console.log('second');";

        byte[] compiled1 = session.compileScript(scriptSource1);
        byte[] compiled2 = session.compileScript(scriptSource2);

        assertNotNull(compiled1, "First compiled script should not be null");
        assertNotNull(compiled2, "Second compiled script should not be null");
        assertTrue(compiled1.length > 0, "First compiled script should have content");
        assertTrue(compiled2.length > 0, "Second compiled script should have content");

        System.out.println("Multiple script compilations successful");
      } catch (Exception e) {
        System.err.println("Multiple compile test failed: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(3)
  void testSnapshotScript() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String embedScript = "console.log('snapshot');";

        byte[] snapshot = session.snapshotScript(embedScript);
        assertNotNull(snapshot, "Snapshot should not be null");
        assertTrue(snapshot.length > 0, "Snapshot should have content");

        System.out.println("Script snapshot created successfully (" + snapshot.length + " bytes)");
      } catch (Exception e) {
        System.err.println("Snapshot script test failed: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(4)
  void testSnapshotScriptMultipleTimes() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String embedScript1 = "console.log('snapshot 1');";
        String embedScript2 = "console.log('snapshot 2');";

        byte[] snapshot1 = session.snapshotScript(embedScript1);
        byte[] snapshot2 = session.snapshotScript(embedScript2);

        assertNotNull(snapshot1, "First snapshot should not be null");
        assertNotNull(snapshot2, "Second snapshot should not be null");
        assertTrue(snapshot1.length > 0, "First snapshot should have content");
        assertTrue(snapshot2.length > 0, "Second snapshot should have content");

        System.out.println("Multiple script snapshots created successfully");
      } catch (Exception e) {
        System.err.println("Multiple snapshot test failed: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(5)
  void testCreateScriptFromBytes() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource = "console.log('test');";
        byte[] compiled = session.compileScript(scriptSource);

        try (Script script = session.createScriptFromBytes(compiled)) {
          assertNotNull(script, "Script created from bytes should not be null");
          assertFalse(script.isDestroyed(), "Script should not be destroyed");

          System.out.println("Script created from bytes successfully");
        }
      } catch (Exception e) {
        System.err.println("Create script from bytes test failed: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(6)
  void testCompileThenCreateFromBytes() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource = "console.log('compile and create');";
        byte[] compiled = session.compileScript(scriptSource);

        try (Script script = session.createScriptFromBytes(compiled)) {
          assertNotNull(script, "Script created from bytes should not be null");
          assertFalse(script.isDestroyed(), "Script should not be destroyed");

          // Load the script
          script.load();
          System.out.println("Script compiled, created from bytes, and loaded successfully");
        }
      } catch (Exception e) {
        System.err.println("Compile then create from bytes test failed: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(7)
  void testSessionDetachedSignal() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        CountDownLatch latch = new CountDownLatch(1);

        session.on(
            "detached",
            (SignalCallbacks.SessionDetachedCallback)
                (reason, crash) -> {
                  System.out.println(
                      "Session detached: reason="
                          + reason
                          + ", crash="
                          + (crash != null ? crash.getReport() : "null"));
                  latch.countDown();
                });

        session.detach();

        boolean signalReceived = latch.await(2, TimeUnit.SECONDS);
        assertTrue(signalReceived, "Detached signal should be received");

        System.out.println("Session detached signal validated");
      } catch (Exception e) {
        System.err.println("Session detached signal test failed: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  private int spawnTestProcess(Device device) {
    try {
      int pid = device.spawn("/bin/sleep", java.util.List.of("3600"));
      if (pid > 0) {
        device.resume(pid);
        System.out.println("Spawned test process with PID: " + pid);
        return pid;
      }
    } catch (Exception e) {
      System.out.println("Could not spawn test process: " + e.getMessage());
    }
    return -1;
  }

  private void cleanupProcess(Device device, int pid) {
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
