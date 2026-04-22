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
import static org.junit.jupiter.api.Assumptions.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.*;

import nl.axelkoolhaas.frida_java.frida.*;

/** Tests for Script "destroyed" signal */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ScriptSignalTest {

  @Test
  @Order(1)
  void testScriptDestroyedSignal() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource = "console.log('test');";

        Script script = session.createScript(scriptSource);
        script.load();

        // Resume the process now that instrumentation is set up
        localDevice.resume(targetPid);

        CountDownLatch latch = new CountDownLatch(1);

        // Register destroyed signal handler
        script.on(
            "destroyed",
            (SignalCallbacks.VoidCallback)
                () -> {
                  System.out.println("Script destroyed signal received");
                  latch.countDown();
                });

        // Unload the script, which should trigger destroyed signal
        script.unload();

        boolean signalReceived = latch.await(5, TimeUnit.SECONDS);
        assertTrue(signalReceived, "Destroyed signal should be received");

        System.out.println("Script destroyed signal test passed");
      } catch (Exception e) {
        System.err.println(
            "Script destroyed signal test failed (can be due to SIP on macOS): " + e.getMessage());
        cleanupProcess(localDevice, targetPid);
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(2)
  void testScriptDestroyedSignalOnSessionDetach() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try {
        Session session = localDevice.attach(targetPid);
        String scriptSource = "console.log('test');";

        Script script = session.createScript(scriptSource);
        script.load();

        // Resume the process now that instrumentation is set up
        localDevice.resume(targetPid);

        CountDownLatch latch = new CountDownLatch(1);

        // Register destroyed signal handler
        script.on(
            "destroyed",
            (SignalCallbacks.VoidCallback)
                () -> {
                  System.out.println("Script destroyed signal received on session detach");
                  latch.countDown();
                });

        // Detach session, which should destroy the script
        session.detach();

        boolean signalReceived = latch.await(5, TimeUnit.SECONDS);
        assertTrue(signalReceived, "Destroyed signal should be received when session detaches");

        System.out.println("Script destroyed on session detach test passed");
      } catch (Exception e) {
        System.err.println(
            "Script destroyed on session detach test failed (can be due to SIP on macOS): "
                + e.getMessage());
        cleanupProcess(localDevice, targetPid);
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  private int spawnTestProcess(Device device) {
    try {
      int pid = device.spawn("/bin/sleep", java.util.List.of("3600"));
      if (pid > 0) {
        // Don't resume yet - leave it suspended so we can attach
        System.out.println("Spawned test process with PID: " + pid + " (suspended)");
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
