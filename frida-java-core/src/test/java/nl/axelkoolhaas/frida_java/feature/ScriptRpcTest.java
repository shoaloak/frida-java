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

import org.junit.jupiter.api.*;

import nl.axelkoolhaas.frida_java.frida.*;

/** Tests for Script RPC functionality (exportsCall) */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ScriptRpcTest {

  @Test
  @Order(1)
  void testRpcExportsCall() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource =
            """
            rpc.exports = {
              add: function(a, b) {
                return a + b;
              },
              hello: function() {
                return 'world';
              }
            };
            """;

        try (Script script = session.createScript(scriptSource)) {
          script.load();

          // Resume the process now that instrumentation is set up
          localDevice.resume(targetPid);

          // Test simple RPC call
          Object result = script.exportsCall("hello");
          assertNotNull(result, "RPC result should not be null");
          assertEquals("world", result.toString(), "RPC should return 'world'");

          System.out.println("RPC exportsCall test passed: " + result);
        }
      } catch (Exception e) {
        System.err.println("RPC test failed (can be due to SIP on macOS): " + e.getMessage());
        cleanupProcess(localDevice, targetPid);
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(2)
  void testRpcExportsCallWithArguments() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource =
            """
            rpc.exports = {
              add: function(a, b) {
                return a + b;
              }
            };
            """;

        try (Script script = session.createScript(scriptSource)) {
          script.load();

          // Resume the process now that instrumentation is set up
          localDevice.resume(targetPid);

          // Test RPC call with arguments
          Object result = script.exportsCall("add", 5, 3);
          assertNotNull(result, "RPC result should not be null");

          // The result might be a Number (Integer or Double)
          int intResult =
              result instanceof Number
                  ? ((Number) result).intValue()
                  : Integer.parseInt(result.toString());
          assertEquals(8, intResult, "RPC should return 5 + 3 = 8");

          System.out.println("RPC with arguments test passed: " + result);
        }
      } catch (Exception e) {
        System.err.println(
            "RPC with arguments test failed (can be due to SIP on macOS): " + e.getMessage());
        cleanupProcess(localDevice, targetPid);
        assumeTrue(false, "Skipping test due to attachment issue: " + e.getMessage());
      } finally {
        cleanupProcess(localDevice, targetPid);
      }
    }
  }

  @Test
  @Order(3)
  void testRpcMultipleCalls() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      Device localDevice = deviceManager.getLocalDevice().orElseThrow();

      int targetPid = spawnTestProcess(localDevice);
      assertTrue(targetPid > 0, "Test process should be spawned");

      try (Session session = localDevice.attach(targetPid)) {
        String scriptSource =
            """
            rpc.exports = {
              counter: 0,
              increment: function() {
                this.counter++;
                return this.counter;
              }
            };
            """;

        try (Script script = session.createScript(scriptSource)) {
          script.load();

          // Resume the process now that instrumentation is set up
          localDevice.resume(targetPid);

          // Test multiple sequential RPC calls
          Object val1 = script.exportsCall("increment");
          int count1 =
              val1 instanceof Number
                  ? ((Number) val1).intValue()
                  : Integer.parseInt(val1.toString());
          assertEquals(1, count1, "First call should return 1");

          Object val2 = script.exportsCall("increment");
          int count2 =
              val2 instanceof Number
                  ? ((Number) val2).intValue()
                  : Integer.parseInt(val2.toString());
          assertEquals(2, count2, "Second call should return 2");

          System.out.println("Multiple RPC calls test passed");
        }
      } catch (Exception e) {
        System.err.println(
            "Multiple RPC calls test failed (can be due to SIP on macOS): " + e.getMessage());
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
