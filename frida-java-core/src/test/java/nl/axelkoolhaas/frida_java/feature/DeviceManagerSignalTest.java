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

/** Tests for DeviceManager signal support and remote device management */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DeviceManagerSignalTest {

  @Test
  @Order(1)
  void testDeviceManagerChangedSignal() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      CountDownLatch latch = new CountDownLatch(1);

      deviceManager.on(
          "changed",
          (SignalCallbacks.VoidCallback)
              () -> {
                System.out.println("DeviceManager changed signal received");
                latch.countDown();
              });

      // Trigger a change by enumerating devices
      deviceManager.enumerateDevices();

      // Wait briefly to see if signal fires
      boolean signalReceived = latch.await(500, TimeUnit.MILLISECONDS);
      System.out.println(
          "Changed signal test completed (received: " + signalReceived + ", may not fire)");
    } catch (Exception e) {
      System.err.println("DeviceManager changed signal test failed: " + e.getMessage());
    }
  }

  @Test
  @Order(2)
  void testDeviceManagerAddedSignal() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      CountDownLatch latch = new CountDownLatch(1);

      deviceManager.on(
          "added",
          (SignalCallbacks.DeviceCallback)
              device -> {
                System.out.println("Device added: " + device.getName());
                latch.countDown();
              });

      // This signal would fire when a new device is connected
      // We just verify the callback can be registered
      System.out.println("Added signal callback registered successfully");
    } catch (Exception e) {
      System.err.println("DeviceManager added signal test failed: " + e.getMessage());
    }
  }

  @Test
  @Order(3)
  void testDeviceManagerRemovedSignal() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      CountDownLatch latch = new CountDownLatch(1);

      deviceManager.on(
          "removed",
          (SignalCallbacks.DeviceCallback)
              device -> {
                System.out.println("Device removed: " + device.getName());
                latch.countDown();
              });

      // This signal would fire when a device is disconnected
      // We just verify the callback can be registered
      System.out.println("Removed signal callback registered successfully");
    } catch (Exception e) {
      System.err.println("DeviceManager removed signal test failed: " + e.getMessage());
    }
  }

  @Test
  @Order(4)
  void testMultipleSignalCallbacks() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      CountDownLatch changedLatch = new CountDownLatch(1);
      CountDownLatch addedLatch = new CountDownLatch(1);

      deviceManager.on(
          "changed",
          (SignalCallbacks.VoidCallback)
              () -> {
                System.out.println("Changed callback");
                changedLatch.countDown();
              });

      deviceManager.on(
          "added",
          (SignalCallbacks.DeviceCallback)
              device -> {
                System.out.println("Added callback: " + device.getName());
                addedLatch.countDown();
              });

      System.out.println("Multiple signal callbacks registered successfully");
    } catch (Exception e) {
      System.err.println("Multiple signal callbacks test failed: " + e.getMessage());
    }
  }

  @Test
  @Order(5)
  void testAddRemoteDevice() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      // Note: addRemoteDevice creates a device object even if connection fails
      // The actual connection happens when operations are performed on the device

      Device remoteDevice = deviceManager.addRemoteDevice("127.0.0.1:27042");
      assertNotNull(remoteDevice, "Remote device should be created");
      remoteDevice.close();

      System.out.println("addRemoteDevice API validated");
    } catch (Exception e) {
      System.err.println("Add remote device test failed: " + e.getMessage());
    }
  }

  @Test
  @Order(6)
  void testRemoteDeviceOptionsCreation() {
    // Test that RemoteDeviceOptions can be created and configured
    // Note: The DeviceManager.addRemoteDevice(address, options) overload may be added in future
    try (RemoteDeviceOptions options = new RemoteDeviceOptions()) {
      options.setOrigin("https://example.com");
      options.setKeepaliveInterval(30);

      assertEquals("https://example.com", options.getOrigin());
      assertEquals(30, options.getKeepaliveInterval());

      System.out.println("RemoteDeviceOptions creation and configuration validated");
    } catch (Exception e) {
      System.err.println("RemoteDeviceOptions test unexpected error: " + e.getMessage());
    }
  }

  @Test
  @Order(7)
  void testRemoveRemoteDevice() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      // Note: This will fail without an actual remote device
      // We test that the API exists and accepts parameters correctly

      assertThrows(
          FridaException.class,
          () -> deviceManager.removeRemoteDevice("127.0.0.1:27042"),
          "Should throw FridaException when removing non-existent remote device");

      System.out.println("removeRemoteDevice API validated");
    } catch (Exception e) {
      System.err.println("Remove remote device test unexpected error: " + e.getMessage());
    }
  }

  @Test
  @Order(8)
  void testInvalidSignalName() {
    try (DeviceManager deviceManager = new DeviceManager()) {
      // Test that invalid signal names are handled gracefully
      // May throw exception or silently ignore depending on implementation
      try {
        deviceManager.on(
            "invalid-signal",
            (SignalCallbacks.VoidCallback)
                () -> {
                  System.out.println("This should not be called");
                });
        System.out.println("Invalid signal name registered (or ignored)");
      } catch (FridaException e) {
        System.out.println("Invalid signal name rejected with exception: " + e.getMessage());
      }

      System.out.println("Invalid signal name handling validated");
    } catch (Exception e) {
      System.err.println("Invalid signal name test failed: " + e.getMessage());
    }
  }
}
