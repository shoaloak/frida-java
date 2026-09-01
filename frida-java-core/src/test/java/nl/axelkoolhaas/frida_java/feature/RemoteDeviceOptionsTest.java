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

import org.junit.jupiter.api.*;

import nl.axelkoolhaas.frida_java.frida.*;

/** Tests for RemoteDeviceOptions class */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class RemoteDeviceOptionsTest {

  @Test
  @Order(1)
  void testCreateRemoteDeviceOptions() {
    try (RemoteDeviceOptions options = new RemoteDeviceOptions()) {
      assertNotNull(options, "RemoteDeviceOptions should not be null");
      System.out.println("RemoteDeviceOptions created successfully");
    }
  }

  @Test
  @Order(2)
  void testSetAndGetOrigin() {
    try (RemoteDeviceOptions options = new RemoteDeviceOptions()) {
      String origin = "https://example.com";
      options.setOrigin(origin);
      assertEquals(origin, options.getOrigin(), "Origin should match");

      String anotherOrigin = "https://test.example.org";
      options.setOrigin(anotherOrigin);
      assertEquals(anotherOrigin, options.getOrigin(), "Updated origin should match");

      System.out.println("Origin get/set operations validated");
    }
  }

  @Test
  @Order(3)
  void testSetAndGetToken() {
    try (RemoteDeviceOptions options = new RemoteDeviceOptions()) {
      String token = "secret-token-12345";
      options.setToken(token);
      assertEquals(token, options.getToken(), "Token should match");

      String anotherToken = "another-secret-67890";
      options.setToken(anotherToken);
      assertEquals(anotherToken, options.getToken(), "Updated token should match");

      System.out.println("Token get/set operations validated");
    }
  }

  @Test
  @Order(4)
  void testSetAndGetKeepaliveInterval() {
    try (RemoteDeviceOptions options = new RemoteDeviceOptions()) {
      options.setKeepaliveInterval(30);
      assertEquals(30, options.getKeepaliveInterval(), "Keepalive interval should be 30");

      options.setKeepaliveInterval(60);
      assertEquals(60, options.getKeepaliveInterval(), "Keepalive interval should be 60");

      options.setKeepaliveInterval(0);
      assertEquals(0, options.getKeepaliveInterval(), "Keepalive interval should be 0");

      System.out.println("Keepalive interval get/set operations validated");
    }
  }

  @Test
  @Order(5)
  void testCombinedOptions() {
    try (RemoteDeviceOptions options = new RemoteDeviceOptions()) {
      String origin = "https://frida.example.com";
      String token = "auth-token-xyz";
      int interval = 45;

      options.setOrigin(origin);
      options.setToken(token);
      options.setKeepaliveInterval(interval);

      assertEquals(origin, options.getOrigin());
      assertEquals(token, options.getToken());
      assertEquals(interval, options.getKeepaliveInterval());

      System.out.println("Combined remote device options validated");
    }
  }

  @Test
  @Order(6)
  void testDefaultValues() {
    try (RemoteDeviceOptions options = new RemoteDeviceOptions()) {
      assertNotNull(options.getOrigin(), "Default origin should not be null");
      assertNotNull(options.getToken(), "Default token should not be null");
      // Default keepalive interval may be -1 or 0
      int defaultInterval = options.getKeepaliveInterval();
      System.out.println("Default keepalive interval: " + defaultInterval);

      System.out.println("Default values validated");
    }
  }

  @Test
  @Order(7)
  void testMultipleInstances() {
    try (RemoteDeviceOptions options1 = new RemoteDeviceOptions();
        RemoteDeviceOptions options2 = new RemoteDeviceOptions()) {

      options1.setOrigin("https://device1.com");
      options1.setToken("token1");
      options1.setKeepaliveInterval(10);

      options2.setOrigin("https://device2.com");
      options2.setToken("token2");
      options2.setKeepaliveInterval(20);

      // Verify instances are independent
      assertEquals("https://device1.com", options1.getOrigin());
      assertEquals("token1", options1.getToken());
      assertEquals(10, options1.getKeepaliveInterval());

      assertEquals("https://device2.com", options2.getOrigin());
      assertEquals("token2", options2.getToken());
      assertEquals(20, options2.getKeepaliveInterval());

      System.out.println("Multiple independent RemoteDeviceOptions instances validated");
    }
  }

  @Test
  @Order(8)
  void testGetCertificateWithoutSetting() {
    try (RemoteDeviceOptions options = new RemoteDeviceOptions()) {
      Certificate cert = options.getCertificate();
      // Certificate may be null if not set
      System.out.println("Certificate retrieval validated (may be null): " + cert);
    }
  }
}
