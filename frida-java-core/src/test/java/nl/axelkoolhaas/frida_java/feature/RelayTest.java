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

/** Tests for Relay class */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class RelayTest {

  @Test
  @Order(1)
  void testCreateRelayWithAllParameters() {
    String address = "turn:relay.example.com:3478";
    String username = "testuser";
    String password = "testpass";

    try (Relay relay = new Relay(address, username, password, RelayKind.TURN_UDP)) {
      assertNotNull(relay, "Relay should not be null");
      assertEquals(address, relay.getAddress(), "Address should match");
      assertEquals(username, relay.getUsername(), "Username should match");
      assertEquals(password, relay.getPassword(), "Password should match");
      assertEquals(RelayKind.TURN_UDP, relay.getKind(), "Kind should be TURN_UDP");

      System.out.println("Relay created with all parameters");
    }
  }

  @Test
  @Order(2)
  void testCreateRelayWithNullCredentials() {
    String address = "turn:public-relay.example.com:3478";

    try (Relay relay = new Relay(address, null, null, RelayKind.TURN_TCP)) {
      assertNotNull(relay, "Relay should not be null");
      assertEquals(address, relay.getAddress(), "Address should match");
      assertEquals(RelayKind.TURN_TCP, relay.getKind(), "Kind should be TURN_TCP");

      System.out.println("Relay created without credentials");
    }
  }

  @Test
  @Order(3)
  void testCreateRelayWithDifferentKinds() {
    String address = "turn:relay.example.com:3478";

    // Test TURN_UDP
    try (Relay relay = new Relay(address, "user", "pass", RelayKind.TURN_UDP)) {
      assertEquals(RelayKind.TURN_UDP, relay.getKind());
      System.out.println("TURN_UDP relay validated");
    }

    // Test TURN_TCP
    try (Relay relay = new Relay(address, "user", "pass", RelayKind.TURN_TCP)) {
      assertEquals(RelayKind.TURN_TCP, relay.getKind());
      System.out.println("TURN_TCP relay validated");
    }

    // Test TURN_TLS
    try (Relay relay = new Relay(address, "user", "pass", RelayKind.TURN_TLS)) {
      assertEquals(RelayKind.TURN_TLS, relay.getKind());
      System.out.println("TURN_TLS relay validated");
    }
  }

  @Test
  @Order(4)
  void testNullAddressThrowsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Relay(null, "user", "pass", RelayKind.TURN_UDP),
        "Should throw IllegalArgumentException for null address");

    System.out.println("Null address validation successful");
  }

  @Test
  @Order(5)
  void testNullKindThrowsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Relay("turn:relay.example.com:3478", "user", "pass", null),
        "Should throw IllegalArgumentException for null RelayKind");

    System.out.println("Null kind validation successful");
  }

  @Test
  @Order(6)
  void testMultipleRelayInstances() {
    try (Relay relay1 = new Relay("turn:relay1.com:3478", "user1", "pass1", RelayKind.TURN_UDP);
        Relay relay2 = new Relay("turn:relay2.com:3478", "user2", "pass2", RelayKind.TURN_TCP)) {

      assertEquals("turn:relay1.com:3478", relay1.getAddress());
      assertEquals("user1", relay1.getUsername());
      assertEquals(RelayKind.TURN_UDP, relay1.getKind());

      assertEquals("turn:relay2.com:3478", relay2.getAddress());
      assertEquals("user2", relay2.getUsername());
      assertEquals(RelayKind.TURN_TCP, relay2.getKind());

      System.out.println("Multiple independent Relay instances validated");
    }
  }

  @Test
  @Order(7)
  void testDifferentAddressFormats() {
    String[] addresses = {
      "turn:relay.example.com:3478",
      "turns:secure-relay.example.com:5349",
      "turn:192.168.1.100:3478",
      "turn:[2001:db8::1]:3478"
    };

    for (String address : addresses) {
      try (Relay relay = new Relay(address, null, null, RelayKind.TURN_UDP)) {
        assertEquals(address, relay.getAddress());
      }
    }

    System.out.println("Different address formats validated");
  }

  @Test
  @Order(8)
  void testAutoCloseable() {
    Relay relay = new Relay("turn:relay.example.com:3478", "user", "pass", RelayKind.TURN_TLS);
    relay.close();
    System.out.println("AutoCloseable pattern validated");
  }
}
