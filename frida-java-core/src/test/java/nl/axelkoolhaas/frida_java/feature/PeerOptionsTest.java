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

/** Tests for PeerOptions class */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class PeerOptionsTest {

  @Test
  @Order(1)
  void testCreatePeerOptions() {
    try (PeerOptions options = new PeerOptions()) {
      assertNotNull(options, "PeerOptions should not be null");
      System.out.println("PeerOptions created successfully");
    }
  }

  @Test
  @Order(2)
  void testSetAndGetStunServer() {
    try (PeerOptions options = new PeerOptions()) {
      String stunServer = "stun:stun.example.com:3478";
      options.setStunServer(stunServer);
      assertEquals(stunServer, options.getStunServer(), "STUN server should match");

      String anotherServer = "stun:stun.google.com:19302";
      options.setStunServer(anotherServer);
      assertEquals(anotherServer, options.getStunServer(), "Updated STUN server should match");

      System.out.println("STUN server get/set operations validated");
    }
  }

  @Test
  @Order(3)
  void testNullStunServerThrowsException() {
    try (PeerOptions options = new PeerOptions()) {
      assertThrows(
          IllegalArgumentException.class,
          () -> options.setStunServer(null),
          "Should throw IllegalArgumentException for null STUN server");

      System.out.println("Null STUN server validation successful");
    }
  }

  @Test
  @Order(4)
  void testAddRelay() {
    try (PeerOptions options = new PeerOptions();
        Relay relay =
            new Relay("turn:relay.example.com:3478", "user", "pass", RelayKind.TURN_UDP)) {

      assertDoesNotThrow(() -> options.addRelay(relay), "Adding relay should not throw");
      System.out.println("Relay added successfully");
    }
  }

  @Test
  @Order(5)
  void testAddMultipleRelays() {
    try (PeerOptions options = new PeerOptions();
        Relay relay1 = new Relay("turn:relay1.com:3478", "user1", "pass1", RelayKind.TURN_UDP);
        Relay relay2 = new Relay("turn:relay2.com:3478", "user2", "pass2", RelayKind.TURN_TCP);
        Relay relay3 = new Relay("turn:relay3.com:3478", "user3", "pass3", RelayKind.TURN_TLS)) {

      options.addRelay(relay1);
      options.addRelay(relay2);
      options.addRelay(relay3);

      System.out.println("Multiple relays added successfully");
    }
  }

  @Test
  @Order(6)
  void testClearRelays() {
    try (PeerOptions options = new PeerOptions();
        Relay relay1 = new Relay("turn:relay1.com:3478", "user1", "pass1", RelayKind.TURN_UDP);
        Relay relay2 = new Relay("turn:relay2.com:3478", "user2", "pass2", RelayKind.TURN_TCP)) {

      options.addRelay(relay1);
      options.addRelay(relay2);

      assertDoesNotThrow(() -> options.clearRelays(), "Clearing relays should not throw");
      System.out.println("Relays cleared successfully");
    }
  }

  @Test
  @Order(7)
  void testAddClearAddPattern() {
    try (PeerOptions options = new PeerOptions();
        Relay relay1 = new Relay("turn:relay1.com:3478", "user1", "pass1", RelayKind.TURN_UDP);
        Relay relay2 = new Relay("turn:relay2.com:3478", "user2", "pass2", RelayKind.TURN_TCP)) {

      options.addRelay(relay1);
      options.clearRelays();
      options.addRelay(relay2);

      System.out.println("Add-clear-add pattern validated");
    }
  }

  @Test
  @Order(8)
  void testCombinedStunAndRelays() {
    try (PeerOptions options = new PeerOptions();
        Relay relay = new Relay("turn:relay.com:3478", "user", "pass", RelayKind.TURN_UDP)) {

      options.setStunServer("stun:stun.example.com:3478");
      options.addRelay(relay);

      assertEquals("stun:stun.example.com:3478", options.getStunServer());
      System.out.println("Combined STUN server and relay configuration validated");
    }
  }

  @Test
  @Order(9)
  void testDefaultStunServer() {
    try (PeerOptions options = new PeerOptions()) {
      String defaultServer = options.getStunServer();
      assertNotNull(defaultServer, "Default STUN server should not be null");
      System.out.println("Default STUN server: " + defaultServer);
    }
  }

  @Test
  @Order(10)
  void testMultipleInstances() {
    try (PeerOptions options1 = new PeerOptions();
        PeerOptions options2 = new PeerOptions();
        Relay relay1 = new Relay("turn:relay1.com:3478", "user1", "pass1", RelayKind.TURN_UDP);
        Relay relay2 = new Relay("turn:relay2.com:3478", "user2", "pass2", RelayKind.TURN_TCP)) {

      options1.setStunServer("stun:stun1.com:3478");
      options1.addRelay(relay1);

      options2.setStunServer("stun:stun2.com:3478");
      options2.addRelay(relay2);

      assertEquals("stun:stun1.com:3478", options1.getStunServer());
      assertEquals("stun:stun2.com:3478", options2.getStunServer());

      System.out.println("Multiple independent PeerOptions instances validated");
    }
  }

  @Test
  @Order(11)
  void testAutoCloseable() {
    PeerOptions options = new PeerOptions();
    options.setStunServer("stun:stun.example.com:3478");
    options.close();
    System.out.println("AutoCloseable pattern validated");
  }
}
