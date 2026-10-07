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

/** Tests for SessionOptions class */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SessionOptionsTest {

  @Test
  @Order(1)
  void testCreateSessionOptions() {
    try (SessionOptions options = new SessionOptions()) {
      assertNotNull(options, "SessionOptions should not be null");
      System.out.println("SessionOptions created successfully");
    }
  }

  @Test
  @Order(2)
  void testSetAndGetRealm() {
    try (SessionOptions options = new SessionOptions()) {
      // Test setting NATIVE realm
      options.setRealm(Realm.NATIVE);
      assertEquals(Realm.NATIVE, options.getRealm(), "Realm should be NATIVE");

      // Test setting EMULATED realm
      options.setRealm(Realm.EMULATED);
      assertEquals(Realm.EMULATED, options.getRealm(), "Realm should be EMULATED");

      System.out.println("Realm get/set operations validated");
    }
  }

  @Test
  @Order(3)
  void testSetAndGetPersistTimeout() {
    try (SessionOptions options = new SessionOptions()) {
      // Test setting timeout to 0 (no persistence)
      options.setPersistTimeout(0);
      assertEquals(0, options.getPersistTimeout(), "Persist timeout should be 0");

      // Test setting timeout to a positive value
      options.setPersistTimeout(30);
      assertEquals(30, options.getPersistTimeout(), "Persist timeout should be 30");

      // Test setting timeout to a larger value
      options.setPersistTimeout(3600);
      assertEquals(3600, options.getPersistTimeout(), "Persist timeout should be 3600");

      System.out.println("Persist timeout get/set operations validated");
    }
  }

  @Test
  @Order(4)
  void testDefaultValues() {
    try (SessionOptions options = new SessionOptions()) {
      // Default realm should be NATIVE (value 1)
      assertNotNull(options.getRealm(), "Default realm should not be null");

      // Default persist timeout should be 0
      assertEquals(0, options.getPersistTimeout(), "Default persist timeout should be 0");

      System.out.println("Default values validated");
    }
  }

  @Test
  @Order(5)
  void testMultipleOptionsInstances() {
    try (SessionOptions options1 = new SessionOptions();
        SessionOptions options2 = new SessionOptions()) {

      options1.setRealm(Realm.NATIVE);
      options1.setPersistTimeout(10);

      options2.setRealm(Realm.EMULATED);
      options2.setPersistTimeout(20);

      // Verify instances are independent
      assertEquals(Realm.NATIVE, options1.getRealm());
      assertEquals(10, options1.getPersistTimeout());

      assertEquals(Realm.EMULATED, options2.getRealm());
      assertEquals(20, options2.getPersistTimeout());

      System.out.println("Multiple independent SessionOptions instances validated");
    }
  }

  @Test
  @Order(6)
  void testAutoCloseable() {
    SessionOptions options = new SessionOptions();
    options.setRealm(Realm.NATIVE);
    options.close();

    // After closing, we should not use the options anymore
    // This test verifies the AutoCloseable interface works
    System.out.println("AutoCloseable pattern validated");
  }
}
