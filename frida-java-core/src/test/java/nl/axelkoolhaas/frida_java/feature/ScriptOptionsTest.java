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

/** Tests for ScriptOptions class */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ScriptOptionsTest {

  @Test
  @Order(1)
  void testCreateScriptOptions() {
    try (ScriptOptions options = new ScriptOptions()) {
      assertNotNull(options, "ScriptOptions should not be null");
      System.out.println("ScriptOptions created successfully");
    }
  }

  @Test
  @Order(2)
  void testSetAndGetName() {
    try (ScriptOptions options = new ScriptOptions()) {
      String scriptName = "test-script";
      options.setName(scriptName);
      assertEquals(scriptName, options.getName(), "Script name should match");

      // Test with different name
      String anotherName = "my-instrumentation";
      options.setName(anotherName);
      assertEquals(anotherName, options.getName(), "Script name should be updated");

      System.out.println("Script name get/set operations validated");
    }
  }

  @Test
  @Order(3)
  void testSetAndGetSnapshot() {
    try (ScriptOptions options = new ScriptOptions()) {
      byte[] snapshot = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};
      options.setSnapshot(snapshot);

      byte[] retrieved = options.getSnapshot();
      assertNotNull(retrieved, "Retrieved snapshot should not be null");
      assertArrayEquals(snapshot, retrieved, "Snapshot bytes should match");

      System.out.println("Snapshot get/set operations validated");
    }
  }

  @Test
  @Order(4)
  void testSetAndGetSnapshotTransport() {
    try (ScriptOptions options = new ScriptOptions()) {
      // Test INLINE transport
      options.setSnapshotTransport(SnapshotTransport.INLINE);
      assertEquals(
          SnapshotTransport.INLINE,
          options.getSnapshotTransport(),
          "Snapshot transport should be INLINE");

      // Test SHARED_MEMORY transport
      options.setSnapshotTransport(SnapshotTransport.SHARED_MEMORY);
      assertEquals(
          SnapshotTransport.SHARED_MEMORY,
          options.getSnapshotTransport(),
          "Snapshot transport should be SHARED_MEMORY");

      System.out.println("Snapshot transport get/set operations validated");
    }
  }

  @Test
  @Order(5)
  void testSetAndGetRuntime() {
    try (ScriptOptions options = new ScriptOptions()) {
      // Test QJS runtime
      options.setRuntime(ScriptRuntime.QJS);
      assertEquals(ScriptRuntime.QJS, options.getRuntime(), "Runtime should be QJS");

      // Test V8 runtime
      options.setRuntime(ScriptRuntime.V8);
      assertEquals(ScriptRuntime.V8, options.getRuntime(), "Runtime should be V8");

      System.out.println("Runtime get/set operations validated");
    }
  }

  @Test
  @Order(6)
  void testEmptySnapshot() {
    try (ScriptOptions options = new ScriptOptions()) {
      byte[] emptySnapshot = new byte[0];
      options.setSnapshot(emptySnapshot);

      byte[] retrieved = options.getSnapshot();
      assertNotNull(retrieved, "Retrieved snapshot should not be null");
      assertEquals(0, retrieved.length, "Empty snapshot should have zero length");

      System.out.println("Empty snapshot handling validated");
    }
  }

  @Test
  @Order(7)
  void testLargeSnapshot() {
    try (ScriptOptions options = new ScriptOptions()) {
      byte[] largeSnapshot = new byte[1024];
      for (int i = 0; i < largeSnapshot.length; i++) {
        largeSnapshot[i] = (byte) (i % 256);
      }

      options.setSnapshot(largeSnapshot);
      byte[] retrieved = options.getSnapshot();

      assertEquals(largeSnapshot.length, retrieved.length, "Snapshot length should match");
      assertArrayEquals(largeSnapshot, retrieved, "Large snapshot bytes should match");

      System.out.println("Large snapshot handling validated");
    }
  }

  @Test
  @Order(8)
  void testCombinedOptions() {
    try (ScriptOptions options = new ScriptOptions()) {
      String name = "comprehensive-test";
      byte[] snapshot = new byte[] {0x10, 0x20, 0x30};

      options.setName(name);
      options.setSnapshot(snapshot);
      options.setSnapshotTransport(SnapshotTransport.SHARED_MEMORY);
      options.setRuntime(ScriptRuntime.V8);

      // Verify all settings
      assertEquals(name, options.getName());
      assertArrayEquals(snapshot, options.getSnapshot());
      assertEquals(SnapshotTransport.SHARED_MEMORY, options.getSnapshotTransport());
      assertEquals(ScriptRuntime.V8, options.getRuntime());

      System.out.println("Combined options validated");
    }
  }

  @Test
  @Order(9)
  void testDefaultValues() {
    try (ScriptOptions options = new ScriptOptions()) {
      // Check that default values can be retrieved without errors
      assertNotNull(options.getName(), "Default name should not be null");
      // Default snapshot might be null or empty depending on implementation
      try {
        byte[] defaultSnapshot = options.getSnapshot();
        System.out.println(
            "Default snapshot: "
                + (defaultSnapshot == null ? "null" : defaultSnapshot.length + " bytes"));
      } catch (Exception e) {
        System.out.println("Default snapshot not available: " + e.getMessage());
      }
      assertNotNull(options.getSnapshotTransport(), "Default transport should not be null");
      assertNotNull(options.getRuntime(), "Default runtime should not be null");

      System.out.println("Default values validated");
    }
  }
}
