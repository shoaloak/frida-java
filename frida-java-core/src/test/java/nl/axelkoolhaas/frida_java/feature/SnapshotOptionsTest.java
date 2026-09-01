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

/** Tests for SnapshotOptions class */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SnapshotOptionsTest {

  @Test
  @Order(1)
  void testCreateSnapshotOptions() {
    try (SnapshotOptions options = new SnapshotOptions()) {
      assertNotNull(options, "SnapshotOptions should not be null");
      System.out.println("SnapshotOptions created successfully");
    }
  }

  @Test
  @Order(2)
  void testSetAndGetWarmupScript() {
    try (SnapshotOptions options = new SnapshotOptions()) {
      String warmupScript = "console.log('warmup');";
      options.setWarmupScript(warmupScript);
      assertEquals(warmupScript, options.getWarmupScript(), "Warmup script should match");

      // Test with more complex script
      String complexScript = "var x = 1; var y = 2; console.log(x + y);";
      options.setWarmupScript(complexScript);
      assertEquals(complexScript, options.getWarmupScript(), "Complex warmup script should match");

      System.out.println("Warmup script get/set operations validated");
    }
  }

  @Test
  @Order(3)
  void testSetAndGetRuntime() {
    try (SnapshotOptions options = new SnapshotOptions()) {
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
  @Order(4)
  void testEmptyWarmupScript() {
    try (SnapshotOptions options = new SnapshotOptions()) {
      String emptyScript = "";
      options.setWarmupScript(emptyScript);
      assertEquals(emptyScript, options.getWarmupScript(), "Empty warmup script should match");

      System.out.println("Empty warmup script handling validated");
    }
  }

  @Test
  @Order(5)
  void testLargeWarmupScript() {
    try (SnapshotOptions options = new SnapshotOptions()) {
      StringBuilder largeScript = new StringBuilder();
      for (int i = 0; i < 100; i++) {
        largeScript.append("console.log('Line ").append(i).append("');");
      }

      String script = largeScript.toString();
      options.setWarmupScript(script);
      assertEquals(script, options.getWarmupScript(), "Large warmup script should match");

      System.out.println("Large warmup script handling validated");
    }
  }

  @Test
  @Order(6)
  void testCombinedOptions() {
    try (SnapshotOptions options = new SnapshotOptions()) {
      String warmup = "function init() { return 'ready'; }";

      options.setWarmupScript(warmup);
      options.setRuntime(ScriptRuntime.V8);

      assertEquals(warmup, options.getWarmupScript());
      assertEquals(ScriptRuntime.V8, options.getRuntime());

      System.out.println("Combined snapshot options validated");
    }
  }

  @Test
  @Order(7)
  void testDefaultValues() {
    try (SnapshotOptions options = new SnapshotOptions()) {
      assertNotNull(options.getWarmupScript(), "Default warmup script should not be null");
      assertNotNull(options.getRuntime(), "Default runtime should not be null");

      System.out.println("Default values validated");
    }
  }

  @Test
  @Order(8)
  void testMultipleInstances() {
    try (SnapshotOptions options1 = new SnapshotOptions();
        SnapshotOptions options2 = new SnapshotOptions()) {

      options1.setWarmupScript("warmup1");
      options1.setRuntime(ScriptRuntime.QJS);

      options2.setWarmupScript("warmup2");
      options2.setRuntime(ScriptRuntime.V8);

      // Verify instances are independent
      assertEquals("warmup1", options1.getWarmupScript());
      assertEquals(ScriptRuntime.QJS, options1.getRuntime());

      assertEquals("warmup2", options2.getWarmupScript());
      assertEquals(ScriptRuntime.V8, options2.getRuntime());

      System.out.println("Multiple independent SnapshotOptions instances validated");
    }
  }
}
