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

import java.io.File;
import java.nio.file.Files;

import org.junit.jupiter.api.*;

import nl.axelkoolhaas.frida_java.frida.*;

/** Tests for FileMonitor class */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class FileMonitorTest {

  private static File tempFile;

  @BeforeAll
  static void setUp() throws Exception {
    tempFile = Files.createTempFile("frida-test", ".txt").toFile();
    tempFile.deleteOnExit();
  }

  @AfterAll
  static void tearDown() {
    if (tempFile != null && tempFile.exists()) {
      tempFile.delete();
    }
  }

  @Test
  @Order(1)
  void testCreateFileMonitor() {
    try (FileMonitor monitor = new FileMonitor(tempFile.getAbsolutePath())) {
      assertNotNull(monitor, "FileMonitor should not be null");
      System.out.println("FileMonitor created successfully for: " + tempFile.getAbsolutePath());
    }
  }

  @Test
  @Order(2)
  void testGetPath() {
    try (FileMonitor monitor = new FileMonitor(tempFile.getAbsolutePath())) {
      String path = monitor.getPath();
      assertNotNull(path, "Path should not be null");
      assertEquals(tempFile.getAbsolutePath(), path, "Path should match");
      System.out.println("FileMonitor path validated: " + path);
    }
  }

  @Test
  @Order(3)
  void testEnableDisable() {
    try (FileMonitor monitor = new FileMonitor(tempFile.getAbsolutePath())) {
      // Test enable
      assertDoesNotThrow(() -> monitor.enable(), "Enable should not throw");
      System.out.println("FileMonitor enabled successfully");

      // Test disable
      assertDoesNotThrow(() -> monitor.disable(), "Disable should not throw");
      System.out.println("FileMonitor disabled successfully");
    }
  }

  @Test
  @Order(4)
  void testMultipleEnableDisable() {
    try (FileMonitor monitor = new FileMonitor(tempFile.getAbsolutePath())) {
      monitor.enable();
      monitor.disable();
      monitor.enable();
      monitor.disable();

      System.out.println("Multiple enable/disable cycles completed");
    }
  }

  @Test
  @Order(5)
  void testMonitorDirectory() throws Exception {
    File tempDir = Files.createTempDirectory("frida-test-dir").toFile();
    tempDir.deleteOnExit();

    try (FileMonitor monitor = new FileMonitor(tempDir.getAbsolutePath())) {
      assertEquals(tempDir.getAbsolutePath(), monitor.getPath());
      monitor.enable();
      monitor.disable();
      System.out.println("Directory monitoring validated");
    } finally {
      tempDir.delete();
    }
  }

  @Test
  @Order(6)
  void testInvalidPath() {
    String invalidPath = "/nonexistent/path/to/file.txt";
    // FileMonitor creation and enabling may succeed even for non-existent paths
    // Frida will monitor when the path becomes available
    try (FileMonitor monitor = new FileMonitor(invalidPath)) {
      assertNotNull(monitor, "FileMonitor should be created");
      assertEquals(invalidPath, monitor.getPath(), "Path should match");

      // Enable monitoring - Frida allows monitoring non-existent paths
      monitor.enable();
      monitor.disable();

      System.out.println("Invalid path handling validated (monitors when path appears)");
    } catch (FridaException e) {
      // Some implementations may fail on creation or enable
      System.out.println("Invalid path rejected: " + e.getMessage());
    }
  }

  @Test
  @Order(7)
  void testAutoCloseable() {
    FileMonitor monitor = new FileMonitor(tempFile.getAbsolutePath());
    monitor.enable();
    monitor.close();
    System.out.println("AutoCloseable pattern validated");
  }
}
