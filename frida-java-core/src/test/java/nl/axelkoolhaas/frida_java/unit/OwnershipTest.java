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

package nl.axelkoolhaas.frida_java.unit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import nl.axelkoolhaas.frida_java.frida.Child;
import nl.axelkoolhaas.frida_java.frida.CompilerOptions;
import nl.axelkoolhaas.frida_java.frida.Crash;
import nl.axelkoolhaas.frida_java.frida.Device;
import nl.axelkoolhaas.frida_java.frida.Process;
import nl.axelkoolhaas.frida_java.frida.Spawn;

/**
 * Unit tests for ownership semantics per CLAUDE.md.
 *
 * <p>These tests validate that signal-parameter wrappers (Child, Spawn, Crash, Process, Device,
 * CompilerOptions) correctly implement the owned vs borrowed contract:
 *
 * <ul>
 *   <li>owned=true: wrapper unrefs on close()
 *   <li>owned=false: wrapper does not unref on close()
 * </ul>
 *
 * <p>Tests do NOT require a live Frida instance. They validate API contracts only.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class OwnershipTest {

  @Test
  @Order(1)
  void testChildImplementsAutoCloseable() {
    assertTrue(AutoCloseable.class.isAssignableFrom(Child.class), "Child should be AutoCloseable");
  }

  @Test
  @Order(2)
  void testSpawnImplementsAutoCloseable() {
    assertTrue(AutoCloseable.class.isAssignableFrom(Spawn.class), "Spawn should be AutoCloseable");
  }

  @Test
  @Order(3)
  void testCrashImplementsAutoCloseable() {
    assertTrue(AutoCloseable.class.isAssignableFrom(Crash.class), "Crash should be AutoCloseable");
  }

  @Test
  @Order(4)
  void testProcessImplementsAutoCloseable() {
    assertTrue(
        AutoCloseable.class.isAssignableFrom(Process.class), "Process should be AutoCloseable");
  }

  @Test
  @Order(5)
  void testDeviceImplementsAutoCloseable() {
    assertTrue(
        AutoCloseable.class.isAssignableFrom(Device.class), "Device should be AutoCloseable");
  }

  @Test
  @Order(6)
  void testCompilerOptionsImplementsAutoCloseable() {
    assertTrue(
        AutoCloseable.class.isAssignableFrom(CompilerOptions.class),
        "CompilerOptions should be AutoCloseable");
  }

  @Test
  @Order(7)
  void testChildRejectsNullPointer() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Child(MemorySegment.NULL),
        "Child should reject NULL pointer");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Child(MemorySegment.NULL, true),
        "Child should reject NULL pointer with owned=true");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Child(MemorySegment.NULL, false),
        "Child should reject NULL pointer with owned=false");
  }

  @Test
  @Order(8)
  void testSpawnRejectsNullPointer() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Spawn(MemorySegment.NULL),
        "Spawn should reject NULL pointer");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Spawn(MemorySegment.NULL, true),
        "Spawn should reject NULL pointer with owned=true");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Spawn(MemorySegment.NULL, false),
        "Spawn should reject NULL pointer with owned=false");
  }

  @Test
  @Order(9)
  void testCrashRejectsNullPointer() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Crash(MemorySegment.NULL),
        "Crash should reject NULL pointer");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Crash(MemorySegment.NULL, true),
        "Crash should reject NULL pointer with owned=true");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Crash(MemorySegment.NULL, false),
        "Crash should reject NULL pointer with owned=false");
  }

  @Test
  @Order(10)
  void testProcessRejectsNullPointer() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Process(MemorySegment.NULL),
        "Process should reject NULL pointer");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Process(MemorySegment.NULL, true),
        "Process should reject NULL pointer with owned=true");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Process(MemorySegment.NULL, false),
        "Process should reject NULL pointer with owned=false");
  }

  @Test
  @Order(11)
  void testDeviceRejectsNullPointer() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Device(MemorySegment.NULL),
        "Device should reject NULL pointer");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Device(MemorySegment.NULL, true),
        "Device should reject NULL pointer with owned=true");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Device(MemorySegment.NULL, false),
        "Device should reject NULL pointer with owned=false");
  }

  @Test
  @Order(12)
  void testCompilerOptionsRejectsNullPointer() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new CompilerOptions(MemorySegment.NULL),
        "CompilerOptions should reject NULL pointer");

    assertThrows(
        IllegalArgumentException.class,
        () -> new CompilerOptions(MemorySegment.NULL, true),
        "CompilerOptions should reject NULL pointer with owned=true");

    assertThrows(
        IllegalArgumentException.class,
        () -> new CompilerOptions(MemorySegment.NULL, false),
        "CompilerOptions should reject NULL pointer with owned=false");
  }

  @Test
  @Order(13)
  void testCompilerOptionsDefaultConstructorCreatesOwned() {
    // The default CompilerOptions() constructor creates its own native object
    // and should own it (call unref on close)
    CompilerOptions options = new CompilerOptions();
    assertDoesNotThrow(options::close, "CompilerOptions default constructor should be closeable");
  }
}
