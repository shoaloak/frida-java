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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import nl.axelkoolhaas.frida_java.frida.Bus;

/**
 * Tests for Bus functionality
 *
 * <p>Note: These tests use a mock Bus pointer since Session.getBus() is not implemented. They test
 * the Bus API contracts and error handling.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class BusTest {

  @Test
  @Order(1)
  void testBusRequiresValidPointer() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Bus(MemorySegment.NULL),
        "Bus should reject NULL pointer");
  }

  @Test
  @Order(2)
  void testBusIsAutoCloseable() {
    // Verify Bus implements AutoCloseable for try-with-resources
    assertTrue(
        AutoCloseable.class.isAssignableFrom(Bus.class), "Bus should implement AutoCloseable");
  }

  @Test
  @Order(3)
  void testBusOnValidatesSignalNames() {
    // Create a fake bus pointer (won't be used for actual operations)
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      // Test invalid signal name
      assertThrows(
          IllegalArgumentException.class,
          () -> bus.on("invalid-signal", (Runnable) () -> {}),
          "Should reject unknown signal names");

      // Don't clean - fake pointer doesn't need cleanup
    }
  }

  @Test
  @Order(4)
  void testBusOnValidatesCallbackTypes() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      // Test wrong callback type for "detached"
      assertThrows(
          IllegalArgumentException.class,
          () -> bus.on("detached", "wrong type"),
          "Should reject wrong callback type for detached signal");

      // Test wrong callback type for "message"
      assertThrows(
          IllegalArgumentException.class,
          () -> bus.on("message", (Runnable) () -> {}),
          "Should reject wrong callback type for message signal");

      // Don't clean - fake pointer doesn't need cleanup
    }
  }

  @Test
  @Order(5)
  void testBusOnRejectsNullCallback() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      assertThrows(
          IllegalArgumentException.class,
          () -> bus.on("detached", null),
          "Should reject null callback");

      // Don't clean - fake pointer doesn't need cleanup
    }
  }

  @Test
  @Order(6)
  @Disabled("Cannot test clean() with fake pointers - fridaUnref crashes on non-GObjects")
  void testBusCleanIsIdempotent() {
    // This test requires a real Bus from Session.getBus()
    // Fake pointers cause SIGABRT when fridaUnref is called
  }

  @Test
  @Order(7)
  @Disabled("Cannot test clean() with fake pointers - fridaUnref crashes on non-GObjects")
  void testBusMethodsThrowAfterClean() {
    // This test requires a real Bus from Session.getBus()
    // Fake pointers cause SIGABRT when fridaUnref is called
  }

  @Test
  @Order(8)
  void testBusOffIsIdempotent() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      // off() on non-existent signal should not throw
      assertDoesNotThrow(() -> bus.off("detached"), "off() should be idempotent");
      assertDoesNotThrow(() -> bus.off("message"), "off() should be idempotent");
      assertDoesNotThrow(() -> bus.off("nonexistent"), "off() should be idempotent");

      // Don't clean - fake pointer doesn't need cleanup
    }
  }

  @Test
  @Order(9)
  @Disabled("Cannot test clean() with fake pointers - fridaUnref crashes on non-GObjects")
  void testBusOffAfterCleanDoesNotThrow() {
    // This test requires a real Bus from Session.getBus()
    // Fake pointers cause SIGABRT when fridaUnref is called
  }

  @Test
  @Order(10)
  @Disabled("Cannot test clean() with fake pointers - fridaUnref crashes on non-GObjects")
  void testBusToStringBeforeAndAfterClean() {
    // This test requires a real Bus from Session.getBus()
    // Fake pointers cause SIGABRT when fridaUnref is called
  }

  @Test
  @Order(11)
  @Disabled(
      "Cannot connect signals with fake pointers - Closure.connectClosure crashes on non-GObjects")
  void testBusAcceptsVoidCallback() {
    // This test requires a real Bus from Session.getBus()
    // Fake pointers cause crash when Closure.connectClosure is called
  }

  @Test
  @Order(12)
  @Disabled(
      "Cannot connect signals with fake pointers - Closure.connectClosure crashes on non-GObjects")
  void testBusAcceptsRunnableCallback() {
    // This test requires a real Bus from Session.getBus()
    // Fake pointers cause crash when Closure.connectClosure is called
  }

  @Test
  @Order(13)
  @Disabled(
      "Cannot connect signals with fake pointers - Closure.connectClosure crashes on non-GObjects")
  void testBusAcceptsMessageCallback() {
    // This test requires a real Bus from Session.getBus()
    // Fake pointers cause crash when Closure.connectClosure is called
  }

  @Test
  @Order(14)
  @Disabled("Cannot test close() with fake pointers - fridaUnref crashes on non-GObjects")
  void testBusCloseIsSameAsClean() {
    // This test requires a real Bus from Session.getBus()
    // Fake pointers cause SIGABRT when fridaUnref is called
  }

  @Test
  @Order(15)
  @Disabled("Cannot test close() with fake pointers - fridaUnref crashes on non-GObjects")
  void testBusTryWithResources() {
    // This test requires a real Bus from Session.getBus()
    // Fake pointers cause SIGABRT when fridaUnref is called
  }
}
