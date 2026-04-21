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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import org.junit.jupiter.api.*;

import nl.axelkoolhaas.frida_java.frida.*;

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
  void testBusCleanIsIdempotent() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      // First clean
      bus.clean();

      // Second clean should not throw
      assertDoesNotThrow(() -> bus.clean(), "clean() should be idempotent");
    }
  }

  @Test
  @Order(7)
  void testBusMethodsThrowAfterClean() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);
      bus.clean();

      // All methods should throw IllegalStateException after clean
      assertThrows(IllegalStateException.class, bus::isDetached, "isDetached after clean");
      assertThrows(IllegalStateException.class, bus::attach, "attach after clean");
      assertThrows(IllegalStateException.class, () -> bus.post("test"), "post after clean");
      assertThrows(
          IllegalStateException.class,
          () -> bus.on("detached", (Runnable) () -> {}),
          "on after clean");
      // Note: getPointer() is package-private for internal use, not tested here
    }
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
  void testBusOffAfterCleanDoesNotThrow() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);
      bus.clean();

      // off() after clean should not throw
      assertDoesNotThrow(() -> bus.off("detached"), "off() after clean should not throw");
    }
  }

  @Test
  @Order(10)
  void testBusToStringBeforeAndAfterClean() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      // toString() after clean should not throw
      bus.clean();
      String cleanedString = bus.toString();
      assertNotNull(cleanedString, "toString() should work after clean");
      assertTrue(cleanedString.contains("cleaned"), "toString() should indicate cleaned state");
    }
  }

  @Test
  @Order(11)
  void testBusAcceptsVoidCallback() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      // Should accept VoidCallback for detached signal (won't actually connect with fake
      // pointer)
      SignalCallbacks.VoidCallback callback = () -> {};

      // This will fail when trying to actually connect, but validates the type checking
      try {
        bus.on("detached", callback);
      } catch (FridaException e) {
        // Expected - fake pointer can't connect to real signal
        assertTrue(
            e.getMessage().contains("Failed to connect"),
            "Should fail with connection error for fake pointer");
      }

      // Don't clean - fake pointer doesn't need cleanup
    }
  }

  @Test
  @Order(12)
  void testBusAcceptsRunnableCallback() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      // Should accept Runnable for detached signal
      Runnable callback = () -> {};

      // This will fail when trying to actually connect, but validates the type checking
      try {
        bus.on("detached", callback);
      } catch (FridaException e) {
        // Expected - fake pointer can't connect to real signal
        assertTrue(
            e.getMessage().contains("Failed to connect"),
            "Should fail with connection error for fake pointer");
      }

      // Don't clean - fake pointer doesn't need cleanup
    }
  }

  @Test
  @Order(13)
  void testBusAcceptsMessageCallback() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      // Should accept MessageCallback for message signal
      SignalCallbacks.MessageCallback callback = (message, data) -> {};

      // This will fail when trying to actually connect, but validates the type checking
      try {
        bus.on("message", callback);
      } catch (FridaException e) {
        // Expected - fake pointer can't connect to real signal
        assertTrue(
            e.getMessage().contains("Failed to connect"),
            "Should fail with connection error for fake pointer");
      }

      // Don't clean - fake pointer doesn't need cleanup
    }
  }

  @Test
  @Order(14)
  void testBusCloseIsSameAsClean() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus = new Bus(fakePtr);

      // close() should work the same as clean()
      bus.close();

      // Should be in cleaned state
      assertThrows(
          IllegalStateException.class, bus::isDetached, "Should be in cleaned state after close()");
    }
  }

  @Test
  @Order(15)
  void testBusTryWithResources() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment fakePtr = arena.allocate(8);

      Bus bus;
      try (Bus b = new Bus(fakePtr)) {
        bus = b;
        assertNotNull(bus, "Bus should be usable inside try-with-resources");
      }

      // After try-with-resources, bus should be cleaned
      assertThrows(
          IllegalStateException.class,
          bus::isDetached,
          "Bus should be cleaned after try-with-resources");
    }
  }
}
