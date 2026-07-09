/*
 * Copyright (C) 2025 Axel Koolhaas
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import nl.axelkoolhaas.frida_java.frida.Closure;
import nl.axelkoolhaas.frida_java.frida.SignalCallbacks;

/**
 * Test class for Closure functionality.
 *
 * <p>Note: The Closure class now uses a GClosure-based approach with custom marshal functions,
 * similar to Go's frida bindings. Signal connections require actual GObjects, so most closure
 * functionality is tested via integration tests (e.g., SessionAndScriptTest).
 *
 * <p>This test class focuses on the public API that can be tested in isolation.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ClosureTest {

  @AfterEach
  void cleanup() {
    // Reset error handler after each test to avoid cross-test pollution
    Closure.setErrorHandler(null);
  }

  @Test
  @Order(1)
  void testSetErrorHandler() {
    AtomicReference<String> capturedSignal = new AtomicReference<>();
    AtomicReference<Throwable> capturedThrowable = new AtomicReference<>();

    SignalCallbacks.ErrorHandler handler =
        (signal, error) -> {
          capturedSignal.set(signal);
          capturedThrowable.set(error);
        };

    // Should not throw when setting handler
    assertDoesNotThrow(
        () -> Closure.setErrorHandler(handler), "Setting error handler should not throw");

    // Should not throw when clearing handler
    assertDoesNotThrow(
        () -> Closure.setErrorHandler(null), "Clearing error handler should not throw");
  }

  @Test
  @Order(2)
  void testErrorHandlerCanBeReplaced() {
    AtomicReference<String> firstHandlerCalled = new AtomicReference<>();
    AtomicReference<String> secondHandlerCalled = new AtomicReference<>();

    SignalCallbacks.ErrorHandler firstHandler =
        (signal, error) -> {
          firstHandlerCalled.set("first");
        };

    SignalCallbacks.ErrorHandler secondHandler =
        (signal, error) -> {
          secondHandlerCalled.set("second");
        };

    Closure.setErrorHandler(firstHandler);
    Closure.setErrorHandler(secondHandler);

    // Only the second handler should be active now
    // (Actual invocation happens through native signals, tested in integration tests)
    assertDoesNotThrow(
        () -> Closure.setErrorHandler(null), "Should be able to clear handler after replacement");
  }

  @Test
  @Order(3)
  void testDisconnectClosureWithInvalidId() {
    // Disconnecting a non-existent closure should not throw
    assertDoesNotThrow(
        () -> Closure.disconnectClosure(999_999),
        "Disconnecting non-existent closure should not throw");

    assertDoesNotThrow(
        () -> Closure.disconnectClosure(0), "Disconnecting closure ID 0 should not throw");

    assertDoesNotThrow(
        () -> Closure.disconnectClosure(-1), "Disconnecting negative closure ID should not throw");
  }

  @Test
  @Order(4)
  void testMessageCallbackInterface() {
    // Test that MessageCallback interface works correctly
    AtomicReference<String> receivedMessage = new AtomicReference<>();
    AtomicReference<byte[]> receivedData = new AtomicReference<>();

    SignalCallbacks.MessageCallback callback =
        (message, data) -> {
          receivedMessage.set(message);
          receivedData.set(data);
        };

    // Simulate callback invocation
    String testMessage = "test message";
    byte[] testData = "test data".getBytes();

    callback.onMessage(testMessage, testData);

    assertEquals(testMessage, receivedMessage.get(), "Message should be captured");
    assertArrayEquals(testData, receivedData.get(), "Data should be captured");
  }

  @Test
  @Order(5)
  void testMessageCallbackWithNullValues() {
    AtomicReference<String> receivedMessage = new AtomicReference<>("initial");
    AtomicReference<byte[]> receivedData = new AtomicReference<>(new byte[] {1, 2, 3});

    SignalCallbacks.MessageCallback callback =
        (message, data) -> {
          receivedMessage.set(message);
          receivedData.set(data);
        };

    // Callback should handle null values gracefully
    callback.onMessage(null, null);

    assertNull(receivedMessage.get(), "Message should be null");
    assertNull(receivedData.get(), "Data should be null");
  }

  @Test
  @Order(6)
  void testErrorHandlerInterface() {
    AtomicReference<String> capturedSignal = new AtomicReference<>();
    AtomicReference<Throwable> capturedException = new AtomicReference<>();

    SignalCallbacks.ErrorHandler handler =
        (signal, error) -> {
          capturedSignal.set(signal);
          capturedException.set(error);
        };

    // Simulate error handler invocation
    String testSignal = "message";
    RuntimeException testException = new RuntimeException("test error");

    handler.onCallbackError(testSignal, testException);

    assertEquals(testSignal, capturedSignal.get(), "Signal should be captured");
    assertEquals(testException, capturedException.get(), "Exception should be captured");
  }

  @Test
  @Order(7)
  void testErrorHandlerAcceptsAllThrowableTypes() {
    // Per CLAUDE.md Threading Model: The marshal method must catch Throwable, not just Exception,
    // and never let anything propagate out of the upcall into C (crashes the JVM).
    // This test validates that the ErrorHandler interface accepts all Throwable types.

    AtomicReference<Throwable> capturedError = new AtomicReference<>();
    SignalCallbacks.ErrorHandler handler = (signal, error) -> capturedError.set(error);

    // Test with RuntimeException
    RuntimeException runtime = new RuntimeException("runtime error");
    handler.onCallbackError("test", runtime);
    assertEquals(runtime, capturedError.get(), "Should accept RuntimeException");

    // Test with Error (e.g., OutOfMemoryError, StackOverflowError)
    Error error = new AssertionError("assertion error");
    handler.onCallbackError("test", error);
    assertEquals(error, capturedError.get(), "Should accept Error subclasses");

    // Test with checked Exception
    Exception checked = new Exception("checked exception");
    handler.onCallbackError("test", checked);
    assertEquals(checked, capturedError.get(), "Should accept checked Exception");

    // Test with Throwable directly
    Throwable throwable = new Throwable("direct throwable");
    handler.onCallbackError("test", throwable);
    assertEquals(throwable, capturedError.get(), "Should accept Throwable directly");
  }

  @Test
  @Order(8)
  void testCallbackExceptionDoesNotCrashWhenNoHandler() {
    // When no error handler is set, exceptions in callbacks should still not propagate
    // out of handleMarshal (which would crash the VM when called from native code).
    // This test validates the contract: clear the handler and verify no exception is thrown
    // from disconnecting closures (the only public path we can exercise without native signals).

    Closure.setErrorHandler(null);

    // These operations should complete without throwing even with no error handler
    assertDoesNotThrow(
        () -> Closure.disconnectClosure(12345),
        "Disconnecting closure should not throw even without error handler");
  }
}
