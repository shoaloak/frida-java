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

import nl.axelkoolhaas.frida_java.frida.Closure;
import nl.axelkoolhaas.frida_java.frida.SignalCallbacks;
import org.junit.jupiter.api.*;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Closure functionality.
 *
 * Note: The Closure class now uses a GClosure-based approach with custom marshal functions,
 * similar to Go's frida bindings. Signal connections require actual GObjects, so most
 * closure functionality is tested via integration tests (e.g., SessionAndScriptTest).
 *
 * This test class focuses on the public API that can be tested in isolation.
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
        AtomicReference<Exception> capturedException = new AtomicReference<>();

        SignalCallbacks.ErrorHandler handler = (signal, error) -> {
            capturedSignal.set(signal);
            capturedException.set(error);
        };

        // Should not throw when setting handler
        assertDoesNotThrow(() -> Closure.setErrorHandler(handler),
                "Setting error handler should not throw");

        // Should not throw when clearing handler
        assertDoesNotThrow(() -> Closure.setErrorHandler(null),
                "Clearing error handler should not throw");
    }

    @Test
    @Order(2)
    void testErrorHandlerCanBeReplaced() {
        AtomicReference<String> firstHandlerCalled = new AtomicReference<>();
        AtomicReference<String> secondHandlerCalled = new AtomicReference<>();

        SignalCallbacks.ErrorHandler firstHandler = (signal, error) -> {
            firstHandlerCalled.set("first");
        };

        SignalCallbacks.ErrorHandler secondHandler = (signal, error) -> {
            secondHandlerCalled.set("second");
        };

        Closure.setErrorHandler(firstHandler);
        Closure.setErrorHandler(secondHandler);

        // Only the second handler should be active now
        // (Actual invocation happens through native signals, tested in integration tests)
        assertDoesNotThrow(() -> Closure.setErrorHandler(null),
                "Should be able to clear handler after replacement");
    }

    @Test
    @Order(3)
    void testDisconnectClosureWithInvalidId() {
        // Disconnecting a non-existent closure should not throw
        assertDoesNotThrow(() -> Closure.disconnectClosure(999_999),
                "Disconnecting non-existent closure should not throw");

        assertDoesNotThrow(() -> Closure.disconnectClosure(0),
                "Disconnecting closure ID 0 should not throw");

        assertDoesNotThrow(() -> Closure.disconnectClosure(-1),
                "Disconnecting negative closure ID should not throw");
    }

    @Test
    @Order(4)
    void testMessageCallbackInterface() {
        // Test that MessageCallback interface works correctly
        AtomicReference<String> receivedMessage = new AtomicReference<>();
        AtomicReference<byte[]> receivedData = new AtomicReference<>();

        SignalCallbacks.MessageCallback callback = (message, data) -> {
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
        AtomicReference<byte[]> receivedData = new AtomicReference<>(new byte[]{1, 2, 3});

        SignalCallbacks.MessageCallback callback = (message, data) -> {
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
        AtomicReference<Exception> capturedException = new AtomicReference<>();

        SignalCallbacks.ErrorHandler handler = (signal, error) -> {
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
}
