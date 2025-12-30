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
import org.junit.jupiter.api.*;

import java.lang.foreign.MemorySegment;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Closure functionality.
 * Tests creation, callback dispatch, memory management, and signal handling.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ClosureTest {

    @Test
    @Order(1)
    void testCreateClosureWithSimpleCallback() {
        AtomicBoolean callbackInvoked = new AtomicBoolean(false);
        Runnable callback = () -> callbackInvoked.set(true);

        Closure closure = Closure.create(callback, "detached");

        assertNotNull(closure, "Closure should not be null");
        assertNotNull(closure.getNativeCallback(), "Native callback should not be null");
        assertFalse(closure.getNativeCallback().equals(MemorySegment.NULL),
                   "Native callback should not be NULL pointer");

        System.out.println("Created closure for 'detached' signal with native callback: " +
                          closure.getNativeCallback());
    }

    @Test
    @Order(2)
    void testCreateClosureWithMessageCallback() {
        AtomicBoolean messageReceived = new AtomicBoolean(false);
        AtomicReference<String> receivedMessage = new AtomicReference<>();
        AtomicReference<byte[]> receivedData = new AtomicReference<>();

        Closure.MessageCallback callback = (message, data) -> {
            messageReceived.set(true);
            receivedMessage.set(message);
            receivedData.set(data);
        };

        Closure closure = Closure.create(callback, "message");

        assertNotNull(closure, "Closure should not be null");
        assertNotNull(closure.getNativeCallback(), "Native callback should not be null");

        System.out.println("Created closure for 'message' signal with native callback: " +
                          closure.getNativeCallback());
    }

    @Test
    @Order(3)
    void testDispatchSimpleSignal() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean detachedSignalReceived = new AtomicBoolean(false);

        Runnable callback = () -> {
            detachedSignalReceived.set(true);
            latch.countDown();
        };

        Closure closure = Closure.create(callback, "detached");

        // Manually trigger the signal dispatch to test the mechanism
        // In real usage, this would be called from native code
        Closure.dispatchSignal(closure.getId(), "detached"); // Using closure ID 1 since it's the first closure

        assertTrue(latch.await(1, TimeUnit.SECONDS), "Callback should be invoked within timeout");
        assertTrue(detachedSignalReceived.get(), "Detached signal should have been received");

        System.out.println("Successfully dispatched and received 'detached' signal");
    }

    @Test
    @Order(4)
    void testDispatchMessageSignal() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> receivedMessage = new AtomicReference<>();
        AtomicReference<byte[]> receivedData = new AtomicReference<>();

        Closure.MessageCallback callback = (message, data) -> {
            receivedMessage.set(message);
            receivedData.set(data);
            latch.countDown();
        };

        Closure closure = Closure.create(callback, "message");

        String testMessage = "Test message from Frida";
        byte[] testData = "test data".getBytes();

        // Manually trigger the message signal dispatch
        Closure.dispatchSignal(closure.getId(), "message", testMessage, testData);

        assertTrue(latch.await(1, TimeUnit.SECONDS), "Message callback should be invoked within timeout");
        assertEquals(testMessage, receivedMessage.get(), "Message should match");
        assertArrayEquals(testData, receivedData.get(), "Data should match");

        System.out.println("Successfully dispatched and received 'message' signal with data");
    }

    @Test
    @Order(5)
    void testDispatchLostSignal() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean lostSignalReceived = new AtomicBoolean(false);

        Runnable callback = () -> {
            lostSignalReceived.set(true);
            latch.countDown();
        };

        Closure closure = Closure.create(callback, "lost");

        // Dispatch the lost signal
        Closure.dispatchSignal(closure.getId(), "lost");

        assertTrue(latch.await(1, TimeUnit.SECONDS), "Lost signal callback should be invoked");
        assertTrue(lostSignalReceived.get(), "Lost signal should have been received");

        System.out.println("Successfully dispatched and received 'lost' signal");
    }

    @Test
    @Order(6)
    void testDispatchUnknownSignal() {
        AtomicBoolean callbackInvoked = new AtomicBoolean(false);

        Runnable callback = () -> callbackInvoked.set(true);

        Closure closure = Closure.create(callback, "unknown_signal");

        // Dispatch an unknown signal - should not crash but also not invoke callback
        Closure.dispatchSignal(closure.getId(), "unknown_signal");

        // Give it a moment to process
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // For unknown signals, the callback won't be invoked in current implementation
        // This tests that the system handles unknown signals gracefully
        System.out.println("Successfully handled unknown signal without crashing");
    }

    @Test
    @Order(7)
    void testDispatchWithNonExistentClosure() {
        // Test dispatching to a closure ID that doesn't exist
        // Should not crash or throw exceptions
        assertDoesNotThrow(() -> {
            Closure.dispatchSignal(999, "detached");
        }, "Dispatching to non-existent closure should not throw exception");

        System.out.println("Successfully handled dispatch to non-existent closure");
    }

    @Test
    @Order(8)
    void testMultipleClosures() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(2);
        AtomicInteger callbackCount = new AtomicInteger(0);

        Runnable callback1 = () -> {
            callbackCount.incrementAndGet();
            latch.countDown();
        };

        Runnable callback2 = () -> {
            callbackCount.incrementAndGet();
            latch.countDown();
        };

        Closure closure1 = Closure.create(callback1, "detached");
        Closure closure2 = Closure.create(callback2, "lost");

        assertNotNull(closure1.getNativeCallback(), "First closure should have native callback");
        assertNotNull(closure2.getNativeCallback(), "Second closure should have native callback");
        assertNotEquals(closure1.getNativeCallback().address(),
                       closure2.getNativeCallback().address(),
                       "Different closures should have different native callbacks");

        // Dispatch to both closures
        Closure.dispatchSignal(closure1.getId(), "detached");
        Closure.dispatchSignal(closure2.getId(), "lost");

        assertTrue(latch.await(2, TimeUnit.SECONDS), "Both callbacks should be invoked");
        assertEquals(2, callbackCount.get(), "Both callbacks should have been called");

        System.out.println("Successfully created and dispatched to multiple closures");
    }

    @Test
    @Order(9)
    void testClosureDispose() throws InterruptedException {
        AtomicBoolean callbackInvoked = new AtomicBoolean(false);

        Runnable callback = () -> callbackInvoked.set(true);

        Closure closure = Closure.create(callback, "detached");

        // Dispose the closure
        closure.dispose();

        // Try to dispatch after disposal - callback should not be invoked
        Closure.dispatchSignal(closure.getId(), "detached");

        // Give it a moment to process
        Thread.sleep(100);

        assertFalse(callbackInvoked.get(), "Callback should not be invoked after disposal");

        System.out.println("Successfully tested closure disposal - callback not invoked after dispose");
    }

    @Test
    @Order(10)
    void testCallbackExceptionHandling() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);

        Runnable faultyCallback = () -> {
            latch.countDown();
            throw new RuntimeException("Test exception in callback - IGNORE THIS ERROR");
        };

        Closure closure = Closure.create(faultyCallback, "detached");

        // This should not crash the application even if callback throws
        assertDoesNotThrow(() -> {
            Closure.dispatchSignal(closure.getId(), "detached");
        }, "Exception in callback should be handled gracefully");

        assertTrue(latch.await(1, TimeUnit.SECONDS), "Callback should still be invoked despite exception");

        System.out.println("Successfully handled exception in callback without crashing");
    }

    @Test
    @Order(11)
    void testMessageCallbackWithNullMessage() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> receivedMessage = new AtomicReference<>();
        AtomicReference<byte[]> receivedData = new AtomicReference<>();

        Closure.MessageCallback callback = (message, data) -> {
            receivedMessage.set(message);
            receivedData.set(data);
            latch.countDown();
        };

        Closure closure = Closure.create(callback, "message");

        // Test with null message and data
        Closure.dispatchSignal(closure.getId(), "message", null, null);

        assertTrue(latch.await(1, TimeUnit.SECONDS), "Callback should handle null values");
        assertNull(receivedMessage.get(), "Message should be null");
        assertNull(receivedData.get(), "Data should be null");

        System.out.println("Successfully handled message callback with null values");
    }

    @Test
    @Order(12)
    void testInvalidCallbackType() {
        // Test with callback that doesn't match expected interface
        String invalidCallback = "This is not a valid callback";

        assertDoesNotThrow(() -> {
            Closure closure = Closure.create(invalidCallback, "detached");
            assertNotNull(closure, "Closure should still be created with invalid callback type");

            // Dispatch should not crash even with invalid callback
            Closure.dispatchSignal(closure.getId(), "detached");
        }, "Invalid callback type should be handled gracefully");

        System.out.println("Successfully handled invalid callback type without crashing");
    }
}
