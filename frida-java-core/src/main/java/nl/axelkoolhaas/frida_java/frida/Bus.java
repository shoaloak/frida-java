package nl.axelkoolhaas.frida_java.frida;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bus represents a communication channel with Frida devices
 */
public class Bus {
    private final MemorySegment busPtr;
    private final Map<String, Object> signalHandlers = new ConcurrentHashMap<>();

    // Native method handles
    private static final MethodHandle FRIDA_BUS_IS_DETACHED;
    private static final MethodHandle FRIDA_BUS_ATTACH_SYNC;
    private static final MethodHandle FRIDA_BUS_POST;

    static {
        Frida.ensureInitialized();
        FRIDA_BUS_IS_DETACHED = FridaLibraryLoader.findFunction("frida_bus_is_detached",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        FRIDA_BUS_ATTACH_SYNC = FridaLibraryLoader.findFunction("frida_bus_attach_sync",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        FRIDA_BUS_POST = FridaLibraryLoader.findFunction("frida_bus_post",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /**
     * Create a Bus wrapper around a native bus pointer
     * @param busPtr Native FridaBus pointer
     */
    public Bus(MemorySegment busPtr) {
        this.busPtr = FridaNativeUtils.requireValidPointer(busPtr, "Bus pointer");
    }

    /**
     * Check if the bus is detached from the device
     * @return true if detached, false otherwise
     */
    public boolean isDetached() {
        try {
            int result = (int) FRIDA_BUS_IS_DETACHED.invoke(busPtr);
            return result == 1;
        } catch (Throwable e) {
            throw new RuntimeException("Failed to check if bus is detached", e);
        }
    }

    /**
     * Attach to the device bus
     * @throws RuntimeException if attachment fails
     */
    public void attach() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

            FRIDA_BUS_ATTACH_SYNC.invoke(busPtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "attach to bus");
        } catch (Throwable e) {
            throw new RuntimeException("Failed to attach to bus", e);
        }
    }

    /**
     * Post a message to the device
     * @param message Message string to send
     * @param data Binary data to send (can be null)
     */
    public void post(String message, byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment messagePtr = arena.allocateFrom(message);

            MemorySegment gBytesData = MemorySegment.NULL;
            if (data != null && data.length > 0) {
                gBytesData = FridaNativeUtils.bytesToGBytes(data, arena);
            }

            FRIDA_BUS_POST.invoke(busPtr, messagePtr, gBytesData);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to post message to bus", e);
        }
    }

    /**
     * Post a message to the device without binary data
     * @param message Message string to send
     */
    public void post(String message) {
        post(message, null);
    }

    /**
     * Connect to bus signals
     * TODO: Implement proper signal handling
     * Available signals:
     * - "detached": callback should be Runnable
     * - "message": callback should be BiConsumer<String, byte[]>
     *
     * @param signalName Signal name to connect to
     * @param callback Callback function
     */
    public void on(String signalName, Object callback) {
        if (callback == null) {
            throw new IllegalArgumentException("Callback cannot be null");
        }

        signalHandlers.put(signalName, callback);

        switch (signalName) {
            case "detached":
                if (!(callback instanceof Runnable)) {
                    throw new IllegalArgumentException("Detached signal callback must be Runnable");
                }
                FridaNativeUtils.connectSignal(busPtr, signalName, callback);
                break;
            case "message":
                // Callback should accept (String message, byte[] data)
                FridaNativeUtils.connectSignal(busPtr, signalName, callback);
                break;
            default:
                throw new IllegalArgumentException("Unknown signal: " + signalName);
        }
    }

    /**
     * Disconnect from a signal
     * @param signalName Signal name to disconnect from
     */
    public void off(String signalName) {
        signalHandlers.remove(signalName);
        // TODO: Implement actual signal disconnection from native GObject
    }

    /**
     * Clean up resources held by the bus
     */
    public void clean() {
        // Disconnect all signals
        signalHandlers.keySet().forEach(this::off);
        signalHandlers.clear();

        // Unreference the native object
        FridaNativeUtils.fridaUnref(busPtr);
    }

    @Override
    public String toString() {
        return "Bus{detached=" + isDetached() + "}";
    }
}
