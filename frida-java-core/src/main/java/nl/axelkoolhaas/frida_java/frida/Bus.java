package nl.axelkoolhaas.frida_java.frida;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GBytesUtil;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bus represents a communication channel with Frida devices
 */
public class Bus {
    private static final Logger log = LoggerFactory.getLogger(Bus.class);
    private final MemorySegment busPtr;
    private final Map<String, Object> signalHandlers = new ConcurrentHashMap<>();
    private final Map<String, Long> handlerIds = new ConcurrentHashMap<>();

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
        log.debug("Bus created");
    }

    /**
     * Check if the bus is detached from the device
     * @return true if detached, false otherwise
     */
    public boolean isDetached() {
        try {
            // frida_bus_is_detached returns gboolean (typedef gint, i.e., int)
            // gboolean: FALSE = 0, TRUE = non-zero (typically 1)
            int result = (int) FRIDA_BUS_IS_DETACHED.invoke(busPtr);
            log.trace("Checked bus detached state: {}", result != 0);
            return result != 0;
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.error("Failed to check if bus is detached: {}", e.getMessage());
            throw new FridaException("Failed to check if bus is detached", e);
        }
    }

    /**
     * Attach to the device bus
     * @throws FridaException if attachment fails
     */
    public void attach() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);
            log.debug("Attaching to bus");
            FRIDA_BUS_ATTACH_SYNC.invoke(busPtr, MemorySegment.NULL, errorPtr);

            MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
            GErrorUtils.handleError(error, "attach to bus");
            log.debug("Bus attached successfully");
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.error("Failed to attach to bus: {}", e.getMessage());
            throw new FridaException("Failed to attach to bus", e);
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
                gBytesData = GBytesUtil.fromByteArray(data, arena);
            }

            FRIDA_BUS_POST.invoke(busPtr, messagePtr, gBytesData);
        } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
            throw e;
        } catch (Throwable e) {
            log.error("Failed to post message to bus: {}", e.getMessage());
            throw new FridaException("Failed to post message to bus", e);
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
     *
     * Available signals:
     * - "detached": Emitted when the bus is detached from the device
     *   Callback should be Runnable
     * - "message": Emitted when a message is received from the device
     *   Callback should be Closure.MessageCallback accepting (String message, byte[] data)
     *
     * @param signalName Signal name to connect to
     * @param callback Callback function
     * @throws IllegalArgumentException if signal name is unknown or callback type is invalid
     */
    public void on(String signalName, Object callback) {
        if (callback == null) {
            throw new IllegalArgumentException("Callback cannot be null");
        }

        signalHandlers.put(signalName, callback);

        long handlerId;
        switch (signalName) {
            case "detached":
                if (!(callback instanceof Runnable)) {
                    throw new IllegalArgumentException("Detached signal callback must be Runnable");
                }
                handlerId = FridaNativeUtils.connectSignal(busPtr, signalName, callback);
                handlerIds.put(signalName, handlerId);
                break;
            case "message":
                // Callback should accept (String message, byte[] data)
                handlerId = FridaNativeUtils.connectSignal(busPtr, signalName, callback);
                handlerIds.put(signalName, handlerId);
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

        Long handlerId = handlerIds.remove(signalName);
        if (handlerId != null) {
            FridaNativeUtils.disconnectSignal(busPtr, handlerId);
        }
    }

    /**
     * Clean up resources held by the bus
     */
    public void clean() {
        // Disconnect all signals
        signalHandlers.keySet().forEach(this::off);
        signalHandlers.clear();

        FridaNativeUtils.fridaUnref(busPtr);
    }

    @Override
    public String toString() {
        return "Bus{detached=" + isDetached() + "}";
    }
}
