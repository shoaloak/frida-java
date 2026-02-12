package nl.axelkoolhaas.frida_java.internal; // <--- Recommended package

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

/**
 * Manages the background GLib Main Loop required for Frida signals.
 * <p>
 * This class is internal API. Users should not interact with it directly;
 * it is initialized automatically by {@link nl.axelkoolhaas.frida_java.frida.Frida}.
 * </p>
 */
public class FridaEventLoop {
    // We bind these manually here because they are specific to the event loop infrastructure
    private static final MethodHandle G_MAIN_LOOP_NEW;
    private static final MethodHandle G_MAIN_LOOP_RUN;
    // We might need unref if we ever implement a shutdown() method
    private static final MethodHandle G_MAIN_LOOP_UNREF;

    static {
        // Ensure symbols are loaded
        G_MAIN_LOOP_NEW = FridaLibraryLoader.findFunction("g_main_loop_new",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_BOOLEAN));
        G_MAIN_LOOP_RUN = FridaLibraryLoader.findFunction("g_main_loop_run",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        G_MAIN_LOOP_UNREF = FridaLibraryLoader.findFunction("g_main_loop_unref",
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    }

    private static MemorySegment mainLoop = MemorySegment.NULL;
    private static volatile boolean running = false;

    /**
     * Starts the GLib Main Loop in a background daemon thread.
     * This method is idempotent (safe to call multiple times).
     */
    public static synchronized void start() {
        if (running) return;
        running = true;

        Thread fridaThread = new Thread(() -> {
            try {
                // 1. Create a new GLib Main Loop
                // context = NULL (uses the default thread-default context)
                // is_running = false
                mainLoop = (MemorySegment) G_MAIN_LOOP_NEW.invoke(MemorySegment.NULL, false);

                // 2. Run the loop
                // This call BLOCKS indefinitely. It will process all signals
                // (File changes, script messages, device events).
                G_MAIN_LOOP_RUN.invoke(mainLoop);

            } catch (Throwable e) {
                System.err.println("Frida-Java: Fatal Error in Event Loop");
                e.printStackTrace();
            }
        }, "Frida-Event-Loop");

        // Daemon thread ensures the JVM exits when the main application finishes.
        // If this wasn't daemon, the app would never close because this loop never ends.
        fridaThread.setDaemon(true);
        fridaThread.start();
    }
}