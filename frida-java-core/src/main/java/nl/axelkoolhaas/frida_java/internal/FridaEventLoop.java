package nl.axelkoolhaas.frida_java.internal; // <--- Recommended package

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;

/**
 * Manages the background GLib Main Loop required for Frida signals.
 *
 * <p>This class is internal API. Users should not interact with it directly; it is initialized
 * automatically by {@link nl.axelkoolhaas.frida_java.frida.Frida}.
 */
public class FridaEventLoop {
  // We bind these manually here because they are specific to the event loop infrastructure
  private static final MethodHandle G_MAIN_LOOP_NEW;
  private static final MethodHandle G_MAIN_LOOP_RUN;
  // We might need unref if we ever implement a shutdown() method
  private static final MethodHandle G_MAIN_LOOP_UNREF;
  private static final MethodHandle G_IDLE_ADD;

  private static final Map<Integer, Runnable> tasks = new ConcurrentHashMap<>();
  private static final AtomicInteger taskIdGenerator = new AtomicInteger(1);
  private static final MemorySegment IDLE_CALLBACK_STUB;

  static {
    // Ensure symbols are loaded
    G_MAIN_LOOP_NEW =
        FridaLibraryLoader.findFunction(
            "g_main_loop_new",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_BOOLEAN));
    G_MAIN_LOOP_RUN =
        FridaLibraryLoader.findFunction(
            "g_main_loop_run", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    G_MAIN_LOOP_UNREF =
        FridaLibraryLoader.findFunction(
            "g_main_loop_unref", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    G_IDLE_ADD =
        FridaLibraryLoader.findFunction(
            "g_idle_add",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    IDLE_CALLBACK_STUB = createIdleStub();
  }

  private static MemorySegment mainLoop = MemorySegment.NULL;
  private static volatile boolean running = false;
  private static volatile Thread loopThread = null;

  /**
   * Starts the GLib Main Loop in a background daemon thread. This method is idempotent (safe to
   * call multiple times).
   */
  public static synchronized void start() {
    if (running) return;
    running = true;

    loopThread =
        new Thread(
            () -> {
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
            },
            "Frida-Event-Loop");

    // Daemon thread ensures the JVM exits when the main application finishes.
    // If this wasn't daemon, the app would never close because this loop never ends.
    loopThread.setDaemon(true);
    loopThread.start();
  }

  /**
   * Internal utility: Executes a task on the GLib thread. If called from the GLib thread, runs
   * immediately. If called from elsewhere, schedules via g_idle_add and waits (blocking).
   */
  public static void executeBlocking(Runnable task) {
    // Optimization: If we are already on the correct thread, just run it.
    if (Thread.currentThread() == loopThread) {
      task.run();
      return;
    }

    // Otherwise, schedule and wait
    CompletableFuture<Void> future = new CompletableFuture<>();
    int taskId = taskIdGenerator.getAndIncrement();

    tasks.put(
        taskId,
        () -> {
          try {
            task.run();
            future.complete(null);
          } catch (Throwable e) {
            future.completeExceptionally(e);
          }
        });

    try {
      MemorySegment data = MemorySegment.ofAddress(taskId);
      G_IDLE_ADD.invoke(IDLE_CALLBACK_STUB, data);
      future.join(); // Block caller until done
    } catch (Throwable e) {
      throw new RuntimeException("Failed to schedule task on Frida Loop", e);
    }
  }

  // --- Native Callback Machinery ---

  private static MemorySegment createIdleStub() {
    try {
      MethodHandle handler =
          MethodHandles.lookup()
              .findStatic(
                  FridaEventLoop.class,
                  "idleCallback",
                  MethodType.methodType(boolean.class, MemorySegment.class));
      return Linker.nativeLinker()
          .upcallStub(
              handler,
              FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS),
              Arena.global());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static boolean idleCallback(MemorySegment userData) {
    int taskId = (int) userData.address();
    Runnable task = tasks.remove(taskId);
    if (task != null) task.run();
    return false; // Remove source
  }
}
