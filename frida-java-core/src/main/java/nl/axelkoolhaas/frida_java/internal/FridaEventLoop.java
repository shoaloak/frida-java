package nl.axelkoolhaas.frida_java.internal;

/**
 * Obsolete event loop class retained for API compatibility.
 *
 * <p>frida-core runs its own worker thread and private GMainContext, started by frida_init(), and
 * pumps it itself. The bindings must not run a host GLib main loop. This class is now a no-op.
 *
 * <p>This class is internal API. Users should not interact with it directly.
 *
 * @deprecated No longer needed; frida-core manages its own event loop. Will be removed in a future
 *     release.
 */
@Deprecated
public class FridaEventLoop {

  /**
   * No-op. frida-core manages its own event loop.
   *
   * @deprecated Will be removed in a future release.
   */
  @Deprecated
  public static void start() {}

  /**
   * Runs the task directly on the calling thread. frida-core's *_sync functions already marshal
   * work onto its own context, so no scheduling is needed.
   *
   * @deprecated Will be removed in a future release.
   */
  @Deprecated
  public static void executeBlocking(Runnable task) {
    task.run();
  }
}
