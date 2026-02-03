package nl.axelkoolhaas.frida_java.frida;

public final class SignalCallbacks {
    private SignalCallbacks() {} // Utility class

    @FunctionalInterface
    public interface MessageCallback {
        void onMessage(String message, byte[] data);
    }

    @FunctionalInterface
    public interface OutputCallback {
        void onOutput(int pid, int fd, byte[] data);
    }

    /**
     * Handler for exceptions thrown by signal callbacks.
     * Since callbacks are invoked from native code, exceptions cannot propagate
     * through the native boundary. Register an error handler to be notified
     * when a callback fails.
     */
    @FunctionalInterface
    public interface ErrorHandler {
        void onCallbackError(String signal, Exception error);
    }

}
