package nl.axelkoolhaas.frida_java.frida.callbacks;

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

    // ... other callback types
}
