package nl.axelkoolhaas.frida_java.frida;

/**
 * Base exception for all Frida-related errors.
 */
public class FridaException extends RuntimeException {
    public FridaException(String message) {
        super(message);
    }
    public FridaException(String message, Throwable cause) {
        super(message, cause);
    }
}

