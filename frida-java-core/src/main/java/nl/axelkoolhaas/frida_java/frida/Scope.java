package nl.axelkoolhaas.frida_java.frida;

public enum Scope {
    MINIMAL(0),
    BASIC(1),
    FULL(2);

    private final int value;

    Scope(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}

