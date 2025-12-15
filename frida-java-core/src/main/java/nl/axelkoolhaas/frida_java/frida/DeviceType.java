package nl.axelkoolhaas.frida_java.frida;

public enum DeviceType {
    LOCAL(0),
    REMOTE(1),
    USB(2);

    private final int value;

    DeviceType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static DeviceType fromValue(int value) {
        for (DeviceType type : values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown device type: " + value);
    }
}

