package nl.axelkoolhaas.frida_java.util;

/**
 * Enum representing supported GLib Types.
 */
public enum GType {
    // Unused, but included for completeness and potential future use
    INVALID(0),         // G_TYPE_MAKE_FUNDAMENTAL(0)
    NONE(4),            // G_TYPE_MAKE_FUNDAMENTAL(1)
    TYPE_INTERFACE(8),  // G_TYPE_MAKE_FUNDAMENTAL(2)
    CHAR(12),           // G_TYPE_MAKE_FUNDAMENTAL(3)
    UCHAR(16),          // G_TYPE_MAKE_FUNDAMENTAL(4)
    LONG(32),           // G_TYPE_MAKE_FUNDAMENTAL(8)
    ULONG(36),          // G_TYPE_MAKE_FUNDAMENTAL(9)
    INT64(40),          // G_TYPE_MAKE_FUNDAMENTAL(10)
    UINT64(44),         // G_TYPE_MAKE_FUNDAMENTAL(11)
    ENUM(48),           // G_TYPE_MAKE_FUNDAMENTAL(12)
    FLAGS(52),          // G_TYPE_MAKE_FUNDAMENTAL(13)
    FLOAT(56),          // G_TYPE_MAKE_FUNDAMENTAL(14)
    DOUBLE(60),         // G_TYPE_MAKE_FUNDAMENTAL(15)
    BOXED(72),          // G_TYPE_MAKE_FUNDAMENTAL(18)
    PARAM(76),          // G_TYPE_MAKE_FUNDAMENTAL(19)
    OBJECT(80),         // G_TYPE_MAKE_FUNDAMENTAL(20)

    // These are the types we actually use
    BOOLEAN(20),        // G_TYPE_MAKE_FUNDAMENTAL(5)
    INT(24),            // G_TYPE_MAKE_FUNDAMENTAL(6)
    UINT(28),           // G_TYPE_MAKE_FUNDAMENTAL(7)
    STRING(64),         // G_TYPE_MAKE_FUNDAMENTAL(16)
    POINTER(68);        // G_TYPE_MAKE_FUNDAMENTAL(17)

    private final long value;

    GType(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }

    public static GType fromValue(long value) {
        for (GType type : values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unsupported GType value: " + value);
    }
}

