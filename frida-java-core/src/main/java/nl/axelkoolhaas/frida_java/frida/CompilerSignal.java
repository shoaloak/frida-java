package nl.axelkoolhaas.frida_java.frida;

/**
 * Available signals for the Compiler.
 */
public enum CompilerSignal {
    /** Emitted when compilation starts. Callback: {@code Runnable} */
    STARTING("starting"),
    /** Emitted when compilation finishes. Callback: {@code Runnable} */
    FINISHED("finished"),
    /** Emitted with compiled bundle. Callback: {@code SignalCallbacks.CompilerOutputCallback} */
    OUTPUT("output"),
    /** Emitted with diagnostic messages. Callback: {@code SignalCallbacks.CompilerDiagnosticsCallback} */
    DIAGNOSTICS("diagnostics"),
    /** Emitted when a watched file changes. Callback: {@code Runnable} */
    FILE_CHANGED("file-changed");

    private final String name;

    CompilerSignal(String name) {
        this.name = name;
    }

    /**
     * Get the native signal name.
     */
    public String getName() {
        return name;
    }
}

