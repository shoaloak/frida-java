/*
 * Copyright (C) 2026 Axel Koolhaas
 *
 * This file is part of frida-java.
 *
 * frida-java is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * frida-java is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with frida-java.  If not, see <https://www.gnu.org/licenses/>.
 */

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

