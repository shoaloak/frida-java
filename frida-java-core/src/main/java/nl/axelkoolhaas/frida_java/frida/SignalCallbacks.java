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
 * Utility class containing all signal callback interfaces for Frida device and process events.
 */
public final class SignalCallbacks {
    private SignalCallbacks() {}

    // General Signal Callbacks
    @FunctionalInterface
    public interface MessageCallback {
        void onMessage(String message, byte[] data);
    }

    // Device/Process Signal Callbacks
    @FunctionalInterface
    public interface ProcessOutputCallback {
        void onOutput(int pid, int fd, byte[] data);
    }

    /**
     * Callback interface for device output events (stdout/stderr from spawned processes)
     */
    @FunctionalInterface
    public interface OutputCallback {
        void onOutput(int pid, int fd, byte[] data);
    }

    @FunctionalInterface
    public interface SpawnCallback {
        void onSpawn(Spawn spawn);
    }

    @FunctionalInterface
    public interface ChildCallback {
        void onChild(Child child);
    }

    @FunctionalInterface
    public interface CrashCallback {
        void onCrash(Crash crash);
    }

    @FunctionalInterface
    public interface UninjectedCallback {
        void onUninjected(String id);
    }

    // Compiler Signal Callbacks
    @FunctionalInterface
    public interface CompilerOutputCallback {
        void onOutput(String bundle);
    }

    @FunctionalInterface
    public interface CompilerDiagnosticsCallback {
        void onDiagnostics(String diagnostics);
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
