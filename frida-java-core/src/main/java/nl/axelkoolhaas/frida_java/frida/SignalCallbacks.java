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
 * Interface definitions for all Frida signals.
 * Signatures are strictly mapped to the Vala/C implementation in frida-core.
 */
public final class SignalCallbacks {
    private SignalCallbacks() {}

    /* --- Common Signals --- */

    /**
     * Called for signals with no arguments other than the instance.
     * Used for: starting, finished, file-changed, destroyed, lost, changed.
     */
    @FunctionalInterface
    public interface VoidCallback {
        void onAction();
    }

    /* --- Script & Bus Signals --- */

    /**
     * Vala: void message (string json, Bytes? data)
     */
    @FunctionalInterface
    public interface MessageCallback {
        void onMessage(String json, byte[] data);
    }

    /* --- Session Signals --- */

    /**
     * Vala: void detached (SessionDetachReason reason, Crash? crash)
     */
    @FunctionalInterface
    public interface SessionDetachedCallback {
        void onDetach(int reason, Crash crash);
    }

    /* --- Device & Process Signals --- */

    /**
     * Vala: void added (Device device) / void removed (Device device)
     */
    @FunctionalInterface
    public interface DeviceCallback {
        void onAction(Device device);
    }

    /**
     * Vala: void spawn_added (Spawn spawn) / void spawn_removed (Spawn spawn)
     */
    @FunctionalInterface
    public interface SpawnCallback {
        void onSpawn(Spawn spawn);
    }

    /**
     * Vala: void child_added (Child child) / void child_removed (Child child)
     */
    @FunctionalInterface
    public interface ChildCallback {
        void onChild(Child child);
    }

    /**
     * Vala: void process_added (Process process) / void process_removed (Process process)
     */
    @FunctionalInterface
    public interface ProcessCallback {
        void onProcess(Process process);
    }

    /**
     * Vala: void crashed (Crash crash)
     */
    @FunctionalInterface
    public interface CrashCallback {
        void onCrash(Crash crash);
    }

    /**
     * Vala: void uninjected (uint id)
     */
    @FunctionalInterface
    public interface UninjectedCallback {
        void onUninjected(int id);
    }

    /* --- Output Signals --- */

    /**
     * Vala: void output (uint pid, int fd, uint8[] data)
     */
    @FunctionalInterface
    public interface DeviceOutputCallback {
        void onOutput(int pid, int fd, byte[] data);
    }

    /**
     * Vala: void output (int fd, uint8[] data)
     */
    @FunctionalInterface
    public interface ProcessOutputCallback {
        void onOutput(int fd, byte[] data);
    }

    /* --- Compiler Signals --- */

    /**
     * Vala: void output (Bundle bundle, Options options)
     */
    @FunctionalInterface
    public interface CompilerOutputCallback {
        void onOutput(String bundle, CompilerOptions options);
    }

    /**
     * Vala: void diagnostics (Diagnostics diag)
     */
    @FunctionalInterface
    public interface CompilerDiagnosticsCallback {
        void onDiagnostics(String diagnostics);
    }

    /* --- Infrastructure --- */

    /**
     * Global error handler for exceptions occurring within callbacks.
     */
    @FunctionalInterface
    public interface ErrorHandler {
        void onCallbackError(String signal, Throwable error);
    }
}