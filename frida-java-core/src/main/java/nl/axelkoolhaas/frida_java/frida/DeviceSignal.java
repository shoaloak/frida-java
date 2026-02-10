/*
 * Copyright (C) 2025 Axel Koolhaas
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

import java.util.HashMap;
import java.util.Map;

/**
 * Available signals for the Device.
 */
public enum DeviceSignal {
    /** Emitted with output from the device. Callback: {@code SignalCallbacks.OutputCallback} */
    OUTPUT("output"),
    /** Emitted when a spawn is added. Callback: {@code SignalCallbacks.SpawnCallback} */
    SPAWN_ADDED("spawn-added"),
    /** Emitted when a spawn is removed. Callback: {@code SignalCallbacks.SpawnCallback} */
    SPAWN_REMOVED("spawn-removed"),
    /** Emitted when a child process is added. Callback: {@code SignalCallbacks.ChildCallback} */
    CHILD_ADDED("child-added"),
    /** Emitted when a child process is removed. Callback: {@code SignalCallbacks.ChildCallback} */
    CHILD_REMOVED("child-removed"),
    /** Emitted when a process crashes. Callback: {@code SignalCallbacks.CrashCallback} */
    PROCESS_CRASHED("process-crashed"),
    /** Emitted when a process is uninjected. Callback: {@code SignalCallbacks.UninjectedCallback} */
    UNINJECTED("uninjected"),
    /** Emitted when the device is lost. Callback: {@code Runnable} */
    LOST("lost");

    // Map for reverse lookup by native signal name
    private static final Map<String, DeviceSignal> BY_NAME = new HashMap<>();
    static {
        for (DeviceSignal s : values()) {
            BY_NAME.put(s.name, s);
        }
    }

    private final String name;

    DeviceSignal(String name) {
        this.name = name;
    }

    /**
     * Get the native signal name.
     */
    public String getName() {
        return name;
    }

    /**
     * Lookup a DeviceSignals enum by its native signal name.
     * @param name the native signal name
     * @return the corresponding DeviceSignals, or null if not found
     */
    public static DeviceSignal fromName(String name) {
        return BY_NAME.get(name);
    }
}
