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
 * Snapshot transport mechanism
 */
public enum SnapshotTransport {
    INLINE(0),
    SHARED_MEMORY(1);

    private final int value;

    SnapshotTransport(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static SnapshotTransport fromValue(int value) {
        for (SnapshotTransport transport : values()) {
            if (transport.value == value) {
                return transport;
            }
        }
        throw new IllegalArgumentException("Unknown SnapshotTransport value: " + value);
    }
}

