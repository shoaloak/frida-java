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

/** Available signals for the Device. */
public enum DeviceSignal {
  SPAWN_ADDED("spawn-added"),
  SPAWN_REMOVED("spawn-removed"),
  CHILD_ADDED("child-added"),
  CHILD_REMOVED("child-removed"),
  PROCESS_ADDED("process-added"),
  PROCESS_REMOVED("process-removed"),
  PROCESS_CRASHED("crashed"),
  OUTPUT("output"),
  UNINJECTED("uninjected"),
  LOST("lost");

  private final String name;

  DeviceSignal(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }
}
