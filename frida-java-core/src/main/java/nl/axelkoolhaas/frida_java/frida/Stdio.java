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

/** Standard input/output options for spawned processes */
public enum Stdio {
  INHERIT(0),
  PIPE(1);

  private final int value;

  Stdio(int value) {
    this.value = value;
  }

  public int getValue() {
    return value;
  }

  public static Stdio fromValue(int value) {
    for (Stdio stdio : values()) {
      if (stdio.value == value) {
        return stdio;
      }
    }
    throw new IllegalArgumentException("Unknown Stdio value: " + value);
  }
}
