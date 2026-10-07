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

package nl.axelkoolhaas.frida_java.model;

import java.lang.foreign.MemorySegment;

/**
 * Represents a device icon in Frida. Wraps a GVariant pointer containing platform-specific icon
 * data (e.g., PNG).
 *
 * <p>Note: This is an untested abstraction but added for completeness.
 */
public class Icon {
  private final MemorySegment variantPtr;

  public Icon(MemorySegment variantPtr) {
    if (variantPtr == null || variantPtr.equals(MemorySegment.NULL)) {
      throw new IllegalArgumentException("Icon variant pointer cannot be null");
    }
    this.variantPtr = variantPtr;
  }

  /**
   * Get the raw GVariant pointer for parsing icon data. The variant typically contains image data
   * in a platform-specific format.
   *
   * @return MemorySegment pointing to the GVariant structure
   */
  public MemorySegment getVariantPointer() {
    return variantPtr;
  }

  @Override
  public String toString() {
    return "Icon{variantPtr=" + variantPtr + "}";
  }
}
