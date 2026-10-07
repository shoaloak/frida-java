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

package nl.axelkoolhaas.frida_java.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import nl.axelkoolhaas.frida_java.util.GType;

/** Unit tests for GLib GType decoding. */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class GTypeTest {

  @Test
  @Order(1)
  void testFromValueResolvesExactFundamentalType() {
    assertEquals(GType.INT, GType.fromValue(GType.INT.getValue()));
  }

  @Test
  @Order(2)
  void testFromValueResolvesDerivedEnumTypeToFundamentalEnum() {
    long derivedEnumType = GType.ENUM.getValue() | (1L << 12);
    assertEquals(GType.ENUM, GType.fromValue(derivedEnumType));
  }

  @Test
  @Order(3)
  void testFromValueRejectsUnsupportedType() {
    assertThrows(IllegalArgumentException.class, () -> GType.fromValue(88L));
  }
}
