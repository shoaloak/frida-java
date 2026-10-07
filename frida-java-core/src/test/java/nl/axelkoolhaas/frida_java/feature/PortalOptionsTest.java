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

package nl.axelkoolhaas.frida_java.feature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import nl.axelkoolhaas.frida_java.frida.PortalOptions;

public class PortalOptionsTest {

  @Test
  void testCreatePortalOptions() {
    try (PortalOptions options = new PortalOptions()) {
      assertNotNull(options);
    }
  }

  @Test
  void testSetAndGetToken() {
    try (PortalOptions options = new PortalOptions()) {
      String token = "portal-token";
      options.setToken(token);
      assertEquals(token, options.getToken());
    }
  }

  @Test
  void testSetAndGetAcl() {
    try (PortalOptions options = new PortalOptions()) {
      List<String> acl = List.of("scope:read", "scope:write");
      options.setAcl(acl);
      List<String> actualAcl = options.getAcl();
      assertTrue(actualAcl.containsAll(acl));
    }
  }
}
