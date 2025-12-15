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

package nl.axelkoolhaas.frida_java.feature;

import nl.axelkoolhaas.frida_java.frida.Frida;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Frida version-related functionality.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class VersionTest {


    @Test
    @Order(1)
    void testGetVersionString() {
        String version = Frida.getVersion();
        assertNotNull(version);
        assertFalse(version.isEmpty());
        System.out.println("Frida version string: " + version);
    }

}
