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

import nl.axelkoolhaas.frida_java.Frida;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Frida version-related functionality.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class VersionTest {

    @BeforeAll
    static void setUp() {
        Frida.init();
    }

    @AfterAll
    static void tearDown() {
        Frida.deinit();
    }

    @Test
    @Order(1)
    void testGetVersionString() {
        String version = Frida.getVersionString();
        assertNotNull(version);
        assertFalse(version.isEmpty());
        System.out.println("Frida version string: " + version);
    }

    @Test
    @Order(2)
    void testGetVersion() {
        int[] version = Frida.getVersion();
        assertNotNull(version);
        assertEquals(4, version.length);

        // Version numbers should be non-negative
        for (int v : version) {
            assertTrue(v >= 0);
        }

        System.out.printf("Frida version: %d.%d.%d.%d%n",
            version[0], version[1], version[2], version[3]);
    }

    @Test
    @Order(3)
    void testVersionComponents() {
        int major = Frida.getMajorVersion();
        int minor = Frida.getMinorVersion();
        int micro = Frida.getMicroVersion();
        int nano = Frida.getNanoVersion();

        assertTrue(major >= 0);
        assertTrue(minor >= 0);
        assertTrue(micro >= 0);
        assertTrue(nano >= 0);

        System.out.printf("Version components - Major: %d, Minor: %d, Micro: %d, Nano: %d%n",
            major, minor, micro, nano);
    }

    @Test
    @Order(4)
    void testVersionConsistency() {
        String versionString = Frida.getVersionString();
        int[] versionArray = Frida.getVersion();

        // The version string should contain the major.minor.micro components
        String expectedPrefix = String.format("%d.%d.%d",
            versionArray[0], versionArray[1], versionArray[2]);

        assertTrue(versionString.startsWith(expectedPrefix),
            "Version string should start with " + expectedPrefix + " but was: " + versionString);
    }
}
