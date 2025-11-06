package nl.axelkoolhaas.frida_java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Frida version-related functionality.
 */
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
    void testGetVersionString() {
        String version = Frida.getVersionString();
        assertNotNull(version);
        assertFalse(version.isEmpty());
        System.out.println("Frida version string: " + version);
    }

    @Test
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
