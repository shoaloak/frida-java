package nl.axelkoolhaas.examples;

import nl.axelkoolhaas.FridaJava;

/**
 * Simple example demonstrating basic Frida Java bindings usage.
 * This example shows how to initialize Frida and get version information.
 */
public class BasicExample {

    public static void main(String[] args) {
        System.out.println("Frida Java Bindings - Basic Example");
        System.out.println("===================================");

        try {
            // Initialize Frida
            FridaJava.init();
            System.out.println("Frida initialized successfully");

            // Get version information
            String versionString = FridaJava.getVersionString();
            System.out.println("Frida version string: " + versionString);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Clean up
            FridaJava.deinit();
            System.out.println("✓ Frida deinitialized");
        }
    }
}
