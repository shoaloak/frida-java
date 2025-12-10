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

package nl.axelkoolhaas.frida_java;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Main Frida class
 */
public class Frida {

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup SYMBOL_LOOKUP;

    // Method handles for Frida functions
    private static final MethodHandle FRIDA_VERSION_STRING;
    private static final MethodHandle FRIDA_VERSION;

    static {
        // Load the Frida library
        SYMBOL_LOOKUP = loadFridaLibrary();

        // Initialize method handles for version functions
        FRIDA_VERSION_STRING = findFunction("frida_version_string",
            FunctionDescriptor.of(ValueLayout.ADDRESS));

        FRIDA_VERSION = findFunction("frida_version",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /**
     * Load the Frida library and return a symbol lookup.
     */
    private static SymbolLookup loadFridaLibrary() {
        String osName = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        String libName = getLibraryName(osName, arch);

        // Try to load from bins directory first
        Path binsPath = Path.of("bins", libName);
        if (Files.exists(binsPath)) {
            try {
                return SymbolLookup.libraryLookup(binsPath, Arena.global());
            } catch (IllegalArgumentException e) {
                System.err.println("Warning: Failed to load Frida library from bins directory (" + binsPath + "): " + e.getMessage());
            }
        }

        // Try to load from JAR resources
        String resourcePath = "/native/" + libName;
        try (InputStream is = Frida.class.getResourceAsStream(resourcePath)) {
            if (is != null) {
                String extension = libName.substring(libName.lastIndexOf('.'));
                Path tempFile = Files.createTempFile("libfrida-core", extension);
                Files.copy(is, tempFile, StandardCopyOption.REPLACE_EXISTING);
                tempFile.toFile().deleteOnExit();

                return SymbolLookup.libraryLookup(tempFile, Arena.global());
            }
        } catch (IOException e) {
            System.err.println("Warning: Failed to load Frida library from JAR (" + resourcePath + "): " + e.getMessage());
        }

        // Fall back to system library
        try {
            return SymbolLookup.libraryLookup("frida-core", Arena.global());
        } catch (IllegalArgumentException e) {
            throw new UnsatisfiedLinkError("Failed to load Frida library 'frida-core' for " + osName + "/" + arch + ". " +
                "Make sure the library is available in the system path, bins directory, or bundled in the JAR as " + resourcePath + ". " +
                "Original error: " + e.getMessage());
        }
    }

    /**
     * Get the platform and architecture-specific library name.
     */
    private static String getLibraryName(String osName, String arch) {
        if (osName.contains("mac")) {
            return "libfrida-core.dylib";
        }
        if (osName.contains("linux")) {
            if (arch.contains("amd64") || arch.contains("x86_64")) {
                return "libfrida-core-x86_64.so";
            } else if (arch.contains("aarch64") || arch.contains("arm64")) {
                return "libfrida-core-arm64.so";
            }
            throw new UnsatisfiedLinkError("Unsupported Linux architecture: " + arch);
        }
        if (osName.contains("windows")) {
            if (arch.contains("amd64") || arch.contains("x86_64")) {
                return "libfrida-core-x86_64.dll";
            } else if (arch.contains("aarch64") || arch.contains("arm64")) {
                return "libfrida-core-arm64.dll";
            }
            throw new UnsatisfiedLinkError("Unsupported Windows architecture: " + arch);
        }
        throw new UnsatisfiedLinkError("Unsupported operating system: " + osName);
    }

    /**
     * Find a function in the Frida library and create a method handle.
     */
    private static MethodHandle findFunction(String name, FunctionDescriptor descriptor) {
        return SYMBOL_LOOKUP.find(name)
            .map(addr -> LINKER.downcallHandle(addr, descriptor))
            .orElseThrow(() -> new UnsatisfiedLinkError("Function not found: " + name));
    }

    /**
     * Get the Frida version as a string.
     * @return Version string (e.g., "17.5.1")
     */
    public static String getVersionString() {
        try {
            MemorySegment result = (MemorySegment) FRIDA_VERSION_STRING.invoke();
            // Read the C string using UTF-8 encoding, searching for null terminator
            return result.reinterpret(Long.MAX_VALUE).getString(0, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get Frida version string", e);
        }
    }

    /**
     * Get the Frida version components.
     * @return Array containing [major, minor, micro, nano] version numbers
     */
    public static int[] getVersion() {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate memory for the four version components
            MemorySegment major = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment minor = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment micro = arena.allocate(ValueLayout.JAVA_INT);
            MemorySegment nano = arena.allocate(ValueLayout.JAVA_INT);

            // Call frida_version function
            FRIDA_VERSION.invoke(major, minor, micro, nano);

            // Extract values and return as array
            return new int[] {
                major.get(ValueLayout.JAVA_INT, 0),
                minor.get(ValueLayout.JAVA_INT, 0),
                micro.get(ValueLayout.JAVA_INT, 0),
                nano.get(ValueLayout.JAVA_INT, 0)
            };
        } catch (Throwable e) {
            throw new RuntimeException("Failed to get Frida version", e);
        }
    }

    /**
     * Get the major version number.
     * @return Major version number
     */
    public static int getMajorVersion() {
        int[] version = getVersion();
        return version[0];
    }

    /**
     * Get the minor version number.
     * @return Minor version number
     */
    public static int getMinorVersion() {
        int[] version = getVersion();
        return version[1];
    }

    /**
     * Get the micro version number.
     * @return Micro version number
     */
    public static int getMicroVersion() {
        int[] version = getVersion();
        return version[2];
    }

    /**
     * Get the nano version number.
     * @return Nano version number
     */
    public static int getNanoVersion() {
        int[] version = getVersion();
        return version[3];
    }
}
