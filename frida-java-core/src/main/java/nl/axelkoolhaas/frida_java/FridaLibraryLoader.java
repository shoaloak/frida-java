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

import nl.axelkoolhaas.frida_java.frida.Frida;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class FridaLibraryLoader {
    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LOADED_LIBRARY;

    static {
        LOADED_LIBRARY = loadFridaLibrary();
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
    public static MethodHandle findFunction(String name, FunctionDescriptor descriptor) {
        return LOADED_LIBRARY.find(name)
                .map(addr -> LINKER.downcallHandle(addr, descriptor))
                .orElse(null);
    }
}
