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
import java.util.Optional;

import nl.axelkoolhaas.frida_java.frida.Frida;
import nl.axelkoolhaas.frida_java.frida.FridaException;

public class FridaLibraryLoader {
  private static OperatingSystem currentOs;
  private static final Linker LINKER = Linker.nativeLinker();
  private static final SymbolLookup LOADED_LIBRARY;

  static {
    LOADED_LIBRARY = loadFridaLibrary();
  }

  /** Load the Frida library and return a symbol lookup. */
  private static SymbolLookup loadFridaLibrary() {
    String osName = System.getProperty("os.name").toLowerCase();
    String arch = System.getProperty("os.arch").toLowerCase();
    String libName = getLibraryNameAndSetOs(osName, arch);

    // Try to load from bins directory first
    Path binsPath = Path.of("bins", libName);
    if (Files.exists(binsPath)) {
      try {
        return SymbolLookup.libraryLookup(binsPath, Arena.global());
      } catch (IllegalArgumentException e) {
        System.err.println(
            "Warning: Failed to load Frida library from bins directory ("
                + binsPath
                + "): "
                + e.getMessage());
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
      System.err.println(
          "Warning: Failed to load Frida library from JAR ("
              + resourcePath
              + "): "
              + e.getMessage());
    }

    // Fall back to system library
    try {
      return SymbolLookup.libraryLookup("frida-core", Arena.global());
    } catch (IllegalArgumentException e) {
      throw new UnsatisfiedLinkError(
          "Failed to load Frida library 'frida-core' for "
              + osName
              + "/"
              + arch
              + ". "
              + "Make sure the library is available in the system path, bins directory, or bundled in the JAR as "
              + resourcePath
              + ". "
              + "Original error: "
              + e.getMessage());
    }
  }

  /** Get the platform and architecture-specific library name. */
  private static String getLibraryNameAndSetOs(String osName, String arch) {
    if (osName.contains("mac")) {
      currentOs = OperatingSystem.MACOS;
      return "libfrida-core.dylib";
    }
    if (osName.contains("linux")) {
      currentOs = OperatingSystem.LINUX;
      if (arch.contains("amd64") || arch.contains("x86_64")) {
        return "libfrida-core-x86_64.so";
      } else if (arch.contains("aarch64") || arch.contains("arm64")) {
        return "libfrida-core-arm64.so";
      }
      throw new UnsatisfiedLinkError("Unsupported Linux architecture: " + arch);
    }
    if (osName.contains("windows")) {
      currentOs = OperatingSystem.WINDOWS;
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
   * Find and return a method handle for a native function.
   *
   * @param name The name of the function to find
   * @param descriptor The function descriptor
   * @return Method handle for the function, or null if not found
   */
  public static MethodHandle findFunction(String name, FunctionDescriptor descriptor) {
    // Try the exact name first (works for Windows and some Linux/macOS symbols)
    Optional<MemorySegment> addr = LOADED_LIBRARY.find(name);

    // If not found, fall back to OS-specific mangling
    if (addr.isEmpty()) {
      addr =
          switch (currentOs) {
            case LINUX -> LOADED_LIBRARY.find("_frida_" + name);
            case MACOS -> LOADED_LIBRARY.find("_" + name);
            default -> Optional.empty();
          };
    }

    // Map to Handle or throw
    return addr.map(a -> LINKER.downcallHandle(a, descriptor))
        .orElseThrow(() -> new FridaException("Required native function not found: " + name));
  }
}
