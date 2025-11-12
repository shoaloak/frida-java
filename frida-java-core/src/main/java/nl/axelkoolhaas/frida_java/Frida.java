package nl.axelkoolhaas.frida_java;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Main Frida class providing version information and core initialization.
 */
public class Frida {

    static {
        loadNativeLibrary();
    }

    /**
     * Load the native library from JAR resources or fall back to system library.
     */
    private static void loadNativeLibrary() {
        String osName = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        String libName = getLibraryName(osName, arch);

        // Try to load the platform-specific library from JAR resources
        String resourcePath = "/native/" + libName;
        try (InputStream is = Frida.class.getResourceAsStream(resourcePath)) {
            if (is != null) {
                // Extract the platform-specific library to temporary file
                String extension = libName.substring(libName.lastIndexOf('.'));
                Path tempFile = Files.createTempFile("libfrida-java", extension);
                Files.copy(is, tempFile, StandardCopyOption.REPLACE_EXISTING);
                tempFile.toFile().deleteOnExit();
                
                // Load the extracted library
                System.load(tempFile.toAbsolutePath().toString());
                return;
            }
        } catch (IOException e) {
            // Fall through to system library loading
            System.err.println("Warning: Failed to load native library from JAR (" + resourcePath + "): " + e.getMessage());
        }
        
        // Fallback to system library loading
        try {
            System.loadLibrary("frida-java");
        } catch (UnsatisfiedLinkError e) {
            throw new UnsatisfiedLinkError("Failed to load native library 'frida-java' for " + osName + "/" + arch + ". " +
                "Make sure the library is available in java.library.path or bundled in the JAR as " + resourcePath + ". " +
                "Original error: " + e.getMessage());
        }
    }
    
    /**
     * Get the platform and architecture-specific library name.
     */
    private static String getLibraryName(String osName, String arch) {
        if (osName.contains("mac")) {
            return "libfrida-java.dylib"; // Universal fat binary for macOS
        }
        if (osName.contains("linux")) {
            if (arch.contains("amd64") || arch.contains("x86_64")) {
                return "libfrida-java-x86_64.so";
            } else if (arch.contains("aarch64") || arch.contains("arm64")) {
                return "libfrida-java-arm64.so";
            }
            throw new UnsatisfiedLinkError("Unsupported Linux architecture: " + arch);
        }
        if (osName.contains("windows")) {
            throw new UnsatisfiedLinkError("Windows is currently not supported.");
//            return "frida-java.dll";
        }
        throw new UnsatisfiedLinkError("Unsupported operating system: " + osName);
    }

    /**
     * Get the Frida version as a string.
     * @return Version string (e.g., "17.5.1")
     */
    public static native String getVersionString();

    /**
     * Get the Frida version components.
     * @return Array containing [major, minor, micro, nano] version numbers
     */
    public static native int[] getVersion();

    /**
     * Initialize Frida core.
     * Must be called before using any other Frida functionality.
     */
    public static native void init();

    /**
     * Deinitialize Frida core.
     * Should be called when done using Frida.
     */
    public static native void deinit();

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

    private Frida() {
        // Prevent instantiation
    }
}
