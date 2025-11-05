package nl.axelkoolhaas;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Main FridaJava class providing version information and core initialization.
 */
public class FridaJava {

    static {
        loadNativeLibrary();
    }

    /**
     * Load the native library from JAR resources or fall back to system library.
     */
    private static void loadNativeLibrary() {
        String osName = System.getProperty("os.name").toLowerCase();
        String libName = getLibraryName(osName);
        
        // Try to load from JAR resources first
        try (InputStream is = FridaJava.class.getResourceAsStream("/native/" + libName)) {
            if (is != null) {
                // Extract library to temporary file
                String libExtension = getLibraryExtension(osName);
                Path tempFile = Files.createTempFile("libfrida-java", libExtension);
                Files.copy(is, tempFile, StandardCopyOption.REPLACE_EXISTING);
                tempFile.toFile().deleteOnExit();
                
                // Load the extracted library
                System.load(tempFile.toAbsolutePath().toString());
                return;
            }
        } catch (IOException e) {
            // Fall through to system library loading
            System.err.println("Warning: Failed to load native library from JAR: " + e.getMessage());
        }
        
        // Fallback to system library loading
        try {
            System.loadLibrary("frida-java");
        } catch (UnsatisfiedLinkError e) {
            throw new UnsatisfiedLinkError("Failed to load native library 'frida-java'. " +
                "Make sure the library is available in java.library.path or bundled in the JAR. " +
                "Original error: " + e.getMessage());
        }
    }
    
    /**
     * Get the platform-specific library name.
     */
    private static String getLibraryName(String osName) {
        if (osName.contains("mac")) return "libfrida-java.dylib";
        if (osName.contains("linux")) return "libfrida-java.so";
        if (osName.contains("windows")) return "frida-java.dll";
        throw new UnsatisfiedLinkError("Unsupported operating system: " + osName);
    }
    
    /**
     * Get the platform-specific library file extension.
     */
    private static String getLibraryExtension(String osName) {
        if (osName.contains("mac")) return ".dylib";
        if (osName.contains("linux")) return ".so";
        if (osName.contains("windows")) return ".dll";
        throw new UnsatisfiedLinkError("Unsupported operating system: " + osName);
    }

    /**
     * Get the Frida version as a string.
     * @return Version string (e.g., "16.1.4")
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
}
