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

import nl.axelkoolhaas.frida_java.frida.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for Compiler-related Frida bindings.
 * Tests compilation, compiler options, and signal handling functionality.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CompilerTest {

    @TempDir
    Path tempDir;

    // ===========================================
    // Constructor Tests (1-10)
    // ===========================================

    @Test
    @Order(1)
    void testCreateCompilerWithDefaultConstructor() {
        try (Compiler compiler = new Compiler()) {
            assertNotNull(compiler, "Compiler should not be null");
            System.out.println("Compiler created successfully with default constructor");
        }
    }

    @Test
    @Order(2)
    void testCreateCompilerWithDeviceManager() {
        try (DeviceManager manager = new DeviceManager();
             Compiler compiler = new Compiler(manager)) {
            assertNotNull(compiler, "Compiler should not be null");
            System.out.println("Compiler created successfully with DeviceManager");
        }
    }

    @Test
    @Order(3)
    void testCompilerIsAutoCloseable() {
        try (Compiler compiler = new Compiler()) {
            assertNotNull(compiler);
        }
        System.out.println("Compiler AutoCloseable works correctly");
    }

    // ===========================================
    // CompilerOptions Tests (10-20)
    // ===========================================

    @Test
    @Order(10)
    void testCreateCompilerOptionsWithDefaults() {
        try (CompilerOptions options = new CompilerOptions()) {
            assertNotNull(options, "CompilerOptions should not be null");
            System.out.println("CompilerOptions created successfully with defaults");
        }
    }

    @Test
    @Order(11)
    void testCompilerOptionsSetProjectRoot() {
        try (CompilerOptions options = new CompilerOptions()) {
            options.setProjectRoot(tempDir.toString());
            System.out.println("Set project root: " + tempDir);
        }
    }

    @Test
    @Order(12)
    void testCompilerOptionsSetJsCompression() {
        try (CompilerOptions options = new CompilerOptions()) {
            options.setJsCompression(CompilerOptions.JsCompression.NONE);
            options.setJsCompression(CompilerOptions.JsCompression.TERSER);
            System.out.println("Set JS compression options successfully");
        }
    }

    @Test
    @Order(13)
    void testCompilerOptionsSetSourceMaps() {
        try (CompilerOptions options = new CompilerOptions()) {
            options.setSourceMaps(CompilerOptions.SourceMaps.OMITTED);
            options.setSourceMaps(CompilerOptions.SourceMaps.INCLUDED);
            System.out.println("Set source maps options successfully");
        }
    }

    @Test
    @Order(14)
    void testCompilerOptionsIsAutoCloseable() {
        try (CompilerOptions options = new CompilerOptions()) {
            assertNotNull(options);
        }
        System.out.println("CompilerOptions AutoCloseable works correctly");
    }

    // ===========================================
    // CompilerSignal Enum Tests (20-30)
    // ===========================================

    @Test
    @Order(20)
    void testCompilerSignalEnumValues() {
        CompilerSignal[] signals = CompilerSignal.values();
        assertEquals(5, signals.length, "Should have 5 compiler signals");
        System.out.println("CompilerSignal enum has " + signals.length + " values");
    }

    @Test
    @Order(21)
    void testCompilerSignalNames() {
        assertEquals("starting", CompilerSignal.STARTING.getName());
        assertEquals("finished", CompilerSignal.FINISHED.getName());
        assertEquals("output", CompilerSignal.OUTPUT.getName());
        assertEquals("diagnostics", CompilerSignal.DIAGNOSTICS.getName());
        assertEquals("file-changed", CompilerSignal.FILE_CHANGED.getName());
        System.out.println("CompilerSignal names are correct");
    }

    // ===========================================
    // Signal Connection Tests (30-50)
    // ===========================================

    @Test
    @Order(30)
    void testConnectToStartingSignal() {
        try (Compiler compiler = new Compiler()) {
            AtomicBoolean called = new AtomicBoolean(false);
            compiler.on(CompilerSignal.STARTING, (Runnable) () -> called.set(true));
            System.out.println("Connected to STARTING signal successfully");
        }
    }

    @Test
    @Order(31)
    void testConnectToFinishedSignal() {
        try (Compiler compiler = new Compiler()) {
            AtomicBoolean called = new AtomicBoolean(false);
            compiler.on(CompilerSignal.FINISHED, (Runnable) () -> called.set(true));
            System.out.println("Connected to FINISHED signal successfully");
        }
    }

    @Test
    @Order(32)
    void testConnectToOutputSignal() {
        try (Compiler compiler = new Compiler()) {
            AtomicReference<String> output = new AtomicReference<>();
            compiler.on(CompilerSignal.OUTPUT, (SignalCallbacks.CompilerOutputCallback) output::set);
            System.out.println("Connected to OUTPUT signal successfully");
        }
    }

    @Test
    @Order(33)
    void testConnectToDiagnosticsSignal() {
        try (Compiler compiler = new Compiler()) {
            AtomicReference<String> diag = new AtomicReference<>();
            compiler.on(CompilerSignal.DIAGNOSTICS, (SignalCallbacks.CompilerDiagnosticsCallback) diag::set);
            System.out.println("Connected to DIAGNOSTICS signal successfully");
        }
    }

    @Test
    @Order(34)
    void testConnectToFileChangedSignal() {
        try (Compiler compiler = new Compiler()) {
            AtomicBoolean called = new AtomicBoolean(false);
            compiler.on(CompilerSignal.FILE_CHANGED, (Runnable) () -> called.set(true));
            System.out.println("Connected to FILE_CHANGED signal successfully");
        }
    }

    @Test
    @Order(35)
    void testDisconnectFromSignal() {
        try (Compiler compiler = new Compiler()) {
            compiler.on(CompilerSignal.STARTING, (Runnable) () -> {});
            compiler.off(CompilerSignal.STARTING);
            System.out.println("Disconnected from STARTING signal successfully");
        }
    }

    @Test
    @Order(36)
    void testThrowsForNullCallback() {
        try (Compiler compiler = new Compiler()) {
            assertThrows(IllegalArgumentException.class, () ->
                    compiler.on(CompilerSignal.STARTING, null)
            );
            System.out.println("Correctly throws for null callback");
        }
    }

    @Test
    @Order(37)
    void testThrowsForWrongCallbackTypeOnStarting() {
        try (Compiler compiler = new Compiler()) {
            assertThrows(IllegalArgumentException.class, () ->
                    compiler.on(CompilerSignal.STARTING, "not a runnable")
            );
            System.out.println("Correctly throws for wrong callback type on STARTING");
        }
    }

    @Test
    @Order(38)
    void testThrowsForWrongCallbackTypeOnOutput() {
        try (Compiler compiler = new Compiler()) {
            assertThrows(IllegalArgumentException.class, () ->
                    compiler.on(CompilerSignal.OUTPUT, (Runnable) () -> {})
            );
            System.out.println("Correctly throws for wrong callback type on OUTPUT");
        }
    }

    @Test
    @Order(39)
    void testThrowsForWrongCallbackTypeOnDiagnostics() {
        try (Compiler compiler = new Compiler()) {
            assertThrows(IllegalArgumentException.class, () ->
                    compiler.on(CompilerSignal.DIAGNOSTICS, (Runnable) () -> {})
            );
            System.out.println("Correctly throws for wrong callback type on DIAGNOSTICS");
        }
    }

    // ===========================================
    // Build Tests (50-70)
    // ===========================================

    @Test
    @Order(50)
    void testBuildSimpleJavaScriptFile() throws IOException {
        Path scriptPath = tempDir.resolve("agent.js");
        Files.writeString(scriptPath, "console.log('Hello from Frida');");

        try (Compiler compiler = new Compiler()) {
            String result = compiler.build(scriptPath.toString());

            assertNotNull(result, "Build result should not be null");
            assertFalse(result.isEmpty(), "Build result should not be empty");
            System.out.println("Built simple JavaScript file, output size: " + result.length() + " bytes");
        }
    }

    @Test
    @Order(51)
    void testBuildTypeScriptFile() throws IOException {
        Path scriptPath = tempDir.resolve("agent.ts");
        Files.writeString(scriptPath, """
            const message: string = "Hello from TypeScript";
            console.log(message);
            """);

        try (Compiler compiler = new Compiler()) {
            String result = compiler.build(scriptPath.toString());

            assertNotNull(result, "Build result should not be null");
            assertFalse(result.isEmpty(), "Build result should not be empty");
            System.out.println("Built TypeScript file, output size: " + result.length() + " bytes");
        }
    }

    @Test
    @Order(52)
    void testBuildWithCompilerOptions() throws IOException {
        Path scriptPath = tempDir.resolve("agent.js");
        Files.writeString(scriptPath, "console.log('test');");

        try (Compiler compiler = new Compiler();
             CompilerOptions options = new CompilerOptions()) {
            options.setProjectRoot(tempDir.toString());
            options.setSourceMaps(CompilerOptions.SourceMaps.OMITTED);

            String result = compiler.build(scriptPath.toString(), options);

            assertNotNull(result, "Build result should not be null");
            assertFalse(result.isEmpty(), "Build result should not be empty");
            System.out.println("Built with CompilerOptions, output size: " + result.length() + " bytes");
        }
    }

    @Test
    @Order(53)
    void testBuildWithTerserCompression() throws IOException {
        Path scriptPath = tempDir.resolve("agent.js");
        Files.writeString(scriptPath, """
            function longFunctionName() {
                const veryLongVariableName = "hello";
                console.log(veryLongVariableName);
            }
            longFunctionName();
            """);

        try (Compiler compiler = new Compiler();
             CompilerOptions options = new CompilerOptions()) {
            options.setJsCompression(CompilerOptions.JsCompression.TERSER);

            String result = compiler.build(scriptPath.toString(), options);

            assertNotNull(result, "Build result should not be null");
            System.out.println("Built with TERSER compression, output size: " + result.length() + " bytes");
        }
    }

    @Test
    @Order(54)
    void testBuildWithSourceMapsIncluded() throws IOException {
        Path scriptPath = tempDir.resolve("agent.ts");
        Files.writeString(scriptPath, "console.log('test');");

        try (Compiler compiler = new Compiler();
             CompilerOptions options = new CompilerOptions()) {
            options.setSourceMaps(CompilerOptions.SourceMaps.INCLUDED);

            String result = compiler.build(scriptPath.toString(), options);

            assertNotNull(result, "Build result should not be null");
            System.out.println("Built with source maps included, output size: " + result.length() + " bytes");
        }
    }

    // ===========================================
    // Build Error Tests (60-70)
    // ===========================================

    @Test
    @Order(60)
    void testBuildThrowsForNonExistentFile() {
        try (Compiler compiler = new Compiler()) {
            assertThrows(FridaException.class, () ->
                    compiler.build("/non/existent/path/agent.js")
            );
            System.out.println("Correctly throws FridaException for non-existent file");
        }
    }

    @Test
    @Order(61)
    void testBuildThrowsForInvalidSyntax() throws IOException {
        Path scriptPath = tempDir.resolve("invalid.ts");
        Files.writeString(scriptPath, """
            const x: string = 123; // Type error
            function broken( { // Syntax error
            """);

        try (Compiler compiler = new Compiler()) {
            assertThrows(FridaException.class, () ->
                    compiler.build(scriptPath.toString())
            );
            System.out.println("Correctly throws FridaException for invalid syntax");
        }
    }

    // ===========================================
    // Resource Management Tests (70-80)
    // ===========================================

    @Test
    @Order(70)
    void testCleanUpSignalsOnClose() {
        Compiler compiler = new Compiler();

        compiler.on(CompilerSignal.STARTING, (Runnable) () -> {});
        compiler.on(CompilerSignal.FINISHED, (Runnable) () -> {});
        compiler.on(CompilerSignal.OUTPUT, (SignalCallbacks.CompilerOutputCallback) s -> {});

        compiler.close();
        System.out.println("Signals cleaned up on close successfully");
    }

    @Test
    @Order(71)
    void testMultipleCloseCallsAreIdempotent() {
        Compiler compiler = new Compiler();

        compiler.close();
        compiler.close(); // Should not throw

        System.out.println("Multiple close calls handled gracefully");
    }
}
