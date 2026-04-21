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

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import nl.axelkoolhaas.frida_java.frida.*;

public class CompilerTest {

  private Compiler compiler;
  private DeviceManager deviceManager;

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() {
    // Following your DeviceTest pattern: initialize the manager and then the feature
    this.deviceManager = new DeviceManager();
    this.compiler = new Compiler(deviceManager);
  }

  @AfterEach
  void tearDown() {
    // Properly clean up native resources
    compiler.close();
    deviceManager.close();
  }

  // Basics

  @Test
  @Order(1)
  void testBuildProducesValidBundle() throws IOException {
    Path script = createScript("agent.js", "console.log('hello from frida-java');");

    // Test the simple build(String) method
    String bundle = compiler.build(script.toString());

    assertNotNull(bundle, "Bundle should not be null");
    assertTrue(
        bundle.contains("hello from frida-java"), "Bundle should contain the original source code");
    assertTrue(bundle.contains("console.log"), "Bundle should contain Frida's wrapper logic");
  }

  @Test
  @Order(2)
  void testBuildWithDependencies() throws IOException {
    // Create a dependency file
    createScript("lib.js", "export const magic = 42;");

    // Create entrypoint that imports the dependency
    Path entry = createScript("main.js", "import { magic } from './lib.js'; console.log(magic);");

    // The compiler should resolve relative imports automatically
    String bundle = compiler.build(entry.toString());

    assertNotNull(bundle);
    assertTrue(
        bundle.contains("42"), "Compiler should have resolved and bundled the import from lib.js");
  }

  @Test
  @Order(3)
  void testBuildThrowsExceptionOnSyntaxError() throws IOException {
    Path broken = createScript("broken.js", "const a = ;"); // Invalid JS

    // Verify that GErrorUtils.handleError correctly translates native errors into FridaException
    FridaException ex =
        assertThrows(
            FridaException.class,
            () -> {
              compiler.build(broken.toString());
            });

    assertNotNull(ex.getMessage(), "Exception should contain details about the syntax error");
  }

  // Signals

  @Test
  @Order(10)
  void testWatchAndOutputSignal() throws Exception {
    // 1. Create script and resolve REAL path to avoid macOS symlink issues
    Path script = createScript("watcher.js", "console.log('v1');");
    String scriptPath = script.toRealPath().toString();

    CountDownLatch updateLatch = new CountDownLatch(1);
    AtomicReference<String> lastBundle = new AtomicReference<>("");

    // 2. Setup Callback
    compiler.on(
        CompilerSignal.OUTPUT,
        (SignalCallbacks.CompilerOutputCallback)
            (bundle, opts) -> {
              // Replace newlines to make logs readable
              String preview = bundle.length() > 50 ? bundle.substring(0, 50) + "..." : bundle;
              System.out.println(
                  "TEST: Received bundle ("
                      + bundle.length()
                      + " bytes): "
                      + preview.replace("\n", "\\n"));

              lastBundle.set(bundle);

              // Check for our target string
              if (bundle.contains("v2")) {
                updateLatch.countDown();
              }
            });

    // 3. Start Watching (using REAL path)
    System.out.println("TEST: Watching " + scriptPath);
    compiler.watch(scriptPath);

    // 4. Wait for OS watcher to settle (1s is safe for tests)
    Thread.sleep(1000);

    // 5. Trigger Change (Write to REAL path to be safe)
    System.out.println("TEST: Writing v2 to file...");
    Files.writeString(script.toRealPath(), "console.log('v2');");

    // 6. Wait for signal
    boolean received = updateLatch.await(5, TimeUnit.SECONDS);

    if (!received) {
      System.err.println("TEST FAILURE! Last Bundle Content:\n" + lastBundle.get());
    }

    assertTrue(received, "Timed out waiting for 'v2' in bundle.");
    assertTrue(lastBundle.get().contains("v2"));
  }

  @Test
  @Order(11)
  void testDiagnosticsSignalForTypeScript() throws IOException, InterruptedException {
    // Invalid TypeScript (type mismatch)
    Path tsFile = createScript("types.ts", "let x: number = 'not a number';");

    CountDownLatch diagLatch = new CountDownLatch(1);
    AtomicReference<String> diagnosticText = new AtomicReference<>();

    compiler.on(
        CompilerSignal.DIAGNOSTICS,
        (SignalCallbacks.CompilerDiagnosticsCallback)
            (diagnostics) -> {
              diagnosticText.set(diagnostics);
              diagLatch.countDown();
            });

    // Attempting to build invalid TS should trigger the diagnostics signal
    try {
      compiler.build(tsFile.toString());
    } catch (FridaException ignored) {
      // Failure is expected here
    }

    boolean received = diagLatch.await(5, TimeUnit.SECONDS);
    assertTrue(received, "Diagnostics signal should fire for TypeScript type errors");
    assertNotNull(diagnosticText.get());
  }

  @Test
  @Order(12)
  void testLifecycleSignals() throws IOException, InterruptedException {
    Path script = createScript("simple.js", "console.log(1);");

    CountDownLatch startLatch = new CountDownLatch(1);
    CountDownLatch finishLatch = new CountDownLatch(1);

    compiler.on(CompilerSignal.STARTING, (Runnable) startLatch::countDown);
    compiler.on(CompilerSignal.FINISHED, (Runnable) finishLatch::countDown);

    compiler.build(script.toString());

    assertTrue(startLatch.await(2, TimeUnit.SECONDS), "STARTING signal should fire during build");
    assertTrue(finishLatch.await(2, TimeUnit.SECONDS), "FINISHED signal should fire after build");
  }

  @Test
  @Order(13)
  void testOffRemovesCallback() throws IOException, InterruptedException {
    Path script = createScript("simple.js", "console.log(1);");
    CountDownLatch latch = new CountDownLatch(1);

    compiler.on(CompilerSignal.FINISHED, (Runnable) latch::countDown);
    compiler.off(CompilerSignal.FINISHED); // Remove it immediately

    compiler.build(script.toString());

    assertFalse(
        latch.await(500, TimeUnit.MILLISECONDS), "Signal should not fire after being disconnected");
  }

  /** Helper to create temporary scripts with absolute paths (which Frida prefers) */
  private Path createScript(String name, String content) throws IOException {
    Path path = tempDir.resolve(name).toAbsolutePath();
    Files.writeString(path, content);
    return path;
  }
}
