/*
 * Copyright (C) 2026 Axel Koolhaas
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

package nl.axelkoolhaas.frida_java.frida;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;

/** Options for the Frida compiler to build/watch TypeScript/JavaScript. */
public class CompilerOptions implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(CompilerOptions.class);
  private final MemorySegment optionsPtr;

  private static final MethodHandle FRIDA_COMPILER_OPTIONS_NEW;
  private static final MethodHandle FRIDA_COMPILER_OPTIONS_SET_PROJECT_ROOT;
  private static final MethodHandle FRIDA_COMPILER_OPTIONS_SET_SOURCE_MAPS;
  private static final MethodHandle FRIDA_COMPILER_OPTIONS_SET_COMPRESSION;
  private static final MethodHandle FRIDA_COMPILER_OPTIONS_SET_OUTPUT_FORMAT;
  private static final MethodHandle FRIDA_COMPILER_OPTIONS_SET_BUNDLE_FORMAT;
  private static final MethodHandle FRIDA_COMPILER_OPTIONS_SET_TYPE_CHECK;

  static {
    Frida.ensureInitialized();

    FRIDA_COMPILER_OPTIONS_NEW =
        FridaLibraryLoader.findFunction(
            "frida_compiler_options_new", FunctionDescriptor.of(ValueLayout.ADDRESS));
    FRIDA_COMPILER_OPTIONS_SET_PROJECT_ROOT =
        FridaLibraryLoader.findFunction(
            "frida_compiler_options_set_project_root",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_COMPILER_OPTIONS_SET_SOURCE_MAPS =
        FridaLibraryLoader.findFunction(
            "frida_compiler_options_set_source_maps",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_COMPILER_OPTIONS_SET_COMPRESSION =
        FridaLibraryLoader.findFunction(
            "frida_compiler_options_set_compression",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_COMPILER_OPTIONS_SET_OUTPUT_FORMAT =
        FridaLibraryLoader.findFunction(
            "frida_compiler_options_set_output_format",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_COMPILER_OPTIONS_SET_BUNDLE_FORMAT =
        FridaLibraryLoader.findFunction(
            "frida_compiler_options_set_bundle_format",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_COMPILER_OPTIONS_SET_TYPE_CHECK =
        FridaLibraryLoader.findFunction(
            "frida_compiler_options_set_type_check",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
  }

  /** Create new compiler options with default settings. */
  public CompilerOptions() {
    try {
      this.optionsPtr = (MemorySegment) FRIDA_COMPILER_OPTIONS_NEW.invoke();
      log.debug("CompilerOptions created");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to create CompilerOptions: {}", e.getMessage());
      throw new FridaException("Failed to create CompilerOptions", e);
    }
  }

  /**
   * Internal constructor to wrap an existing native pointer. Used by Signal marshaling.
   *
   * @param ptr The native pointer.
   */
  public CompilerOptions(MemorySegment ptr) {
    this.optionsPtr = FridaNativeUtils.requireValidPointer(ptr, "CompilerOptions pointer");
  }

  /* Enums (Verified against compiler.vala) */

  public enum JsCompression {
    NONE(0),
    TERSER(1);
    private final int value;

    JsCompression(int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }
  }

  public enum SourceMaps {
    OMITTED(0),
    INCLUDED(1);
    private final int value;

    SourceMaps(int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }
  }

  public enum OutputFormat {
    INLINE_SOURCE_MAP(0),
    LINKED_SOURCE_MAP(1);
    private final int value;

    OutputFormat(int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }
  }

  public enum BundleFormat {
    STANDALONE(0),
    EMBEDDED(1);
    private final int value;

    BundleFormat(int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }
  }

  public enum TypeCheckMode {
    NONE(0),
    FULL(1);
    private final int value;

    TypeCheckMode(int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }
  }

  /* Setters */

  /**
   * Set the project root directory. Use this if your entrypoint script is in another directory
   * besides the current one.
   *
   * @param projectRoot Path to the project root directory
   */
  public void setProjectRoot(String projectRoot) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment projectRootPtr = arena.allocateFrom(projectRoot);
      FRIDA_COMPILER_OPTIONS_SET_PROJECT_ROOT.invoke(optionsPtr, projectRootPtr);
      log.trace("Set project root: {}", projectRoot);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set project root: {}", e.getMessage());
      throw new FridaException("Failed to set project root", e);
    }
  }

  /**
   * Set JavaScript compression for generated output.
   *
   * @param compression Compression type to use
   */
  public void setJsCompression(JsCompression compression) {
    try {
      FRIDA_COMPILER_OPTIONS_SET_COMPRESSION.invoke(optionsPtr, compression.getValue());
      log.trace("Set JS compression: {}", compression);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set JS compression: {}", e.getMessage());
      throw new FridaException("Failed to set JS compression", e);
    }
  }

  /**
   * Set whether source maps should be included or omitted.
   *
   * @param sourceMaps Source maps option
   */
  public void setSourceMaps(SourceMaps sourceMaps) {
    try {
      FRIDA_COMPILER_OPTIONS_SET_SOURCE_MAPS.invoke(optionsPtr, sourceMaps.getValue());
      log.trace("Set source maps: {}", sourceMaps);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set source maps: {}", e.getMessage());
      throw new FridaException("Failed to set source maps", e);
    }
  }

  /**
   * Set the output format for compiled scripts.
   *
   * @param outputFormat Output format to use
   */
  public void setOutputFormat(OutputFormat outputFormat) {
    try {
      FRIDA_COMPILER_OPTIONS_SET_OUTPUT_FORMAT.invoke(optionsPtr, outputFormat.getValue());
      log.trace("Set output format: {}", outputFormat);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set output format: {}", e.getMessage());
      throw new FridaException("Failed to set output format", e);
    }
  }

  /**
   * Set the bundle format for compiled output.
   *
   * @param bundleFormat Bundle format to use
   */
  public void setBundleFormat(BundleFormat bundleFormat) {
    try {
      FRIDA_COMPILER_OPTIONS_SET_BUNDLE_FORMAT.invoke(optionsPtr, bundleFormat.getValue());
      log.trace("Set bundle format: {}", bundleFormat);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set bundle format: {}", e.getMessage());
      throw new FridaException("Failed to set bundle format", e);
    }
  }

  /**
   * Set the type checking mode during compilation.
   *
   * @param typeCheckMode Type checking mode to use
   */
  public void setTypeCheckMode(TypeCheckMode typeCheckMode) {
    try {
      FRIDA_COMPILER_OPTIONS_SET_TYPE_CHECK.invoke(optionsPtr, typeCheckMode.getValue());
      log.trace("Set type check mode: {}", typeCheckMode);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set type check mode: {}", e.getMessage());
      throw new FridaException("Failed to set type check mode", e);
    }
  }

  /**
   * Get the native pointer to the options struct. Used internally when passing options to compiler
   * methods.
   */
  MemorySegment getPointer() {
    return optionsPtr;
  }

  /** Clean up native resources. */
  public void clean() {
    log.debug("Cleaning up CompilerOptions");
    FridaNativeUtils.fridaUnref(optionsPtr);
  }

  @Override
  public void close() {
    clean();
  }
}
