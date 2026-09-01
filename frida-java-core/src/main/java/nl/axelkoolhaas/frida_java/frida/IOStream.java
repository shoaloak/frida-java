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

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;

/**
 * IOStream wraps GIOStream for reading and writing data to/from channels.
 *
 * <p>This class provides a high-level Java API for interacting with GLib I/O streams returned by
 * {@link Device#openChannel(String)}.
 */
public class IOStream implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(IOStream.class);

  private final MemorySegment streamPtr;
  private final MemorySegment inputStreamPtr;
  private final MemorySegment outputStreamPtr;

  private static final MethodHandle G_IO_STREAM_GET_INPUT_STREAM;
  private static final MethodHandle G_IO_STREAM_GET_OUTPUT_STREAM;
  private static final MethodHandle G_IO_STREAM_IS_CLOSED;
  private static final MethodHandle G_IO_STREAM_CLOSE;
  private static final MethodHandle G_INPUT_STREAM_READ;
  private static final MethodHandle G_INPUT_STREAM_READ_ALL;
  private static final MethodHandle G_OUTPUT_STREAM_WRITE;
  private static final MethodHandle G_OUTPUT_STREAM_WRITE_ALL;

  static {
    G_IO_STREAM_GET_INPUT_STREAM =
        FridaLibraryLoader.findFunction(
            "g_io_stream_get_input_stream",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_IO_STREAM_GET_OUTPUT_STREAM =
        FridaLibraryLoader.findFunction(
            "g_io_stream_get_output_stream",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_IO_STREAM_IS_CLOSED =
        FridaLibraryLoader.findFunction(
            "g_io_stream_is_closed",
            FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
    G_IO_STREAM_CLOSE =
        FridaLibraryLoader.findFunction(
            "g_io_stream_close",
            FunctionDescriptor.of(
                ValueLayout.JAVA_BOOLEAN,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    G_INPUT_STREAM_READ =
        FridaLibraryLoader.findFunction(
            "g_input_stream_read",
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    G_INPUT_STREAM_READ_ALL =
        FridaLibraryLoader.findFunction(
            "g_input_stream_read_all",
            FunctionDescriptor.of(
                ValueLayout.JAVA_BOOLEAN,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    G_OUTPUT_STREAM_WRITE =
        FridaLibraryLoader.findFunction(
            "g_output_stream_write",
            FunctionDescriptor.of(
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    G_OUTPUT_STREAM_WRITE_ALL =
        FridaLibraryLoader.findFunction(
            "g_output_stream_write_all",
            FunctionDescriptor.of(
                ValueLayout.JAVA_BOOLEAN,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
  }

  public IOStream(MemorySegment streamPtr) {
    this.streamPtr = FridaNativeUtils.requireValidPointer(streamPtr, "IOStream pointer");
    log.trace("Creating IOStream from native pointer");

    try {
      this.inputStreamPtr = (MemorySegment) G_IO_STREAM_GET_INPUT_STREAM.invoke(streamPtr);
      this.outputStreamPtr = (MemorySegment) G_IO_STREAM_GET_OUTPUT_STREAM.invoke(streamPtr);

      if (inputStreamPtr.equals(MemorySegment.NULL) || outputStreamPtr.equals(MemorySegment.NULL)) {
        throw new FridaException("Failed to get input/output streams from GIOStream");
      }
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to initialize IOStream", e);
    }
  }

  /**
   * Check if the stream is closed.
   *
   * @return true if the stream is closed, false otherwise
   */
  public boolean isClosed() {
    try {
      return (boolean) G_IO_STREAM_IS_CLOSED.invoke(streamPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to check if IOStream is closed", e);
    }
  }

  /**
   * Close the stream.
   *
   * @throws IOException if an I/O error occurs
   */
  public void close() throws IOException {
    log.trace("Closing IOStream");
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      boolean success = (boolean) G_IO_STREAM_CLOSE.invoke(streamPtr, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      if (!error.equals(MemorySegment.NULL)) {
        GErrorUtils.handleError(error, "close IOStream");
      }

      if (!success) {
        throw new IOException("Failed to close IOStream");
      }
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (IOException e) {
      throw e;
    } catch (Throwable e) {
      throw new IOException("Failed to close IOStream", e);
    }
  }

  /**
   * Read up to data.length bytes from the stream.
   *
   * @param data buffer to read into
   * @return number of bytes read, or 0 if EOF
   * @throws IOException if an I/O error occurs
   */
  public int read(byte[] data) throws IOException {
    if (data == null || data.length == 0) {
      return 0;
    }

    log.trace("Reading up to {} bytes from IOStream", data.length);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buffer = arena.allocate(data.length);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      long bytesRead =
          (long)
              G_INPUT_STREAM_READ.invoke(
                  inputStreamPtr, buffer, (long) data.length, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      if (!error.equals(MemorySegment.NULL)) {
        GErrorUtils.handleError(error, "read from IOStream");
      }

      if (bytesRead < 0) {
        throw new IOException("Failed to read from IOStream");
      }

      if (bytesRead > 0) {
        MemorySegment.copy(buffer, 0, MemorySegment.ofArray(data), 0, bytesRead);
      }

      log.trace("Read {} bytes from IOStream", bytesRead);
      return (int) bytesRead;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (IOException e) {
      throw e;
    } catch (Throwable e) {
      throw new IOException("Failed to read from IOStream", e);
    }
  }

  /**
   * Read exactly count bytes from the stream.
   *
   * @param count number of bytes to read
   * @return byte array with exactly count bytes
   * @throws IOException if an I/O error occurs or EOF is reached before reading count bytes
   */
  public byte[] readAll(int count) throws IOException {
    if (count <= 0) {
      return new byte[0];
    }

    log.trace("Reading exactly {} bytes from IOStream", count);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buffer = arena.allocate(count);
      MemorySegment bytesReadPtr = arena.allocate(ValueLayout.JAVA_LONG);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      boolean success =
          (boolean)
              G_INPUT_STREAM_READ_ALL.invoke(
                  inputStreamPtr, buffer, (long) count, bytesReadPtr, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      if (!error.equals(MemorySegment.NULL)) {
        GErrorUtils.handleError(error, "read all from IOStream");
      }

      if (!success) {
        throw new IOException("Failed to read all bytes from IOStream");
      }

      long bytesRead = bytesReadPtr.get(ValueLayout.JAVA_LONG, 0);
      byte[] result = new byte[(int) bytesRead];
      MemorySegment.copy(buffer, 0, MemorySegment.ofArray(result), 0, bytesRead);

      log.trace("Read all {} bytes from IOStream", bytesRead);
      return result;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (IOException e) {
      throw e;
    } catch (Throwable e) {
      throw new IOException("Failed to read all from IOStream", e);
    }
  }

  /**
   * Write data to the stream.
   *
   * @param data data to write
   * @return number of bytes written
   * @throws IOException if an I/O error occurs
   */
  public int write(byte[] data) throws IOException {
    if (data == null || data.length == 0) {
      return 0;
    }

    log.trace("Writing {} bytes to IOStream", data.length);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buffer = arena.allocate(data.length);
      MemorySegment.copy(MemorySegment.ofArray(data), 0, buffer, 0, data.length);

      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      long bytesWritten =
          (long)
              G_OUTPUT_STREAM_WRITE.invoke(
                  outputStreamPtr, buffer, (long) data.length, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      if (!error.equals(MemorySegment.NULL)) {
        GErrorUtils.handleError(error, "write to IOStream");
      }

      if (bytesWritten < 0) {
        throw new IOException("Failed to write to IOStream");
      }

      log.trace("Wrote {} bytes to IOStream", bytesWritten);
      return (int) bytesWritten;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (IOException e) {
      throw e;
    } catch (Throwable e) {
      throw new IOException("Failed to write to IOStream", e);
    }
  }

  /**
   * Write all data to the stream.
   *
   * @param data data to write
   * @throws IOException if an I/O error occurs
   */
  public void writeAll(byte[] data) throws IOException {
    if (data == null || data.length == 0) {
      return;
    }

    log.trace("Writing all {} bytes to IOStream", data.length);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buffer = arena.allocate(data.length);
      MemorySegment.copy(MemorySegment.ofArray(data), 0, buffer, 0, data.length);

      MemorySegment bytesWrittenPtr = arena.allocate(ValueLayout.JAVA_LONG);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      boolean success =
          (boolean)
              G_OUTPUT_STREAM_WRITE_ALL.invoke(
                  outputStreamPtr,
                  buffer,
                  (long) data.length,
                  bytesWrittenPtr,
                  MemorySegment.NULL,
                  errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      if (!error.equals(MemorySegment.NULL)) {
        GErrorUtils.handleError(error, "write all to IOStream");
      }

      if (!success) {
        throw new IOException("Failed to write all bytes to IOStream");
      }

      long bytesWritten = bytesWrittenPtr.get(ValueLayout.JAVA_LONG, 0);
      log.trace("Wrote all {} bytes to IOStream", bytesWritten);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (IOException e) {
      throw e;
    } catch (Throwable e) {
      throw new IOException("Failed to write all to IOStream", e);
    }
  }

  /** Clean up native resources held by this IOStream. */
  public void clean() {
    log.trace("Cleaning IOStream resources");
    try {
      FridaNativeUtils.fridaUnref(streamPtr);
      FridaNativeUtils.fridaUnref(inputStreamPtr);
      FridaNativeUtils.fridaUnref(outputStreamPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to clean IOStream", e);
    }
  }
}
