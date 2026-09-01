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

/**
 * Relay configuration for WebRTC peer-to-peer connections.
 *
 * <p>A Relay represents a TURN server used to establish peer connections when direct connectivity
 * is not possible.
 */
public class Relay implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(Relay.class);
  private final MemorySegment relayPtr;
  private volatile boolean closed = false;

  private static final MethodHandle FRIDA_RELAY_NEW;
  private static final MethodHandle FRIDA_RELAY_GET_ADDRESS;
  private static final MethodHandle FRIDA_RELAY_GET_USERNAME;
  private static final MethodHandle FRIDA_RELAY_GET_PASSWORD;
  private static final MethodHandle FRIDA_RELAY_GET_KIND;

  static {
    Frida.ensureInitialized();

    FRIDA_RELAY_NEW =
        FridaLibraryLoader.findFunction(
            "frida_relay_new",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_INT));
    FRIDA_RELAY_GET_ADDRESS =
        FridaLibraryLoader.findFunction(
            "frida_relay_get_address",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_RELAY_GET_USERNAME =
        FridaLibraryLoader.findFunction(
            "frida_relay_get_username",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_RELAY_GET_PASSWORD =
        FridaLibraryLoader.findFunction(
            "frida_relay_get_password",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_RELAY_GET_KIND =
        FridaLibraryLoader.findFunction(
            "frida_relay_get_kind",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
  }

  /**
   * Create a new Relay configuration
   *
   * @param address Relay server address (e.g., "turn:relay.example.com:3478")
   * @param username Username for authentication (may be null)
   * @param password Password for authentication (may be null)
   * @param kind Type of relay (TURN_UDP, TURN_TCP, or TURN_TLS)
   */
  public Relay(String address, String username, String password, RelayKind kind) {
    if (address == null) {
      throw new IllegalArgumentException("Relay address cannot be null");
    }
    if (kind == null) {
      throw new IllegalArgumentException("RelayKind cannot be null");
    }

    log.debug("Creating Relay: address={}, kind={}", address, kind);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment addressPtr = arena.allocateFrom(address);
      MemorySegment usernamePtr =
          username != null ? arena.allocateFrom(username) : MemorySegment.NULL;
      MemorySegment passwordPtr =
          password != null ? arena.allocateFrom(password) : MemorySegment.NULL;

      this.relayPtr =
          (MemorySegment)
              FRIDA_RELAY_NEW.invoke(addressPtr, usernamePtr, passwordPtr, kind.getValue());
      FridaNativeUtils.requireValidPointer(relayPtr, "Relay pointer");
      log.debug("Relay created");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to create Relay: {}", e.getMessage());
      throw new FridaException("Failed to create Relay", e);
    }
  }

  /**
   * Internal constructor from native pointer
   *
   * @param relayPtr Native FridaRelay pointer
   */
  @SuppressWarnings("unused")
  Relay(MemorySegment relayPtr) {
    this.relayPtr = FridaNativeUtils.requireValidPointer(relayPtr, "Relay pointer");
    log.debug("Relay created from native pointer");
  }

  /**
   * Get the relay server address
   *
   * @return Relay server address
   */
  public String getAddress() {
    checkNotClosed();
    try {
      MemorySegment addressPtr = (MemorySegment) FRIDA_RELAY_GET_ADDRESS.invoke(relayPtr);
      String address = FridaNativeUtils.memorySegmentToString(addressPtr);
      log.trace("Got relay address: {}", address);
      return address;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get relay address: {}", e.getMessage());
      throw new FridaException("Failed to get relay address", e);
    }
  }

  /**
   * Get the authentication username
   *
   * @return Username, or empty string if not set
   */
  public String getUsername() {
    checkNotClosed();
    try {
      MemorySegment usernamePtr = (MemorySegment) FRIDA_RELAY_GET_USERNAME.invoke(relayPtr);
      String username = FridaNativeUtils.memorySegmentToString(usernamePtr);
      log.trace("Got relay username: {}", username);
      return username;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get relay username: {}", e.getMessage());
      throw new FridaException("Failed to get relay username", e);
    }
  }

  /**
   * Get the authentication password
   *
   * @return Password, or empty string if not set
   */
  public String getPassword() {
    checkNotClosed();
    try {
      MemorySegment passwordPtr = (MemorySegment) FRIDA_RELAY_GET_PASSWORD.invoke(relayPtr);
      String password = FridaNativeUtils.memorySegmentToString(passwordPtr);
      log.trace("Got relay password");
      return password;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get relay password: {}", e.getMessage());
      throw new FridaException("Failed to get relay password", e);
    }
  }

  /**
   * Get the relay kind (protocol type)
   *
   * @return RelayKind enumeration value
   */
  public RelayKind getKind() {
    checkNotClosed();
    try {
      int kindValue = (int) FRIDA_RELAY_GET_KIND.invoke(relayPtr);
      RelayKind kind = RelayKind.fromValue(kindValue);
      log.trace("Got relay kind: {}", kind);
      return kind;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get relay kind: {}", e.getMessage());
      throw new FridaException("Failed to get relay kind", e);
    }
  }

  /**
   * Get the native pointer (internal use only)
   *
   * @return Native FridaRelay pointer
   */
  MemorySegment getPointer() {
    checkNotClosed();
    return relayPtr;
  }

  private void checkNotClosed() {
    if (closed) {
      throw new IllegalStateException("Relay has been closed");
    }
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    synchronized (this) {
      if (closed) {
        return;
      }
      closed = true;
    }

    log.debug("Closing Relay");
    try {
      FridaNativeUtils.fridaUnref(relayPtr);
      log.debug("Relay closed");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to close Relay: {}", e.getMessage());
      throw new FridaException("Failed to close Relay", e);
    }
  }

  @Override
  public String toString() {
    if (closed) {
      return "Relay{closed}";
    }
    try {
      return String.format("Relay{address='%s', kind=%s}", getAddress(), getKind());
    } catch (Throwable e) {
      return "Relay{error=" + e.getMessage() + "}";
    }
  }
}
