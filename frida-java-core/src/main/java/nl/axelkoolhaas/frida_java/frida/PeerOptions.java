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
 * Configuration options for peer-to-peer connections.
 *
 * <p>PeerOptions specify STUN servers and TURN relays used to establish WebRTC peer connections
 * when direct connectivity is not possible.
 */
public class PeerOptions implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(PeerOptions.class);
  private final MemorySegment optionsPtr;
  private volatile boolean closed = false;

  private static final MethodHandle FRIDA_PEER_OPTIONS_NEW;
  private static final MethodHandle FRIDA_PEER_OPTIONS_GET_STUN_SERVER;
  private static final MethodHandle FRIDA_PEER_OPTIONS_SET_STUN_SERVER;
  private static final MethodHandle FRIDA_PEER_OPTIONS_CLEAR_RELAYS;
  private static final MethodHandle FRIDA_PEER_OPTIONS_ADD_RELAY;

  static {
    Frida.ensureInitialized();

    FRIDA_PEER_OPTIONS_NEW =
        FridaLibraryLoader.findFunction(
            "frida_peer_options_new", FunctionDescriptor.of(ValueLayout.ADDRESS));
    FRIDA_PEER_OPTIONS_GET_STUN_SERVER =
        FridaLibraryLoader.findFunction(
            "frida_peer_options_get_stun_server",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PEER_OPTIONS_SET_STUN_SERVER =
        FridaLibraryLoader.findFunction(
            "frida_peer_options_set_stun_server",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PEER_OPTIONS_CLEAR_RELAYS =
        FridaLibraryLoader.findFunction(
            "frida_peer_options_clear_relays", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    FRIDA_PEER_OPTIONS_ADD_RELAY =
        FridaLibraryLoader.findFunction(
            "frida_peer_options_add_relay",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  /** Create new peer connection options with default settings */
  public PeerOptions() {
    log.debug("Creating PeerOptions");
    try {
      this.optionsPtr = (MemorySegment) FRIDA_PEER_OPTIONS_NEW.invoke();
      FridaNativeUtils.requireValidPointer(optionsPtr, "PeerOptions pointer");
      log.debug("PeerOptions created");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to create PeerOptions: {}", e.getMessage());
      throw new FridaException("Failed to create PeerOptions", e);
    }
  }

  /**
   * Internal constructor from native pointer
   *
   * @param optionsPtr Native FridaPeerOptions pointer
   */
  @SuppressWarnings("unused")
  PeerOptions(MemorySegment optionsPtr) {
    this.optionsPtr = FridaNativeUtils.requireValidPointer(optionsPtr, "PeerOptions pointer");
    log.debug("PeerOptions created from native pointer");
  }

  /**
   * Get the STUN server address
   *
   * @return STUN server address (e.g., "stun:stun.example.com:3478")
   */
  public String getStunServer() {
    checkNotClosed();
    try {
      MemorySegment serverPtr =
          (MemorySegment) FRIDA_PEER_OPTIONS_GET_STUN_SERVER.invoke(optionsPtr);
      String server = FridaNativeUtils.memorySegmentToString(serverPtr);
      log.trace("Got STUN server: {}", server);
      return server;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get STUN server: {}", e.getMessage());
      throw new FridaException("Failed to get STUN server", e);
    }
  }

  /**
   * Set the STUN server address
   *
   * @param stunServer STUN server address (e.g., "stun:stun.example.com:3478")
   */
  public void setStunServer(String stunServer) {
    if (stunServer == null) {
      throw new IllegalArgumentException("STUN server cannot be null");
    }
    checkNotClosed();
    log.debug("Setting STUN server: {}", stunServer);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment serverPtr = arena.allocateFrom(stunServer);
      FRIDA_PEER_OPTIONS_SET_STUN_SERVER.invoke(optionsPtr, serverPtr);
      log.debug("STUN server set");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set STUN server: {}", e.getMessage());
      throw new FridaException("Failed to set STUN server", e);
    }
  }

  /** Clear all configured relay servers */
  public void clearRelays() {
    checkNotClosed();
    log.debug("Clearing relays");
    try {
      FRIDA_PEER_OPTIONS_CLEAR_RELAYS.invoke(optionsPtr);
      log.debug("Relays cleared");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to clear relays: {}", e.getMessage());
      throw new FridaException("Failed to clear relays", e);
    }
  }

  /**
   * Add a TURN relay server
   *
   * @param relay Relay configuration to add
   */
  public void addRelay(Relay relay) {
    if (relay == null) {
      throw new IllegalArgumentException("Relay cannot be null");
    }
    checkNotClosed();
    log.debug("Adding relay: {}", relay.getAddress());
    try {
      FRIDA_PEER_OPTIONS_ADD_RELAY.invoke(optionsPtr, relay.getPointer());
      log.debug("Relay added");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to add relay: {}", e.getMessage());
      throw new FridaException("Failed to add relay", e);
    }
  }

  /**
   * Get the native pointer (internal use only)
   *
   * @return Native FridaPeerOptions pointer
   */
  MemorySegment getPointer() {
    checkNotClosed();
    return optionsPtr;
  }

  private void checkNotClosed() {
    if (closed) {
      throw new IllegalStateException("PeerOptions has been closed");
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

    log.debug("Closing PeerOptions");
    try {
      FridaNativeUtils.fridaUnref(optionsPtr);
      log.debug("PeerOptions closed");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to close PeerOptions: {}", e.getMessage());
      throw new FridaException("Failed to close PeerOptions", e);
    }
  }

  @Override
  public String toString() {
    if (closed) {
      return "PeerOptions{closed}";
    }
    try {
      return String.format("PeerOptions{stunServer='%s'}", getStunServer());
    } catch (Throwable e) {
      return "PeerOptions{error=" + e.getMessage() + "}";
    }
  }
}
