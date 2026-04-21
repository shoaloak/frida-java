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

package nl.axelkoolhaas.frida_java.frida;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GBytesUtil;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;

/** Represents a Frida session with a target process */
public class Session implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(Session.class);

  private final MemorySegment sessionPtr;

  private static final MethodHandle FRIDA_SESSION_IS_DETACHED;
  private static final MethodHandle FRIDA_SESSION_DETACH_SYNC;
  private static final MethodHandle FRIDA_SESSION_RESUME_SYNC;
  private static final MethodHandle FRIDA_SESSION_GET_PID;
  private static final MethodHandle FRIDA_SESSION_ENABLE_CHILD_GATING_SYNC;
  private static final MethodHandle FRIDA_SESSION_DISABLE_CHILD_GATING_SYNC;
  private static final MethodHandle FRIDA_SESSION_CREATE_SCRIPT_SYNC;
  private static final MethodHandle FRIDA_SESSION_COMPILE_SCRIPT_SYNC;
  private static final MethodHandle FRIDA_SESSION_SNAPSHOT_SCRIPT_SYNC;
  private static final MethodHandle FRIDA_SESSION_CREATE_SCRIPT_FROM_BYTES_SYNC;
  private static final MethodHandle FRIDA_SESSION_SETUP_PEER_CONNECTION_SYNC;
  private static final MethodHandle FRIDA_SESSION_JOIN_PORTAL_SYNC;

  static {
    Frida.ensureInitialized();

    FRIDA_SESSION_IS_DETACHED =
        FridaLibraryLoader.findFunction(
            "frida_session_is_detached",
            FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));
    FRIDA_SESSION_DETACH_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_detach_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_SESSION_RESUME_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_resume_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_SESSION_GET_PID =
        FridaLibraryLoader.findFunction(
            "frida_session_get_pid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_SESSION_ENABLE_CHILD_GATING_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_enable_child_gating_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_SESSION_DISABLE_CHILD_GATING_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_disable_child_gating_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_SESSION_CREATE_SCRIPT_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_create_script_sync",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    FRIDA_SESSION_COMPILE_SCRIPT_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_compile_script_sync",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    FRIDA_SESSION_SNAPSHOT_SCRIPT_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_snapshot_script_sync",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    FRIDA_SESSION_CREATE_SCRIPT_FROM_BYTES_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_create_script_from_bytes_sync",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    FRIDA_SESSION_SETUP_PEER_CONNECTION_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_setup_peer_connection_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    FRIDA_SESSION_JOIN_PORTAL_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_session_join_portal_sync",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
  }

  public Session(MemorySegment sessionPtr) {
    this.sessionPtr = FridaNativeUtils.requireValidPointer(sessionPtr, "Session pointer");
    log.debug("Session created");
  }

  /**
   * Check if the session is detached
   *
   * @return true if the session is detached, false otherwise
   */
  public boolean isDetached() {
    try {
      return (boolean) FRIDA_SESSION_IS_DETACHED.invokeExact(sessionPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to check if session is detached", e);
    }
  }

  /**
   * Get the PID of the process this session is attached to
   *
   * @return process ID
   */
  public int getPid() {
    try {
      return (int) FRIDA_SESSION_GET_PID.invokeExact(sessionPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to get session PID", e);
    }
  }

  /** Detach the session from the target process */
  public void detach() {
    log.debug("Detaching session from pid={}", getPid());
    try (Arena arena = Arena.ofConfined()) {
      // Error handling
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      log.trace("Native call: frida_session_detach_sync()");
      // Detach the session (session, cancellable=NULL, error)
      FRIDA_SESSION_DETACH_SYNC.invokeExact(sessionPtr, MemorySegment.NULL, errorPtr);

      // Check for errors
      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "detach session");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to detach session", e);
    }
  }

  /** Resume the session */
  public void resume() {
    try (Arena arena = Arena.ofConfined()) {
      // Error handling
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      // Resume the session (session, cancellable=NULL, error)
      FRIDA_SESSION_RESUME_SYNC.invokeExact(sessionPtr, MemorySegment.NULL, errorPtr);

      // Check for errors
      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "resume session");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to resume session", e);
    }
  }

  /** Enable child gating for this session */
  public void enableChildGating() {
    try (Arena arena = Arena.ofConfined()) {
      // Error handling
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      // Enable child gating (session, cancellable=NULL, error)
      FRIDA_SESSION_ENABLE_CHILD_GATING_SYNC.invokeExact(sessionPtr, MemorySegment.NULL, errorPtr);

      // Check for errors
      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "enable child gating");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to enable child gating", e);
    }
  }

  /** Disable child gating for this session */
  public void disableChildGating() {
    try (Arena arena = Arena.ofConfined()) {
      // Error handling
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      // Disable child gating (session, cancellable=NULL, error)
      FRIDA_SESSION_DISABLE_CHILD_GATING_SYNC.invokeExact(sessionPtr, MemorySegment.NULL, errorPtr);

      // Check for errors
      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "disable child gating");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to disable child gating", e);
    }
  }

  /**
   * Create a script in this session
   *
   * @param script JavaScript source code
   * @return Script object
   */
  public Script createScript(String script) {
    log.debug("Creating script ({} bytes)", script.length());
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment scriptPtr = arena.allocateFrom(script);

      // Error handling
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      log.trace("Native call: frida_session_create_script_sync()");
      // Create script (session, script, options=NULL, cancellable=NULL, error)
      MemorySegment scriptObjPtr =
          (MemorySegment)
              FRIDA_SESSION_CREATE_SCRIPT_SYNC.invokeExact(
                  sessionPtr, scriptPtr, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

      // Check for errors
      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "create script");

      log.debug("Script created successfully");
      return new Script(scriptObjPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to create script: {}", e.getMessage());
      throw new FridaException("Failed to create script", e);
    }
  }

  /**
   * Compile a script to bytecode Note: ScriptOptions parameter support will be added in a future
   * update
   *
   * @param source JavaScript or TypeScript source code
   * @return Compiled bytecode as byte array
   * @throws FridaException if compilation fails
   */
  public byte[] compileScript(String source) {
    log.debug("Compiling script ({} bytes)", source.length());
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment sourcePtr = arena.allocateFrom(source);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      log.trace("Native call: frida_session_compile_script_sync()");
      // Compile script (session, source, options=NULL, cancellable=NULL, error)
      MemorySegment gBytesPtr =
          (MemorySegment)
              FRIDA_SESSION_COMPILE_SCRIPT_SYNC.invokeExact(
                  sessionPtr, sourcePtr, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "compile script");

      byte[] bytecode = GBytesUtil.toByteArray(gBytesPtr);
      log.debug("Script compiled successfully ({} bytes)", bytecode.length);
      return bytecode;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to compile script: {}", e.getMessage());
      throw new FridaException("Failed to compile script", e);
    }
  }

  /**
   * Create a snapshot from a script Note: SnapshotOptions parameter support will be added in a
   * future update
   *
   * @param embedScript Script to embed in the snapshot
   * @return Snapshot data as byte array
   * @throws FridaException if snapshot creation fails
   */
  public byte[] snapshotScript(String embedScript) {
    log.debug("Creating snapshot from script ({} bytes)", embedScript.length());
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment embedScriptPtr = arena.allocateFrom(embedScript);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      log.trace("Native call: frida_session_snapshot_script_sync()");
      // Snapshot script (session, embedScript, warmupScript=NULL, options=NULL, cancellable=NULL,
      // error)
      MemorySegment gBytesPtr =
          (MemorySegment)
              FRIDA_SESSION_SNAPSHOT_SCRIPT_SYNC.invokeExact(
                  sessionPtr,
                  embedScriptPtr,
                  MemorySegment.NULL,
                  MemorySegment.NULL,
                  MemorySegment.NULL,
                  errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "snapshot script");

      byte[] snapshot = GBytesUtil.toByteArray(gBytesPtr);
      log.debug("Snapshot created successfully ({} bytes)", snapshot.length);
      return snapshot;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to snapshot script: {}", e.getMessage());
      throw new FridaException("Failed to snapshot script", e);
    }
  }

  /**
   * Create a script from compiled bytecode Note: ScriptOptions parameter support will be added in a
   * future update
   *
   * @param bytes Compiled script bytecode
   * @return Script object
   * @throws FridaException if script creation fails
   */
  public Script createScriptFromBytes(byte[] bytes) {
    log.debug("Creating script from bytes ({} bytes)", bytes.length);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment gBytesData = GBytesUtil.fromByteArray(bytes, arena);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      log.trace("Native call: frida_session_create_script_from_bytes_sync()");
      // Create script from bytes (session, bytes, options=NULL, cancellable=NULL, error)
      MemorySegment scriptObjPtr =
          (MemorySegment)
              FRIDA_SESSION_CREATE_SCRIPT_FROM_BYTES_SYNC.invokeExact(
                  sessionPtr, gBytesData, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "create script from bytes");

      log.debug("Script created from bytes successfully");
      return new Script(scriptObjPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to create script from bytes: {}", e.getMessage());
      throw new FridaException("Failed to create script from bytes", e);
    }
  }

  /**
   * Setup a peer connection for the session Note: PeerOptions parameter support will be added in a
   * future update Note: This is an advanced feature for peer-to-peer Frida connections
   *
   * @param stun STUN server address (e.g., "stun:stun.l.google.com:19302")
   * @throws FridaException if setup fails
   */
  public void setupPeerConnection(String stun) {
    log.debug("Setting up peer connection with STUN server: {}", stun);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment stunPtr = arena.allocateFrom(stun);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      log.trace("Native call: frida_session_setup_peer_connection_sync()");
      // Setup peer connection (session, stun_server, relays=NULL, options=NULL, cancellable=NULL,
      // error)
      FRIDA_SESSION_SETUP_PEER_CONNECTION_SYNC.invokeExact(
          sessionPtr,
          stunPtr,
          MemorySegment.NULL,
          MemorySegment.NULL,
          MemorySegment.NULL,
          errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "setup peer connection");

      log.debug("Peer connection setup successfully");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to setup peer connection: {}", e.getMessage());
      throw new FridaException("Failed to setup peer connection", e);
    }
  }

  /**
   * Join a portal for collaborative debugging
   *
   * <p>Note: PortalOptions parameter support will be added in a future update
   *
   * <p>Note: This is an advanced feature for portal-based collaboration
   *
   * @param address Portal address
   * @return PortalMembership object representing the active membership
   * @throws FridaException if joining portal fails
   */
  public PortalMembership joinPortal(String address) {
    log.debug("Joining portal at address: {}", address);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment addressPtr = arena.allocateFrom(address);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      log.trace("Native call: frida_session_join_portal_sync()");
      // Join portal (session, address, options=NULL, cancellable=NULL, error)
      MemorySegment membershipPtr =
          (MemorySegment)
              FRIDA_SESSION_JOIN_PORTAL_SYNC.invokeExact(
                  sessionPtr, addressPtr, MemorySegment.NULL, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "join portal");

      log.debug("Successfully joined portal");
      return new PortalMembership(membershipPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to join portal: {}", e.getMessage());
      throw new FridaException("Failed to join portal", e);
    }
  }

  /**
   * Register callbacks for session events
   *
   * <p>Available signals: - "detached": Emitted when the session is detached from the target
   * process Callback should be SignalCallbacks.SessionDetachedCallback accepting (int reason, Crash
   * crash)
   *
   * @param signalName Signal name to connect to
   * @param callback Callback function
   * @throws IllegalArgumentException if signal name is unknown or callback type is invalid
   */
  public void on(String signalName, Object callback) {
    if (callback == null) {
      throw new IllegalArgumentException("Callback cannot be null");
    }

    log.debug("Registering callback for session signal: {}", signalName);

    if ("detached".equals(signalName)) {
      if (!(callback instanceof SignalCallbacks.SessionDetachedCallback)) {
        throw new IllegalArgumentException(
            "Detached signal callback must be SessionDetachedCallback");
      }

      try {
        long handlerId = Closure.connectClosure(sessionPtr, signalName, callback);

        if (handlerId > 0) {
          log.trace("Connected session signal '{}' with handler ID {}", signalName, handlerId);
        } else {
          log.warn("Failed to connect session signal '{}' - no handler ID returned", signalName);
        }
      } catch (Exception e) {
        log.debug("Failed to connect session signal '{}': {}", signalName, e.getMessage());
        throw new FridaException("Failed to connect session signal '" + signalName + "'", e);
      }
    } else {
      throw new IllegalArgumentException("Unknown signal: " + signalName);
    }

    log.trace("Registered callback for session signal '{}'", signalName);
  }

  /** Automatically detach when used in try-with-resources */
  @Override
  public void close() {
    if (!isDetached()) {
      detach();
    }
  }
}
