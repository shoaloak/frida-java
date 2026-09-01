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

/** Options for session attachment */
public class SessionOptions implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(SessionOptions.class);
  private final MemorySegment optionsPtr;

  private static final MethodHandle FRIDA_SESSION_OPTIONS_NEW;
  private static final MethodHandle FRIDA_SESSION_OPTIONS_SET_REALM;
  private static final MethodHandle FRIDA_SESSION_OPTIONS_SET_PERSIST_TIMEOUT;
  private static final MethodHandle FRIDA_SESSION_OPTIONS_GET_REALM;
  private static final MethodHandle FRIDA_SESSION_OPTIONS_GET_PERSIST_TIMEOUT;

  static {
    Frida.ensureInitialized();

    FRIDA_SESSION_OPTIONS_NEW =
        FridaLibraryLoader.findFunction(
            "frida_session_options_new", FunctionDescriptor.of(ValueLayout.ADDRESS));
    FRIDA_SESSION_OPTIONS_SET_REALM =
        FridaLibraryLoader.findFunction(
            "frida_session_options_set_realm",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_SESSION_OPTIONS_SET_PERSIST_TIMEOUT =
        FridaLibraryLoader.findFunction(
            "frida_session_options_set_persist_timeout",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_SESSION_OPTIONS_GET_REALM =
        FridaLibraryLoader.findFunction(
            "frida_session_options_get_realm",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_SESSION_OPTIONS_GET_PERSIST_TIMEOUT =
        FridaLibraryLoader.findFunction(
            "frida_session_options_get_persist_timeout",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
  }

  /** Create new session options with default settings */
  public SessionOptions() {
    try {
      this.optionsPtr = (MemorySegment) FRIDA_SESSION_OPTIONS_NEW.invoke();
      log.debug("SessionOptions created");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to create SessionOptions: {}", e.getMessage());
      throw new FridaException("Failed to create SessionOptions", e);
    }
  }

  /**
   * Set the realm for the session (native or emulated)
   *
   * @param realm Realm to use
   */
  public void setRealm(Realm realm) {
    try {
      FRIDA_SESSION_OPTIONS_SET_REALM.invoke(optionsPtr, realm.getValue());
      log.trace("Set session realm: {}", realm);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set session realm: {}", e.getMessage());
      throw new FridaException("Failed to set session realm", e);
    }
  }

  /**
   * Set the persist timeout in seconds
   *
   * @param timeoutSeconds Timeout in seconds (0 for no persistence)
   */
  public void setPersistTimeout(int timeoutSeconds) {
    try {
      FRIDA_SESSION_OPTIONS_SET_PERSIST_TIMEOUT.invoke(optionsPtr, timeoutSeconds);
      log.trace("Set persist timeout: {} seconds", timeoutSeconds);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to set persist timeout: {}", e.getMessage());
      throw new FridaException("Failed to set persist timeout", e);
    }
  }

  /**
   * Get the realm setting
   *
   * @return Realm
   */
  public Realm getRealm() {
    try {
      int value = (int) FRIDA_SESSION_OPTIONS_GET_REALM.invoke(optionsPtr);
      Realm realm = Realm.fromValue(value);
      log.trace("Got session realm: {}", realm);
      return realm;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get session realm: {}", e.getMessage());
      throw new FridaException("Failed to get session realm", e);
    }
  }

  /**
   * Get the persist timeout setting
   *
   * @return Timeout in seconds
   */
  public int getPersistTimeout() {
    try {
      int timeout = (int) FRIDA_SESSION_OPTIONS_GET_PERSIST_TIMEOUT.invoke(optionsPtr);
      log.trace("Got persist timeout: {} seconds", timeout);
      return timeout;
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to get persist timeout: {}", e.getMessage());
      throw new FridaException("Failed to get persist timeout", e);
    }
  }

  /**
   * Get the native pointer to the options struct Used internally when passing options to device
   * methods
   */
  MemorySegment getPointer() {
    return optionsPtr;
  }

  @Override
  public void close() {
    try {
      FridaNativeUtils.fridaUnref(optionsPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to cleanup SessionOptions", e);
    }
  }
}
