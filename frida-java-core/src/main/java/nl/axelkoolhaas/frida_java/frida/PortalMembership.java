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
import nl.axelkoolhaas.frida_java.util.GErrorUtils;

/**
 * Portal membership for collaborative debugging sessions.
 *
 * <p>A PortalMembership is returned when a Session joins a portal and provides the ability to
 * terminate the membership.
 *
 * <p>This is an advanced feature for portal-based collaboration.
 */
public class PortalMembership implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(PortalMembership.class);
  private final MemorySegment membershipPtr;
  private volatile boolean closed = false;

  private static final MethodHandle FRIDA_PORTAL_MEMBERSHIP_TERMINATE_SYNC;

  static {
    Frida.ensureInitialized();

    FRIDA_PORTAL_MEMBERSHIP_TERMINATE_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_portal_membership_terminate_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  /**
   * Internal constructor from native pointer
   *
   * @param membershipPtr Native FridaPortalMembership pointer
   */
  PortalMembership(MemorySegment membershipPtr) {
    this.membershipPtr =
        FridaNativeUtils.requireValidPointer(membershipPtr, "PortalMembership pointer");
    log.debug("PortalMembership created from native pointer");
  }

  /**
   * Terminate the portal membership
   *
   * @throws FridaException if termination fails
   */
  public void terminate() {
    checkNotClosed();
    log.debug("Terminating portal membership");
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      log.trace("Native call: frida_portal_membership_terminate_sync()");
      FRIDA_PORTAL_MEMBERSHIP_TERMINATE_SYNC.invoke(membershipPtr, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "terminate portal membership");
      log.debug("Portal membership terminated");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to terminate portal membership: {}", e.getMessage());
      throw new FridaException("Failed to terminate portal membership", e);
    }
  }

  /**
   * Get the native pointer (internal use only)
   *
   * @return Native FridaPortalMembership pointer
   */
  MemorySegment getPointer() {
    checkNotClosed();
    return membershipPtr;
  }

  private void checkNotClosed() {
    if (closed) {
      throw new IllegalStateException("PortalMembership has been closed");
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

    log.debug("Closing PortalMembership");
    try {
      FridaNativeUtils.fridaUnref(membershipPtr);
      log.debug("PortalMembership closed");
    } catch (Throwable e) {
      log.debug("Failed to close PortalMembership: {}", e.getMessage());
      throw new FridaException("Failed to close PortalMembership", e);
    }
  }

  @Override
  public String toString() {
    if (closed) {
      return "PortalMembership{closed}";
    }
    return "PortalMembership{active}";
  }
}
