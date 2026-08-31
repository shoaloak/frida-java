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

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.List;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;

/** Options for connecting a session to a portal. */
public class PortalOptions implements AutoCloseable {
  private final MemorySegment optionsPtr;

  private static final MethodHandle FRIDA_PORTAL_OPTIONS_NEW;
  private static final MethodHandle FRIDA_PORTAL_OPTIONS_GET_CERTIFICATE;
  private static final MethodHandle FRIDA_PORTAL_OPTIONS_GET_TOKEN;
  private static final MethodHandle FRIDA_PORTAL_OPTIONS_GET_ACL;
  private static final MethodHandle FRIDA_PORTAL_OPTIONS_SET_CERTIFICATE;
  private static final MethodHandle FRIDA_PORTAL_OPTIONS_SET_TOKEN;
  private static final MethodHandle FRIDA_PORTAL_OPTIONS_SET_ACL;

  static {
    Frida.ensureInitialized();
    FRIDA_PORTAL_OPTIONS_NEW =
        FridaLibraryLoader.findFunction(
            "frida_portal_options_new", FunctionDescriptor.of(ValueLayout.ADDRESS));
    FRIDA_PORTAL_OPTIONS_GET_CERTIFICATE =
        FridaLibraryLoader.findFunction(
            "frida_portal_options_get_certificate",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PORTAL_OPTIONS_GET_TOKEN =
        FridaLibraryLoader.findFunction(
            "frida_portal_options_get_token",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PORTAL_OPTIONS_GET_ACL =
        FridaLibraryLoader.findFunction(
            "frida_portal_options_get_acl",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PORTAL_OPTIONS_SET_CERTIFICATE =
        FridaLibraryLoader.findFunction(
            "frida_portal_options_set_certificate",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PORTAL_OPTIONS_SET_TOKEN =
        FridaLibraryLoader.findFunction(
            "frida_portal_options_set_token",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PORTAL_OPTIONS_SET_ACL =
        FridaLibraryLoader.findFunction(
            "frida_portal_options_set_acl",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
  }

  public PortalOptions() {
    try {
      this.optionsPtr = (MemorySegment) FRIDA_PORTAL_OPTIONS_NEW.invoke();
      FridaNativeUtils.requireValidPointer(optionsPtr, "PortalOptions pointer");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to create PortalOptions", e);
    }
  }

  public Certificate getCertificate() {
    try {
      MemorySegment certPtr =
          (MemorySegment) FRIDA_PORTAL_OPTIONS_GET_CERTIFICATE.invoke(optionsPtr);
      if (certPtr.equals(MemorySegment.NULL)) {
        return null;
      }
      return new Certificate(certPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to get portal certificate", e);
    }
  }

  public String getToken() {
    try {
      MemorySegment tokenPtr = (MemorySegment) FRIDA_PORTAL_OPTIONS_GET_TOKEN.invoke(optionsPtr);
      return FridaNativeUtils.memorySegmentToString(tokenPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to get portal token", e);
    }
  }

  public List<String> getAcl() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment lengthPtr = arena.allocate(ValueLayout.JAVA_INT);
      lengthPtr.set(ValueLayout.JAVA_INT, 0, 0);
      MemorySegment aclPtr =
          (MemorySegment) FRIDA_PORTAL_OPTIONS_GET_ACL.invoke(optionsPtr, lengthPtr);
      int length = lengthPtr.get(ValueLayout.JAVA_INT, 0);

      if (aclPtr.equals(MemorySegment.NULL) || length <= 0) {
        return List.of();
      }

      return FridaNativeUtils.cStringArrayToJavaList(aclPtr, length);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to get portal ACL", e);
    }
  }

  public void setCertificate(Certificate certificate) {
    if (certificate == null) {
      throw new IllegalArgumentException("Certificate cannot be null");
    }
    try {
      FRIDA_PORTAL_OPTIONS_SET_CERTIFICATE.invoke(optionsPtr, certificate.getPointer());
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to set portal certificate", e);
    }
  }

  public void setToken(String token) {
    if (token == null) {
      throw new IllegalArgumentException("Token cannot be null");
    }
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment tokenPtr = arena.allocateFrom(token);
      FRIDA_PORTAL_OPTIONS_SET_TOKEN.invoke(optionsPtr, tokenPtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to set portal token", e);
    }
  }

  public void setAcl(List<String> acl) {
    if (acl == null) {
      throw new IllegalArgumentException("ACL cannot be null");
    }
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment aclArrayPtr = MemorySegment.NULL;
      if (!acl.isEmpty()) {
        aclArrayPtr = arena.allocate(MemoryLayout.sequenceLayout(acl.size(), ValueLayout.ADDRESS));
        for (int i = 0; i < acl.size(); i++) {
          aclArrayPtr.setAtIndex(ValueLayout.ADDRESS, i, arena.allocateFrom(acl.get(i)));
        }
      }

      FRIDA_PORTAL_OPTIONS_SET_ACL.invoke(optionsPtr, aclArrayPtr, acl.size());
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      throw new FridaException("Failed to set portal ACL", e);
    }
  }

  public void setAcl(String... acl) {
    setAcl(List.of(acl));
  }

  MemorySegment getPointer() {
    return optionsPtr;
  }

  @Override
  public void close() {
    FridaNativeUtils.fridaUnref(optionsPtr);
  }
}
