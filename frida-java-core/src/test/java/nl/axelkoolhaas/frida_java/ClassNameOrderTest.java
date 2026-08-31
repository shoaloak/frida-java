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

package nl.axelkoolhaas.frida_java;

import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestClassOrder;

import nl.axelkoolhaas.frida_java.feature.ApplicationTest;
import nl.axelkoolhaas.frida_java.feature.BusTest;
import nl.axelkoolhaas.frida_java.feature.ChildTest;
import nl.axelkoolhaas.frida_java.feature.ClosureTest;
import nl.axelkoolhaas.frida_java.feature.CompilerTest;
import nl.axelkoolhaas.frida_java.feature.DeviceManagerSignalTest;
import nl.axelkoolhaas.frida_java.feature.DeviceTest;
import nl.axelkoolhaas.frida_java.feature.FileMonitorTest;
import nl.axelkoolhaas.frida_java.feature.PeerOptionsTest;
import nl.axelkoolhaas.frida_java.feature.PortalTest;
import nl.axelkoolhaas.frida_java.feature.ProcessTest;
import nl.axelkoolhaas.frida_java.feature.RelayTest;
import nl.axelkoolhaas.frida_java.feature.RemoteDeviceOptionsTest;
import nl.axelkoolhaas.frida_java.feature.ScriptOptionsTest;
import nl.axelkoolhaas.frida_java.feature.ScriptRpcTest;
import nl.axelkoolhaas.frida_java.feature.ScriptSignalTest;
import nl.axelkoolhaas.frida_java.feature.SessionAndScriptTest;
import nl.axelkoolhaas.frida_java.feature.SessionNewMethodsTest;
import nl.axelkoolhaas.frida_java.feature.SessionOptionsTest;
import nl.axelkoolhaas.frida_java.feature.SnapshotOptionsTest;
import nl.axelkoolhaas.frida_java.feature.SpawnTest;
import nl.axelkoolhaas.frida_java.feature.VersionTest;
import nl.axelkoolhaas.frida_java.unit.GTypeTest;
import nl.axelkoolhaas.frida_java.unit.OwnershipTest;

/**
 * Test orchestrator using ClassOrderer.ClassName.class for deterministic execution order.
 *
 * <p>Nested classes are prefixed A_, B_, C_... to enforce alphabetical ordering. Unit tests that do
 * not require a live Frida instance run first (A_-B_), followed by feature tests that exercise
 * native Frida functionality.
 */
@TestClassOrder(ClassOrderer.ClassName.class)
public class ClassNameOrderTest {

  // ========== Unit tests (no live Frida required) ==========

  @Nested
  class A_OwnershipTest extends OwnershipTest {}

  @Nested
  class B_VersionTest extends VersionTest {}

  @Nested
  class C_ClosureTest extends ClosureTest {}

  // ========== Feature tests (require live Frida) ==========

  @Nested
  class D_DeviceTest extends DeviceTest {}

  @Nested
  class E_ProcessTest extends ProcessTest {}

  @Nested
  class F_ApplicationTest extends ApplicationTest {}

  @Nested
  class G_SpawnTest extends SpawnTest {}

  @Nested
  class H_SessionAndScriptTest extends SessionAndScriptTest {}

  @Nested
  class I_ChildTest extends ChildTest {}

  @Nested
  class J_CompilerTest extends CompilerTest {}

  @Nested
  class K_SessionOptionsTest extends SessionOptionsTest {}

  @Nested
  class L_ScriptOptionsTest extends ScriptOptionsTest {}

  @Nested
  class M_SnapshotOptionsTest extends SnapshotOptionsTest {}

  @Nested
  class N_RemoteDeviceOptionsTest extends RemoteDeviceOptionsTest {}

  @Nested
  class O_FileMonitorTest extends FileMonitorTest {}

  @Nested
  class P_RelayTest extends RelayTest {}

  @Nested
  class Q_PeerOptionsTest extends PeerOptionsTest {}

  @Nested
  class R_SessionNewMethodsTest extends SessionNewMethodsTest {}

  @Nested
  class S_DeviceManagerSignalTest extends DeviceManagerSignalTest {}

  @Nested
  class T_ScriptRpcTest extends ScriptRpcTest {}

  @Nested
  class U_ScriptSignalTest extends ScriptSignalTest {}

  @Nested
  class V_BusTest extends BusTest {}

  @Nested
  class W_PortalTest extends PortalTest {}

  @Nested
  class X_GTypeTest extends GTypeTest {}
}
