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

import nl.axelkoolhaas.frida_java.feature.*;

@TestClassOrder(ClassOrderer.ClassName.class)
public class ClassNameOrderTest {
  @Nested
  class A_VersionTest extends VersionTest {}

  @Nested
  class B_DeviceTest extends DeviceTest {}

  @Nested
  class D_ProcessTest extends ProcessTest {}

  @Nested
  class E_ApplicationTest extends ApplicationTest {}

  @Nested
  class F_SpawnTest extends SpawnTest {}

  @Nested
  class G_SessionAndScriptTest extends SessionAndScriptTest {}

  @Nested
  class I_ChildTest extends ChildTest {}

  @Nested
  class J_ClosureTest extends ClosureTest {}

  @Nested
  class K_CompilerTest extends CompilerTest {}

  @Nested
  class L_SessionOptionsTest extends SessionOptionsTest {}

  @Nested
  class M_ScriptOptionsTest extends ScriptOptionsTest {}

  @Nested
  class N_SnapshotOptionsTest extends SnapshotOptionsTest {}

  @Nested
  class O_RemoteDeviceOptionsTest extends RemoteDeviceOptionsTest {}

  @Nested
  class P_FileMonitorTest extends FileMonitorTest {}

  @Nested
  class Q_RelayTest extends RelayTest {}

  @Nested
  class R_PeerOptionsTest extends PeerOptionsTest {}

  @Nested
  class S_SessionNewMethodsTest extends SessionNewMethodsTest {}

  @Nested
  class T_DeviceManagerSignalTest extends DeviceManagerSignalTest {}
}
