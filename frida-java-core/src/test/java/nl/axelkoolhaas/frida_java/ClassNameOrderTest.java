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

import nl.axelkoolhaas.frida_java.feature.*;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestClassOrder;

@TestClassOrder(ClassOrderer.ClassName.class)
public class ClassNameOrderTest {
    @Nested
    class A_VersionTest extends VersionTest {}
    @Nested
    class B_DeviceTest extends DeviceTest {}
    @Nested
    class C_DeviceAdvancedTest extends DeviceAdvancedTest {}
    @Nested
    class D_ProcessTest extends ProcessTest {}
    @Nested
    class E_ApplicationTest extends ApplicationTest {}
    @Nested
    class F_SpawnTest extends SpawnTest {}
    @Nested
    class G_SessionTest extends SessionTest {}
    @Nested
    class H_ScriptTest extends ScriptTest {}
    @Nested
    class I_ChildTest extends ChildTest {}
    @Nested
    class J_ErrorHandlingTest extends ErrorHandlingTest {}
}

