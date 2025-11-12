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

