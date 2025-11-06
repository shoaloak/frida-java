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
    class C_ProcessTest extends ProcessTest {}
    @Nested
    class D_ApplicationTest extends ApplicationTest {}
    @Nested
    class E_SessionTest extends SessionTest {}
    @Nested
    class F_ErrorHandlingTest extends ErrorHandlingTest {}
}

