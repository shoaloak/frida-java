# Frida Java Examples

This module contains examples demonstrating how to use the Frida Java bindings.

## BasicExample

The `BasicExample` demonstrates:
- Getting version information
- Device enumeration (local, remote, etc.)
- Process enumeration
- Resource management with try-with-resources

## Building and Running

### Build from root directory:
```bash
mvn clean package
```

### Run as executable JAR (Recommended):
```bash
# Native access permissions are pre-configured in the JAR
java -jar frida-java-examples/target/frida-java-example-jar-with-dependencies.jar
```

### Run with Maven exec plugin:
```bash
cd frida-java-examples
mvn exec:java -Dexec.mainClass="nl.axelkoolhaas.examples.BasicExample" \
  -Dexec.args="--enable-native-access=ALL-UNNAMED"
```

**Note:** The executable JAR includes native access permissions in its manifest, so no additional JVM flags are needed.
When running via Maven exec or in your IDE, you'll need to add `--enable-native-access=ALL-UNNAMED`.

