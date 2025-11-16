# Frida Java Examples

This module contains an example demonstrating how to use the Frida Java bindings.

## Version Example

The `BasicExample` demonstrates:
- Initializing and deinitializing Frida
- Getting version information
- Basic error handling

To run the example:
```bash
mvn clean compile exec:java -Dexec.mainClass="nl.axelkoolhaas.examples.BasicExample"
```

## Building and Running

From the root directory:
```bash
# Build everything including examples
mvn clean package
```

### Run with Maven exec plugin:
```bash
cd frida-java-examples
mvn exec:java -Dexec.mainClass="nl.axelkoolhaas.examples.BasicExample"
```

### Run as executable JAR:
```bash
# After building, run the standalone JAR
java -jar frida-java-examples/target/frida-java-example.jar
```

