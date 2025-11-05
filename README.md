# Frida Java Bindings

Java bindings for [Frida](https://github.com/frida/frida) dynamic instrumentation toolkit.

## Project Structure

This project is organized as a multi-module Maven project:

- **`frida-java-core`** - The main library containing Java bindings for Frida
- **`frida-java-examples`** - Example applications demonstrating usage

## Prerequisites

* [Java Development Kit (JDK)](https://adoptium.net/)
  - Java 11 or higher is required
* [Apache Maven](https://maven.apache.org/)
* [Clang](https://clang.llvm.org/)
  - GCC can also be used, but on macOS, clang is the default compiler

### Frida Devkit

Run [setup script](frida-java-core/scripts/setup.sh) to do this automatically

* Download the corresponding _frida-core-devkit_ from the Frida releases [page](https://github.com/frida/frida/releases/)
* Extract the downloaded archive to `frida-java-core/frida-devkit/` directory

## Build

Supported platforms
- [x] MacOS (x86_64, arm64)
- [ ] Linux (x86_64, arm64)
- [ ] Windows (x86_64)

To build the entire project, run the following command from the root directory:

```bash
mvn clean install
```

This will:
1. Build the core library (`frida-java`)
2. Build the examples module (`frida-java-examples`)
3. Run tests for the core library
4. Install both artifacts to your local Maven repository

## Usage

Add the core library as a dependency to your Maven project:

```xml
<dependency>
    <groupId>nl.axelkoolhaas</groupId>
    <artifactId>frida-java</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

### Running Examples

To see the library in action, check out the examples:

```bash
# Build everything first
mvn clean install

# Run the basic example
cd frida-java-examples
mvn exec:java -Dexec.mainClass="nl.axelkoolhaas.examples.BasicExample"
```

See the [examples README](frida-java-examples/README.md) for more details.

