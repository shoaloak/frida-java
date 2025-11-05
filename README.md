# Java bindings for Frida

Java bindings for [Frida](https://github.com/frida/frida).

## Prerequisites

* [Java Development Kit (JDK)](https://adoptium.net/)
  - Java 11 or higher is required
* [Apache Maven](https://maven.apache.org/)
* [Clang](https://clang.llvm.org/)
  - GCC can also be used, but on macOS, clang is the default compiler

### Frida Devkit

Run [setup script](scripts/setup.sh) to do this automatically

* Download the corresponding _frida-core-devkit_ from the Frida releases [page](https://github.com/frida/frida/releases/)
* Extract the downloaded archive to `frida-devkit/` directory

## Build

Supported platforms
- [x] MacOS (x86_64, arm64)
- [ ] Linux (x86_64, arm64)
- [ ] Windows (x86_64)

To build the project, run the following command:

```bash
mvn clean install
```

This will compile the Java code, the native C code, and run the tests. The
final JAR file will be in the `target` directory.

## Usage

This library provides Java bindings for Frida. Add it as a dependency to your Maven project:

```xml
<dependency>
    <groupId>nl.axelkoolhaas</groupId>
    <artifactId>frida-java</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```
