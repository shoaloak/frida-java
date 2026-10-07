# Frida Java Bindings

Java bindings for [Frida](https://github.com/frida/frida) dynamic instrumentation toolkit.

## Table of Contents

- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
  - [Frida Devkit](#frida-devkit)
- [Build](#build)
- [Usage](#usage)
  - [Native Access Configuration](#native-access-configuration)
  - [Maven Configuration](#maven-configuration)
  - [Running Examples](#running-examples)
- [Development](#development)
- [Publishing](#publishing)

## Project Structure

This project is organized as a multi-module Maven project:

- **`frida-java-core`** - The main library containing Java bindings for Frida
- **`frida-java-examples`** - Example applications demonstrating usage

## Prerequisites

**All Platforms:**
* [Java 25+](https://adoptium.net/) (for Foreign Function & Memory API)
* [Apache Maven](https://maven.apache.org/)

**Build Tools per Platform:**
* **[Linux](https://www.linux.org/):** [GCC](https://gcc.gnu.org/) (`build-essential`)
  * [curl](https://curl.se/) for downloading Frida Devkit
* **[macOS](https://www.apple.com/os/macos/):** [Xcode Command Line Tools](https://developer.apple.com/xcode/) (`xcode-select --install`)
  * [curl](https://curl.se/) for downloading Frida Devkit
* **[Windows](https://www.microsoft.com/windows/):** [Visual Studio 2019+](https://visualstudio.microsoft.com/) with C++ build tools
  * [PowerShell](https://docs.microsoft.com/en-us/powershell/) for downloading and building Frida Devkit

### Frida Devkit

You can either download prebuilt native libraries from this project's
[GitHub Actions](https://github.com/shoaloak/frida-java/actions), or build them locally with scripts:

* Linux: `frida-java-core/scripts/build-frida-linux.sh`
* macOS: `frida-java-core/scripts/build-frida-macos.sh`
* Windows: `frida-java-core/scripts/build-frida-windows.ps1`

When built locally, scripts download the Frida devkit and output native libraries to
`frida-java-core/frida-devkit/`.

In GitHub Actions, artefact names are split by purpose:

* `maven-release-*` = JAR artefacts intended for Maven release consumption
* `native-raw-*` = raw `.so` / `.dll` / `.dylib` binaries for local development staging

Before running Maven, place the built libraries in `frida-java-core/native/`.
For a full classifier build, this directory must contain:

* `libfrida-core.dylib`
* `libfrida-core-arm64.so`
* `libfrida-core-x86_64.so`
* `libfrida-core-arm64.dll`
* `libfrida-core-x86_64.dll`

Maven now produces:

* `frida-java-<version>.jar` (Java classes only)
* `frida-java-<version>-linux-x86_64.jar`
* `frida-java-<version>-linux-aarch64.jar`
* `frida-java-<version>-windows-x86_64.jar`
* `frida-java-<version>-windows-aarch64.jar`
* `frida-java-<version>-macos-universal.jar`

## Build

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
    <version>2.0</version>
</dependency>
```

Add one platform-specific native classifier dependency at runtime, for example:

```xml
<dependency>
    <groupId>nl.axelkoolhaas</groupId>
    <artifactId>frida-java</artifactId>
    <version>2.0</version>
    <classifier>linux-x86_64</classifier>
    <scope>runtime</scope>
</dependency>
```

### Native Access Configuration

Since this library uses Java's Foreign Function & Memory API,
you need to enable native access when running your application:

```bash
# For command line execution
java --enable-native-access=ALL-UNNAMED -cp your-app.jar:frida-java-2.0.jar YourMainClass

# Or set JVM arguments in your IDE/build tool
--enable-native-access=ALL-UNNAMED
```

### Maven Configuration

For Maven projects, you can add the following JVM config:

**For running tests:**
```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-surefire-plugin</artifactId>
  <configuration>
    <argLine>--enable-native-access=ALL-UNNAMED</argLine>
  </configuration>
</plugin>
```

**For creating executable JARs:**
```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-assembly-plugin</artifactId>
    <configuration>
        <archive>
            <manifestEntries>
                <Add-Opens>java.base/java.lang=ALL-UNNAMED</Add-Opens>
                <Enable-Native-Access>ALL-UNNAMED</Enable-Native-Access>
            </manifestEntries>
        </archive>
    </configuration>
</plugin>
```


### Running Examples

To see the library in action, check out the examples:

```bash
# Build everything first
mvn clean install

# Run the basic example (native access already configured in JAR)
cd frida-java-examples
java -jar target/frida-java-example-jar-with-dependencies.jar
```

See the [examples README](frida-java-examples/README.md) for more details.

### Portal authentication scope

For v2, `EndpointParameters` supports **token-based authentication only**.

Callback-based authentication is intentionally not implemented. This keeps the binding Java-first
and avoids introducing extra native bridge code for GObject interface implementation, following a
KISS approach during active development.

## Development

Instruction for both developers and LLMs are present at `.github/copilot-instructions.md`.
To enable SLF4J logging, see `org.slf4j.simpleLogger.defaultLogLevel` inside the `pom.xml` of
the `frida-java-core` module. Surefire test reports are generated in `frida-java-core/target/surefire-reports/`.


Development tracking lives in issues and pull requests.

## Publishing

Publishing is configured for the `frida-java-core` module (`nl.axelkoolhaas:frida-java`) through
the dedicated GitHub Actions workflow `.github/workflows/release-central.yml`.

### Required GitHub repository secrets

* `CENTRAL_USERNAME` - Sonatype Central user token username
* `CENTRAL_PASSWORD` - Sonatype Central user token password
* `GPG_PRIVATE_KEY` - ASCII-armoured private key
* `GPG_PASSPHRASE` - passphrase for the private key

### Triggering a release

Use either:

* a manual run of the `Release to Maven Central` workflow, or
* pushing a tag matching `v*`.

The release workflow includes a hard pre-publish gate that fails unless both artefacts exist:
`frida-java-<version>-sources.jar` and `frida-java-<version>-javadoc.jar`.
