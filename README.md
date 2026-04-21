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

The native Frida libraries must be placed in the `frida-java-core/native/` directory before building. You have two options:

**Option 1: Download from frida-java GitHub Actions (Recommended)**
* Go to this project's [GitHub Actions](https://github.com/shoaloak/frida-java/actions)
* Download the pre-built artifacts for your platform
* Extract the native libraries to `frida-java-core/native/`

**Option 2: Build Yourself**
* Run the appropriate build script for your platform:
  * Linux: `frida-java-core/scripts/build-frida-linux.sh`
  * macOS: `frida-java-core/scripts/build-frida-macos.sh`
  * Windows: `frida-java-core/scripts/build-frida-windows.ps1`
* The script will automatically download the Frida devkit and build the native library

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

### Native Access Configuration

Since this library uses Java's Foreign Function & Memory API,
you need to enable native access when running your application:

```bash
# For command line execution
java --enable-native-access=ALL-UNNAMED -cp your-app.jar:frida-java-2.0.jar YourMainClass

# Or set JVM arguments in your IDE/build tool
-Denable-native-access=ALL-UNNAMED
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

## Development

Instruction for both developers and LLMs are present at `.github/copilot-instructions.md`.
To enable SLF4J logging, see `org.slf4j.simpleLogger.defaultLogLevel` inside the `pom.xml` of
the `frida-java-core` module.


### TODO

Bugs:
- [ ] "[INFO] pom.xml not found in frida-java-2.0.jar"

These bindings are heavily inspired by the go bindings, we are currently lacking these.

- [ ] Cleanups.java ?
- [ ] EndpointParameters.java ?
- [ ] Errors.java ?
- [ ] FileMonitor.java ?
- [ ] iostream ?             <---- 
- [ ] Misc.java ?
- [ ] Package.java
- [ ] PeerOptions.java ?
- [ ] PortalMembership.java ?
- [ ] PortalOptions.java ?
- [ ] PortalService ?
- [ ] Relay.java ?
- [ ] RemoteDeviceOptions.java ?
- [ ] ScriptOptions.java ?
- [ ] Service.java ?
- [ ] SessionOptions.java ?
- [ ] Unmarshaller.java ?

- create tests for difference callbacks (crash)
  - Device deattachment?
- check if Device is complete

