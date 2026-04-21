# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Java bindings for the [Frida](https://github.com/frida/frida) dynamic instrumentation toolkit, using Java's Foreign Function & Memory API (FFM). The goal is a first-class Java SDK that hides all FFM/native complexity — not a thin wrapper. Requires Java 25+.

## Commands

### Build & Test

```bash
# Build everything (core + examples) and run tests
mvn clean install

# Build and test core library only
cd frida-java-core && mvn clean install

# Run tests only
mvn test

# Apply code formatting (required before committing)
mvn spotless:apply
```

### Native Libraries (prerequisite for build)

Native libraries must exist in `frida-java-core/native/` before building. The maven-enforcer-plugin will fail the build if they are absent.

```bash
# Option 1: Download pre-built artifacts from GitHub Actions
# (recommended — go to https://github.com/shoaloak/frida-java/actions)

# Option 2: Build locally
frida-java-core/scripts/build-frida-linux.sh      # Linux
frida-java-core/scripts/build-frida-macos.sh      # macOS
frida-java-core/scripts/build-frida-windows.ps1   # Windows
```

### Running Examples

```bash
mvn clean install
cd frida-java-examples
java -jar target/frida-java-example-jar-with-dependencies.jar
```

### SLF4J Test Logging

Adjust `org.slf4j.simpleLogger.defaultLogLevel` in `frida-java-core/pom.xml` to change test log verbosity (`debug`, `trace`, etc.).

## Architecture

### Layered Design

```
Public API Layer        frida-java-core/src/main/.../frida/
  Frida.java            Static entry point (getVersion, ensureInitialized)
  DeviceManager.java    Device discovery (enumerateDevices, getLocalDevice, ...)
  Device.java           spawn, attach, enumerateProcesses, injectLibraryFile, ...
  Session.java          Attach to process, createScript, detach
  Script.java           Load/unload instrumentation scripts, post, setMessageHandler
  Compiler.java         Compile TypeScript → JavaScript

GLib Interop Layer      frida-java-core/src/main/.../util/
  GErrorUtils           GError* → domain exceptions
  GHashTableUtil        GHashTable* → Map<String, Object>
  GBytesUtil            GBytes* → byte[]
  GValueUtil            GValue* → Java objects
  GSignalUtil           Connect GLib signals with Java handlers

Internal               frida-java-core/src/main/.../internal/
  FridaEventLoop        Daemon thread running the GLib main loop (started by Frida.ensureInitialized)
```

The FFM calls, `MemorySegment` handling, and raw native pointers must never appear in public API signatures. Only the `util/` and `internal/` packages touch these.

### Test Structure

All tests are discovered via a single orchestrator class. Only `ClassNameOrderTest.java` is listed in maven-surefire-plugin `<includes>`. It uses `@TestClassOrder(ClassOrderer.ClassName.class)` with nested test classes prefixed `A_`, `B_`, ... to enforce execution order.

Feature tests live in `src/test/java/.../feature/` and require a live Frida native library. Unit tests that do not need a running Frida instance are preferred for new code.

### Multi-module Structure

| Module | Purpose |
|---|---|
| `frida-java-core` | Main library — all bindings, utilities, and tests |
| `frida-java-examples` | Standalone examples packaged as an executable uber JAR |
| `reference/` | Go and C Frida reference implementations (not built by Maven) |

## API Design Rules

These rules come from `.github/copilot-instructions.md` and govern all public API decisions:

- **No FFM leakage** — `MemorySegment`, `ValueLayout`, `Arena` must not appear in public method signatures or exceptions.
- **Domain exceptions** — Translate all native errors to `FridaException` subclasses (`FridaAttachException`, `FridaProcessNotFoundException`, `FridaScriptException`, `FridaTransportException`). Never expose errno or raw native codes.
- **Optional for normal absence** — Methods like `getDeviceById(String)` return `Optional<T>` instead of throwing when the result simply doesn't exist. Throw exceptions only for true errors (permission denied, transport failure, etc.).
- **Thread-safe init** — `Frida.ensureInitialized()` uses double-checked locking; call it wherever initialization might be needed.
- **No blocking on native callback threads** — Native Frida callbacks may not run on Java-managed threads; offload heavy work to dedicated executors.

## GLib Interop Strategy

Frida's C API returns GLib data structures that must be converted. The rule: **convert GLib data types, do not bind GLib's signal/object system**.

Allowed:
- `GHashTable*`, `GBytes*`, `GVariant*`, `GError*` conversions (via `util/` classes)

Forbidden:
- `g_signal_connect_data`, `g_signal_lookup`, GObject introspection, manual signal management

## Logging Policy

- Use SLF4J (`LoggerFactory.getLogger(...)`) — no backend required.
- `debug`/`trace` only — for FFM call boundaries, resource lifecycle, unsafe memory ops.
- Never log normal failures that are already represented by exceptions (`log.error("Attach failed"); throw ...` is forbidden).
- Guard expensive logs: `if (log.isTraceEnabled()) { log.trace(...); }`

## Code Style

- Google Java Style Guide; lines ≤ 120 characters.
- `final` on variables that are not reassigned.
- No emojis anywhere — code, comments, commits, or documentation.
- Run `mvn spotless:apply` before committing.
