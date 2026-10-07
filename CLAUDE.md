# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Java bindings for the [Frida](https://github.com/frida/frida) dynamic instrumentation toolkit, using Java's Foreign Function & Memory API (FFM). The goal is a first-class Java SDK that hides all FFM/native complexity, not a thin wrapper. Requires Java 25+.

Anything touching threading, signals, closures, or native object lifetime must follow the Threading Model section below. Those rules are the main defence against JVM crashes. Written content (comments, docs, commits) uses British English spelling and no em dashes.

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
# (recommended: go to https://github.com/shoaloak/frida-java/actions)

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
  Compiler.java         Compile TypeScript to JavaScript

GLib Interop Layer      frida-java-core/src/main/.../util/
  GErrorUtils           GError* to domain exceptions
  GHashTableUtil        GHashTable* to Map<String, Object>
  GBytesUtil            GBytes* to byte[]
  GValueUtil            GValue* to Java objects
  GSignalUtil           Connect GLib signals with Java handlers
  Closure               GClosure marshal upcall: native signals to Java callbacks

Internal               frida-java-core/src/main/.../internal/
  FridaEventLoop        Obsolete. See Threading Model. frida-core runs its own
                        main loop; this should be removed or reduced to a no-op.
```

The FFM calls, `MemorySegment` handling, and raw native pointers must never appear in public API signatures. Only the `util/` and `internal/` packages touch these.

### Threading Model & Native Object Lifetime

The authoritative rules live in `.github/copilot-instructions.md`. Summary:

- **frida-core owns the loop.** frida-core runs its own worker thread and private `GMainContext`, started by `frida_init()`, and pumps it itself. The bindings must not run a host GLib main loop. `FridaEventLoop` is obsolete: `g_main_loop_new(NULL, ...)` binds the global-default context, not the context Frida dispatches signals on, so it does nothing useful and only adds a thread that touches GLib state. Remove it or reduce it to a no-op. The reference bindings (frida-python, frida-go) run no loop of their own.
- **Call through `*_sync`.** The `*_sync` variants marshal the operation onto frida-core's context and block the caller until completion. That is the correct, thread-safe pattern. Do not build a scheduler around `g_idle_add`. If you genuinely must run code on frida-core's context, use `frida_get_main_context()` with `g_main_context_invoke`.
- **The upcall boundary is fragile.** Signal callbacks arrive on frida-core's worker thread, auto-attached to the JVM by the FFM runtime. The shared GClosure marshal stub must be bound to `Arena.global()`, and the marshal method must catch `Throwable` so nothing propagates into native code (an exception crossing the boundary crashes the VM). Route failures to the error handler. Never call blocking `*_sync` APIs from inside a callback: you are on frida-core's own context thread and will deadlock. Offload heavy or re-entrant work to a `java.util.concurrent` executor.
- **Owned vs borrowed pointers.** Objects returned by `*_sync` constructors and getters are owned (a reference is transferred to us); release each exactly once in `close()` / cleanup. Objects passed as signal parameters (the `Crash` in `detached`, the `Device` in `added`/`removed`, and so on) are borrowed and valid only for the duration of the callback. If a wrapper built from a borrowed pointer must outlive the callback, `g_object_ref` it first and mark it owned; otherwise do not ref, do not unref, and do not retain the raw pointer. Never unref a borrowed object, and never unref twice. Resolve the ref-count TODOs in `Closure` on this basis.

### Test Structure

All tests are discovered via a single orchestrator class. Only `ClassNameOrderTest.java` is listed in maven-surefire-plugin `<includes>`. It uses `@TestClassOrder(ClassOrderer.ClassName.class)` with nested test classes prefixed `A_`, `B_`, ... to enforce execution order.

Feature tests live in `src/test/java/.../feature/` and require a live Frida native library. Unit tests that do not need a running Frida instance are preferred for new code. Add integration coverage for signal lifecycle (connect a handler, trigger it, then confirm no crash across GC and `close()`); ownership regressions surface there, not in unit tests.

### Multi-module Structure

| Module | Purpose |
|---|---|
| `frida-java-core` | Main library: all bindings, utilities, and tests |
| `frida-java-examples` | Standalone examples packaged as an executable uber JAR |
| `reference/` | Go and C Frida reference implementations (not built by Maven) |

For init, threading, signal, or closure decisions, consult the upstream reference bindings: frida-python (`frida/_frida/extension.c`) and frida-go (`frida/closure.go`, `frida/frida.go`). When in doubt about ownership or threading, match what they do.

## API Design Rules

These rules come from `.github/copilot-instructions.md` and govern all public API decisions:

- **No FFM leakage** - `MemorySegment`, `ValueLayout`, `Arena` must not appear in public method signatures or exceptions.
- **Domain exceptions** - Translate all native errors to `FridaException` subclasses (`FridaAttachException`, `FridaProcessNotFoundException`, `FridaScriptException`, `FridaTransportException`). Never expose errno or raw native codes.
- **Optional for normal absence** - Methods like `getDeviceById(String)` return `Optional<T>` instead of throwing when the result simply does not exist. Throw exceptions only for true errors (permission denied, transport failure, etc.).
- **Thread-safe init** - `Frida.ensureInitialized()` uses double-checked locking; call it wherever initialisation might be needed. It calls `frida_init()`; it must not start a host main loop.
- **Callback thread safety** - Signal callbacks run on frida-core's worker thread (auto-attached to the JVM), not an application thread. Never block them, and never call blocking `*_sync` APIs from within them. Catch `Throwable` at the marshal upcall boundary. Offload heavy work to a dedicated executor.
- **Native object ownership** - Track owned vs borrowed (see Threading Model). Never unref a borrowed signal parameter; ref before retaining anything past the callback.

## GLib Interop Strategy

Frida's C API returns GLib data structures that must be converted at the boundary, so that plain Java types cross into the public API.

Convert (via `util/` classes):
- `GHashTable*` to `Map<String, Object>`, `GBytes*` to `byte[]`, `GVariant*` to Java objects, `GError*` to domain exceptions.

GObject signals and closures are now bound (`GSignalUtil`, `Closure`), which supersedes the earlier "do not bind signals" rule. Signal and closure work must follow the Threading Model and ownership rules above. Do not hardcode native struct sizes (for example `SIZEOF_GCLOSURE`); derive or validate them against the target ABI.

## Logging Policy

- Use SLF4J (`LoggerFactory.getLogger(...)`), no backend required.
- `debug`/`trace` only, for FFM call boundaries, resource lifecycle, unsafe memory ops.
- Never log normal failures that are already represented by exceptions (`log.error("Attach failed"); throw ...` is forbidden).
- Guard expensive logs: `if (log.isTraceEnabled()) { log.trace(...); }`

## Code Style

- Google Java Style Guide; lines <= 120 characters.
- `final` on variables that are not reassigned.
- No emojis anywhere: code, comments, commits, or documentation.
- British English spelling and no em dashes in written content.
- Run `mvn spotless:apply` before committing.
