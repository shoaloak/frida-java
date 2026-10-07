# Copilot Instructions for Frida Java FFM Bindings

These instructions guide Copilot to generate stable, Java idiomatic, production quality Frida bindings using the Foreign Function and Memory API (FFM).  
The public API must feel like a native Java SDK, not a thin FFI wrapper.

As of the signal/closure work, these bindings **do** bind GObject signals and closures. Anything touching threading, signals, closures, or native object lifetime must follow the "Architecture" section below, which is the most load-bearing part of this file and the main defence against JVM crashes.

Written content (comments, docs, commit messages) uses British English spelling and no em dashes.

---

## Project Intent

This project provides Java bindings for Frida using the Foreign Function and Memory API (FFM).

The library must:
- Hide low level FFM and native details from consumers
- Expose stable, domain specific Java abstractions
- Remain ergonomic, predictable, and forward compatible

Public APIs must not leak implementation details.

---

## Architecture: Threading Model, Signals & Native Object Lifetime

This section supersedes any earlier guidance that said to avoid binding GObject signals. Getting these rules wrong is the primary cause of JVM crashes (SIGSEGV from use-after-free, refcount underflow, or exceptions crossing the native boundary).

### Frida owns the main loop. We do not.

- frida-core runs its **own** dedicated worker thread with its **own** private `GMainContext`, started by `frida_init()`. frida-core pumps that context itself.
- Therefore the bindings **must not** run a host GLib main loop. Do not call `g_main_loop_new` / `g_main_loop_run` to "pump signals". The canonical bindings (frida-python, frida-go) run no loop of their own.
- `internal/FridaEventLoop` is obsolete and should be removed or reduced to a no-op. Reasons:
  - `g_main_loop_new(NULL, ...)` binds the **global-default** `GMainContext`, not the private context Frida dispatches signals on, so it does not pump Frida signals at all.
  - It only adds a second thread that touches GLib state, which is a hazard, not a help.
- Do **not** schedule work with `g_idle_add` on the global-default context (the old `executeBlocking` pattern): that runs on the wrong thread relative to frida-core. If you genuinely need to run code on frida-core's context, obtain it via `frida_get_main_context()` and use `g_main_context_invoke`. In almost all cases you do not need this.

### Make Frida calls through the `*_sync` variants

- Call the `*_sync` functions (`frida_device_attach_sync`, `frida_script_load_sync`, ...). They internally marshal the operation onto frida-core's context and block the calling thread until completion. This is the correct, thread-safe call pattern and needs no host loop or bespoke scheduler.
- Do not build a custom blocking scheduler around `g_idle_add`.

### Signal callbacks and the native to Java upcall boundary

- Use one shared `GClosure` marshal upcall stub, bound to `Arena.global()` so it lives for the JVM lifetime. Never back the stub with a confined or auto arena: native code calling a freed stub crashes the VM.
- Connect with `g_signal_connect_closure_by_id` using a single shared marshal stub, rather than per-signal C callbacks.
- Signal callbacks arrive on **frida-core's worker thread**. The FFM runtime auto-attaches that native thread to the JVM for the upcall. Never assume a callback runs on an application-managed thread.
- The marshal method is a native to Java boundary. Catch `Throwable`, not just `Exception`, and never let anything propagate out of the upcall into C. An exception crossing the upcall boundary crashes the JVM. Route failures to the registered error handler instead.
- Keep marshal work short and non-blocking. Do **not** call blocking `*_sync` Frida APIs from inside a signal callback: you are already on frida-core's context thread, and a sync call that waits on that same context will deadlock. Hand off to a `java.util.concurrent` executor if heavier work or re-entrant Frida calls are needed.
- Signals can add trailing parameters across minor versions, so marshal handlers should treat the parameter count as `>=` the expected minimum rather than an exact match.

### Native object lifetime: borrowed vs owned

Every Frida/GObject pointer arrives in one of two ownership modes. Deciding this per pointer is mandatory; ambiguity here is what crashes the VM.

- **Owned**: returned by `*_sync` constructors and getters that transfer a reference to the caller (for example, the session returned by `frida_device_attach_sync` carries a +1 reference that is ours). The wrapper owns it and must release it exactly once via `frida_unref` / `g_object_unref` in `close()` / cleanup.
- **Borrowed**: passed as signal/marshal parameters (for example the `Crash` in `detached`, the `Device` in `added`/`removed`, the `Child` in `child-added`, the `CompilerOptions` in `output`). These are owned by the emitter and valid **only** for the duration of the callback.

Rules:
- If a wrapper built from a borrowed pointer must outlive the callback, take a reference first (`g_object_ref`) and mark the wrapper as owned so it participates in normal cleanup.
- If it does not outlive the callback, do not ref and do not unref, and do not retain the raw pointer past the callback. Treat it as a non-owning view.
- `close()` / cleanup must unref only when the wrapper is owned. Never unref a borrowed object. Never unref twice.
- Resolve every `// TODO: should we increase the ref count` in the marshaller by deciding owned vs borrowed per the above. For any object that escapes the callback into user code, ref it.
- Make ownership explicit in wrapper constructors (for example an `owned` flag), rather than leaving it implicit.

### Reference bindings

Mirror the official bindings for anything involving init, threading, signals, or closures. When in doubt, match what they do:
- frida-python, `frida/_frida/extension.c`: `frida_init` once at module load; `PyGObjectSignalClosure_marshal` acquires the runtime lock (`PyGILState_Ensure`) because callbacks arrive on a foreign thread; blocking calls are wrapped in `Py_BEGIN_ALLOW_THREADS`; no host main loop.
- frida-go, `frida/closure.go` and `frida/frida.go`: GClosure plus `g_signal_connect_closure_by_id`; no host main loop.

---

## GLib Interop

Convert the GLib data structures that Frida's C API returns into Java types:
- `GHashTable*` -> `Map<String, Object>` (system parameters, etc.)
- `GBytes*` -> `byte[]` (binary data)
- `GVariant*` -> Java objects (structured data)
- `GError*` -> domain exceptions

GObject signals and closures are now part of the binding surface (see the Architecture section). This replaces the earlier "do not bind signals" guidance. Prefer converting GLib data structures at the boundary and returning plain Java types from public APIs; never expose `GHashTable`, `GBytes`, or `GVariant` in public signatures.

Also derive or validate native struct sizes rather than hardcoding them. For example, `SIZEOF_GCLOSURE` must match the target ABI; validate it rather than assuming 32 bytes.

---

## Error Handling Principles

### Do not expose raw FFM or native exceptions

Never leak:
- FFM linker exceptions
- `MemorySegment` errors
- Raw errno or native status codes
- Platform specific failure details

All native and FFI errors must be translated into meaningful domain exceptions.

---

### Use domain specific exception types

Errors should map to Frida concepts rather than implementation details.

Prefer throwing:
- `FridaException` (base type)
- `FridaProcessNotFoundException`
- `FridaAttachException`
- `FridaScriptException`
- `FridaTransportException`

Avoid forcing callers to interpret raw integers or native error codes.

---

### Exceptions are the public contract

Exceptions are the primary user-facing error channel.

- All actionable failure information must live in exception messages or fields
- Callers must not need logs to understand failures
- Preserve root causes whenever possible:
  ```
  throw new FridaException("Meaningful message", cause);
  ```

Do not swallow stack traces.

---

### Wrap runtime and native failures

Catch low-level failures inside the binding layer and rethrow stable exceptions.

Let propagate:
- `NullPointerException`
- `IllegalArgumentException`
- `AssertionError`

These indicate programming mistakes and should not be wrapped.

Note the one exception to "let propagate": inside the GClosure marshal upcall, nothing may cross back into native code. There, catch `Throwable` and divert to the error handler (see the Architecture section).

---

## Logging & Debugging Policy (Strict)

### Purpose of logging

Logging exists only to help maintainers debug native and FFM behavior.  
It must never replace exceptions or pollute application logs.

Exceptions = user contract  
Logs = internal diagnostics

---

## Logging backend policy

- Use SLF4J as the logging façade
- Do not require a specific backend (Logback, Log4j2, JUL, etc.)
- Logging must not fail execution if no backend exists
- Logging dependencies should remain optional

Example:
```
private static final Logger log =
LoggerFactory.getLogger(FridaSession.class);
```

---

## Logging rules

### Allowed logging (debug / trace)

Log only internal diagnostics, such as:
- Native and FFM call boundaries
- Resource lifecycle events
- Unsafe memory operations
- Unexpected internal states
- Native failures before throwing exceptions (debug only)

Examples:
```
log.trace("Calling frida_attach(pid={})", pid);
log.debug("Opening FridaSession id={}", sessionId);
log.trace("Allocating MemorySegment size={}", size);
```

---

### Forbidden logging

Do not log:
- Normal failures already represented by exceptions
- User mistakes or invalid API usage
- High volume hot paths unless trace only
- Sensitive or unstable internal memory data unless debugging

Avoid:
```
log.error("Attach failed");
throw new FridaAttachException(...);
```

---

### Logging levels

| Level | Usage |
|------|------|
| trace | Deep FFM internals, memory dumps |
| debug | Diagnostics, lifecycle events |
| info  | Rare meaningful lifecycle milestones |
| warn  | Unexpected but recoverable internal anomalies |
| error | Only fatal internal invariants (avoid in normal flow) |

The library should almost never log at error level.

---

### Performance safety

Guard expensive logs:
```
if (log.isTraceEnabled()) {
log.trace("Native struct dump:\n{}", dumpStruct(nativeStruct));
}
```

Never compute heavy debug data unless logging is enabled.

---

## API Layering Expectations

### Internal binding layer

Handles:
- FFM calls
- Memory segments
- Unsafe pointers
- Native return codes

This layer may be unsafe but must remain internal only.

---

### Public API layer

Exposes:
- Java friendly methods
- High level Frida abstractions
- Domain specific exceptions

Rules:
- No `MemorySegment` or FFM primitives in public API signatures unless explicitly documented
- Public APIs must remain stable even if FFM internals change

---

### Optional advanced access

If needed, expose an explicit advanced namespace such as:
- `RawFridaBindings`
- `UnsafeFrida`

This keeps the primary API clean.

---

## Optional and Absence Handling

For API methods where absence is a normal, expected outcome (such as looking up a process by PID, device by ID, etc.), prefer returning `Optional<T>` rather than throwing an exception. This allows users to check for presence without handling exceptions for normal control flow.

- Use `Optional<T>` for lookups where the result may not exist.
- Only throw exceptions for true error conditions (e.g., communication failure, permission denied, etc.), not for absence.
- Document clearly when a method returns `Optional.empty()` versus when it throws.

Example:
```java
Optional<FridaProcess> process = session.findProcessByPid(pid);
process.ifPresentOrElse(
    p -> { /* use process */ },
    () -> { /* handle not found */ }
);
```

Do NOT require users to catch exceptions just to check for existence.

---

## API Design Expectations

Prefer exceptions over status codes for error conditions. Use `Optional` for normal absence.

Good:
```java
Optional<FridaProcess> process = session.findProcessByPid(pid);
if (process.isEmpty()) {
    // handle not found
}

session.attach(pid); // throws FridaAttachException on error
```

Avoid:
- Returning error integers
- Exposing errno or native return values
- Throwing exceptions for normal absence (use Optional instead)

APIs must feel idiomatic in Java:
- Clear naming
- Predictable failure behavior
- Minimal platform specific branching

---

## Code Style & Formatting

### Java style

- Follow the Google Java Style Guide
- Use `final` where variables are not reassigned
- Prefer simple, explicit control flow in low-level FFM code
- Use streams or lambdas only when they clearly improve readability
- **NO EMOJIS** in code, comments, commit messages, or documentation - use clear, professional text
- Written content uses British English spelling and no em dashes

---

### Formatting

- `spotless` enforces formatting
- Run `mvn spotless:apply` before committing
- Keep lines under 120 characters

---

## Concurrency & Threading

See the Architecture section for the authoritative threading model. In summary:

- frida-core owns its worker thread and main context. The bindings do not run a host main loop.
- Public API components should be thread-safe unless documented otherwise.
- Native Frida handles are often not thread-safe; synchronise access to shared native state.
- Prefer `java.util.concurrent` utilities over manual locking.

### Native callback safety

- Signal callbacks run on frida-core's worker thread, auto-attached to the JVM. Never assume they run on an application thread.
- Never block the callback thread, and never call blocking `*_sync` Frida APIs from within a callback (deadlock risk on frida-core's own context).
- Offload heavy work, or any re-entrant Frida calls, to a dedicated executor.
- Catch `Throwable` at the upcall boundary so nothing propagates into native code.

### Asynchronous operations

Use `CompletableFuture` or callback-based async APIs at the public layer. Do not block long-running native threads.

---

## Dependency Management

- Use Maven for dependency management
- Keep dependencies minimal
- SLF4J is the only permitted logging dependency
- Do not add dependencies that force a specific logging backend

---

## Testing Principles

### Unit & integration tests

- Use JUnit 5
- Unit tests should not require a running Frida instance when possible
- Integration tests should validate real native interactions
- Use `assertThrows` to validate exception behavior
- Add integration coverage for signal lifecycle: connect a handler, emit/trigger it, and confirm no crash across GC and `close()`. Ownership regressions surface here, not in unit tests.

---

### Test naming

- Test classes: `ClassNameTest.java`
- Test method names should describe behavior clearly

---

## Core Goal

The final library must feel like:
- A first-class Java SDK
- A safe, stable abstraction over native Frida
- Not a thin Foreign Function Interface wrapper

Copilot should prioritize **API stability, safety, clarity, and Java ergonomics** over raw native exposure.