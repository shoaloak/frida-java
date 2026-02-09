# Copilot Instructions for Frida Java FFM Bindings

These instructions guide Copilot to generate stable, Java idiomatic, production quality Frida bindings using the Foreign Function and Memory API (FFM).  
The public API must feel like a native Java SDK, not a thin FFI wrapper.

---

## Project Intent

This project provides Java bindings for Frida using the Foreign Function and Memory API (FFM).

The library must:
- Hide low level FFM and native details from consumers
- Expose stable, domain specific Java abstractions
- Remain ergonomic, predictable, and forward compatible

Public APIs must not leak implementation details.

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

## Strategic GLib Usage

### Core Principle

Avoid GLib complexity while handling unavoidable GLib data structures that Frida returns.

**Handle GLib data structures that Frida API returns:**
- `GHashTable*` → `Map<String, Object>` (system parameters, etc.)
- `GBytes*` → `byte[]` (binary data)
- `GVariant*` → Java objects (structured data)
- `GError*` → domain exceptions

**Do NOT bind GLib's signal/object system:**
- No `g_signal_connect_data`, `g_signal_lookup`, `G_OBJECT_GET_TYPE`
- No `g_signal_handler_disconnect`, `G_TYPE_FROM_INSTANCE`
- No manual GObject introspection or signal management

---

### Why This Approach

**GLib data structures are unavoidable** because Frida's C API returns them:
```c
// Frida API returns GHashTable - we must convert it
GHashTable* frida_device_query_system_parameters_sync(...);
```

**GLib signals are avoidable** and add unnecessary complexity:
- Go's Frida bindings succeed by avoiding signal complexity
- Simple function callbacks are more reliable than GObject signals
- Signal binding increases surface area for native function failures

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

---

### Formatting

- `spotless` enforces formatting
- Run `mvn spotless:apply` before committing
- Keep lines under 120 characters

---

## Concurrency & Threading

### Thread safety

- Public API components should be thread-safe unless documented otherwise
- Native Frida handles are often not thread-safe
- Synchronize access to shared native state
- Prefer `java.util.concurrent` utilities over manual locking

---

### Native callback safety

- Never assume native callbacks run on Java-managed threads
- Avoid blocking Frida callback threads
- Offload heavy work to dedicated executors

---

### Asynchronous operations

Use:
- `CompletableFuture`
- Callback-based async APIs

Avoid blocking long-running native threads.

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
