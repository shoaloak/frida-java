# macOS Cross-Compilation Docker Setup

This directory contains the Docker setup for cross-compiling the Frida Java bindings for macOS from a Linux environment.

## Files

- `Dockerfile.macos` - Docker image definition for macOS cross-compilation
- `scripts/build-macos-cross.sh` - Build script that runs inside the Docker container

## Usage

### Option 1: Using the helper script

```bash
# From the project root
./scripts/build-macos-docker.sh
```

### Option 2: Manual Docker commands

```bash
# Build the Docker image
docker build -t frida-java-macos-cross -f docker/Dockerfile.macos .

# Run the build
docker run --rm -v "$(pwd)/build-output:/workspace/build-output" frida-java-macos-cross
```

## Cross-Compiler Details

The build uses the `x86_64-apple-darwin24-clang` and `aarch64-apple-darwin24-clang` cross-compilers to build:

- `libfrida-java-x86_64.dylib` - x86_64 macOS binary
- `libfrida-java-arm64.dylib` - ARM64 macOS binary  
- `libfrida-java.dylib` - Universal binary (both architectures)

The compiler invocation format is:
```bash
x86_64-apple-darwin24-clang --target=x86_64-apple-darwin24 source.c -o output
```

## Output

Build artifacts are placed in `./build-output/target/`:
- `objs/` - Contains compiled object files (.o) organized by architecture
  - `x86_64/` - x86_64 object files
  - `arm64/` - ARM64 object files  
- `*.dylib` - Dynamic library files
  - `libfrida-java-x86_64.dylib` - x86_64 macOS binary
  - `libfrida-java-arm64.dylib` - ARM64 macOS binary
  - `libfrida-java.dylib` - Universal binary (both architectures)

## Maven Integration

The build uses Maven's native-maven-plugin with cross-compilation toolchain. The `native-only` profile compiles only native code, skipping Java compilation and JAR packaging to focus on producing the compiled artifacts.
