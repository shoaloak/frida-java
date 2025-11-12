#!/bin/bash
set -e

# Source environment
source /etc/environment

echo "=== Starting macOS Cross-Compilation Build ==="
echo "Build timestamp: $(date)"
echo "Java Home: $JAVA_HOME"
echo "Java version:"
java -version
echo "Maven version:"
mvn -version

# Detect available cross-compilers
echo "=== Cross-Compiler Detection ==="
OSXCROSS_PATH="/opt/osxcross/bin"
if [ -d "$OSXCROSS_PATH" ]; then
    echo "Available cross-compilers:"
    for compiler in "$OSXCROSS_PATH"/*clang*; do
        if [[ -f "$compiler" ]]; then
            basename "$compiler"
        fi
    done

    # Set up compiler environment
    export PATH="$OSXCROSS_PATH:$PATH"
    export OSXCROSS_ROOT="/opt/osxcross"

    # Detect available architectures
    X86_COMPILER="$OSXCROSS_PATH/x86_64-apple-darwin24-clang"
    ARM_COMPILER="$OSXCROSS_PATH/aarch64-apple-darwin24-clang"

    if [ -f "$X86_COMPILER" ]; then
        echo "✓ x86_64 compiler found: $X86_COMPILER"
        HAS_X86=true
    else
        echo "✗ x86_64 compiler not found"
        HAS_X86=false
    fi

    if [ -f "$ARM_COMPILER" ]; then
        echo "✓ ARM64 compiler found: $ARM_COMPILER"
        HAS_ARM=true
    else
        echo "✗ ARM64 compiler not found"
        HAS_ARM=false
    fi
else
    echo "ERROR: OSXCross not found at $OSXCROSS_PATH"
    exit 1
fi

# Create output directories
mkdir -p /workspace/build-output/macos/{x86_64,arm64,universal}

# Navigate to core project
if [ ! -d "/workspace/frida-java-core" ]; then
    echo "ERROR: frida-java-core directory not found"
    exit 1
fi

cd /workspace/frida-java-core

# Function to build native code manually (bypassing Maven's native plugin issues)
build_native_arch() {
    local arch=$1
    local compiler=$2
    local target=$3
    local frida_arch=$4

    echo "=== Building native code for $arch ==="
    echo "Using compiler: $compiler"
    echo "Target: $target"

    # Set up directories
    local obj_dir="target/objs/$arch"
    mkdir -p "$obj_dir"

    # Compile native code
    echo "Compiling native sources..."
    $compiler \
        --target=$target \
        -fPIC \
        -I"$JAVA_HOME/include" \
        -I"$JAVA_HOME/include/linux" \
        -I"frida-devkit/macos-$frida_arch" \
        -c src/main/native/_frida_java.c \
        -o "$obj_dir/_frida_java.o"

    # Link shared library
    echo "Linking shared library..."
    $compiler \
        --target=$target \
        -shared \
        -o "target/libfrida-java-$arch.dylib" \
        "$obj_dir/_frida_java.o" \
        -L"frida-devkit/macos-$frida_arch" \
        -lfrida-core \
        -framework Foundation \
        -framework AppKit \
        -framework IOKit \
        -framework Security \
        -lbsm \
        -ldl \
        -lm \
        -lresolv \
        -Wl,-w

    echo "✓ $arch native build completed"
}

# Function to build native-only with Maven using cross-compilation
build_native_only() {
    echo "=== Building Native Libraries Only ==="

    # Clean previous builds
    mvn clean -q

    # Set up cross-compiler environment for Maven
    export CC="$X86_COMPILER --target=x86_64-apple-darwin24"
    export CXX="$X86_COMPILER --target=x86_64-apple-darwin24"
    export AR="x86_64-apple-darwin24-ar"
    export STRIP="x86_64-apple-darwin24-strip"
    export RANLIB="x86_64-apple-darwin24-ranlib"

    # Update Maven properties for cross-compilation
    export MAVEN_OPTS="-Dnative.compiler.macos=$X86_COMPILER"

    echo "Cross-compiler environment:"
    echo "CC: $CC"
    echo "Maven compiler: $X86_COMPILER"

    # Use maven to compile native code with native-only profile
    echo "Building with Maven native-only profile and cross-compilers..."

    # Use the native-only profile with cross-compiler
    mvn compile -Pnative-only \
        -Dnative.compiler.macos="$X86_COMPILER" \
        -Djava.home="$JAVA_HOME" \
        -X || {

        echo "Maven native plugin failed, falling back to manual compilation..."

        # Fallback to manual compilation if Maven plugin doesn't work with cross-compiler
        build_native_arch "x86_64" "$X86_COMPILER" "x86_64-apple-darwin24" "x86_64"

        if [ "$HAS_ARM" = true ]; then
            build_native_arch "arm64" "$ARM_COMPILER" "aarch64-apple-darwin24" "arm64"
        fi

        # Create universal binary if both architectures are available
        if [ "$HAS_X86" = true ] && [ "$HAS_ARM" = true ]; then
            echo "=== Creating Universal Binary ==="
            lipo -create \
                target/libfrida-java-x86_64.dylib \
                target/libfrida-java-arm64.dylib \
                -output target/libfrida-java.dylib
            echo "✓ Universal binary created"
        elif [ "$HAS_X86" = true ]; then
            # Copy x86_64 as universal if only x86_64 is available
            cp target/libfrida-java-x86_64.dylib target/libfrida-java.dylib
        elif [ "$HAS_ARM" = true ]; then
            # Copy arm64 as universal if only arm64 is available
            cp target/libfrida-java-arm64.dylib target/libfrida-java.dylib
        fi
    }

    echo "✓ Native compilation completed"
}

# Build native libraries only
build_native_only

# Copy entire target directory with all compiled artifacts
echo "=== Copying Target Directory with All Artifacts ==="
mkdir -p /workspace/build-output/target
cp -r target/* /workspace/build-output/target/ 2>/dev/null || echo "No target files found"

echo "=== Native Build Summary ==="
echo "Native compilation completed at: $(date)"
echo "Target directory copied to: /workspace/build-output/target/"
echo ""
echo "Compiled artifacts:"
echo "- Object files (.o):"
find /workspace/build-output/target -name "*.o" -exec ls -la {} \; 2>/dev/null || echo "  No object files found"
echo "- Dynamic libraries (.dylib):"
find /workspace/build-output/target -name "*.dylib" -exec ls -la {} \; 2>/dev/null || echo "  No dylib files found"
echo ""
echo "Complete target directory structure:"
find /workspace/build-output/target -type f -exec ls -la {} \; 2>/dev/null || echo "  No files found"

echo "=== Native build completed successfully! ==="
