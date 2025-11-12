#!/bin/bash
set -e

# Navigate to project root
cd "$(dirname "$0")/.."

echo "=== Building macOS Native Cross-Compilation Docker Image ==="
docker build -t frida-java-macos-native -f docker/Dockerfile.macos .

echo "=== Running macOS Native Cross-Compilation Build ==="
docker run --rm -v "$(pwd)/build-output:/workspace/build-output" frida-java-macos-native

echo "=== Native Build Complete ==="
echo "Compiled artifacts available in: ./build-output/target/"
echo ""
echo "Contents:"
echo "- Object files (.o):"
find ./build-output/target -name "*.o" -exec ls -la {} \; 2>/dev/null || echo "  No object files found"
echo "- Dynamic libraries (.dylib):"
find ./build-output/target -name "*.dylib" -exec ls -la {} \; 2>/dev/null || echo "  No dylib files found"
echo ""
echo "Complete target directory structure:"
ls -la ./build-output/target/ 2>/dev/null || echo "Build output directory not found"
