#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="${SCRIPT_DIR}/../../"
readonly TARGET_DIR="${PROJECT_DIR}/frida-java-core/frida-devkit"
readonly FRIDA_VERSION="17.5.1"
readonly FRIDA_URL="https://github.com/frida/frida/releases/download"

function fetch_arch_devkit() {
  local arch="$1"
  echo "Fetching macOS ${arch} devkit..."
  mkdir -p "macos-${arch}"
  curl --progress-bar --location --output - \
    "$FRIDA_URL/$FRIDA_VERSION/frida-core-devkit-$FRIDA_VERSION-macos-$arch.tar.xz" \
    | tar -x -J --directory "macos-${arch}"
}

# check if curl is installed
if ! command -v curl &> /dev/null
then
    echo "Curl could not be found. Please install Curl to proceed."
    exit 1
fi

# Prepare directory
mkdir -p "${TARGET_DIR}"
cd "${TARGET_DIR}" || exit

# check if arm devkit already exists, otherwise download
if [ ! -d "macos-arm64" ]; then
  echo "macOS arm64 devkit not found. Proceeding to download..."
  fetch_arch_devkit "arm64"
fi

if [ ! -d "macos-x86_64" ]; then
  echo "macOS x86_64 devkit not found. Proceeding to download..."
  fetch_arch_devkit "x86_64"
fi

# Build ARM dylib with all required frameworks
if [ ! -f "libfrida-core-arm64.dylib" ]; then
  clang -shared \
    -arch arm64 \
    -o libfrida-core-arm64.dylib \
    -Wl,-force_load,macos-arm64/libfrida-core.a \
    -Wl,-install_name,@rpath/libfrida-core.dylib \
    -framework CoreFoundation \
    -framework Foundation \
    -framework AppKit \
    -framework IOKit \
    -framework Security \
    -lbsm \
    -ldl \
    -lm \
    -lresolv
fi

# Build x86_64 dylib with all required frameworks
if [ ! -f "libfrida-core-x86_64.dylib" ]; then
  # -Wl,-w suppresses "ld: warning: alignment (1) of atom is too small and may result in unaligned pointers"
  clang -shared \
    -arch x86_64 \
    -o libfrida-core-x86_64.dylib \
    -Wl,-force_load,macos-x86_64/libfrida-core.a \
    -Wl,-install_name,@rpath/libfrida-core.dylib \
    -Wl,-w \
    -framework CoreFoundation \
    -framework Foundation \
    -framework AppKit \
    -framework IOKit \
    -framework Security \
    -lbsm \
    -ldl \
    -lm \
    -lresolv
fi

# Merge into universal dylib
lipo -create \
  libfrida-core-arm64.dylib \
  libfrida-core-x86_64.dylib \
  -output libfrida-core.dylib

# Verify
lipo -info libfrida-core.dylib

# Cleanup
rm libfrida-core-arm64.dylib libfrida-core-x86_64.dylib
