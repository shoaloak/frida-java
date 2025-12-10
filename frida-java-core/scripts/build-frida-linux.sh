#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="${SCRIPT_DIR}/../../"
readonly TARGET_DIR="${PROJECT_DIR}/frida-java-core/frida-devkit"
readonly FRIDA_VERSION="17.5.1"
readonly FRIDA_URL="https://github.com/frida/frida/releases/download"

function fetch_arch_devkit() {
  local arch="$1"
  echo "Fetching Linux ${arch} devkit..."
  mkdir -p "linux-${arch}"
  curl --progress-bar --location --output - \
    "$FRIDA_URL/$FRIDA_VERSION/frida-core-devkit-$FRIDA_VERSION-linux-$arch.tar.xz" \
    | tar -x -J --directory "linux-${arch}"
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
if [ ! -d "linux-arm64" ]; then
  echo "Linux arm64 devkit not found. Proceeding to download..."
  fetch_arch_devkit "arm64"
fi

if [ ! -d "linux-x86_64" ]; then
  echo "Linux x86_64 devkit not found. Proceeding to download..."
  fetch_arch_devkit "x86_64"
fi

# Build ARM64 shared library
gcc -shared \
  -fPIC \
  -o libfrida-core-arm64.so \
  -Wl,--whole-archive,linux-arm64/libfrida-core.a \
  -Wl,--no-whole-archive \
  -Wl,-soname,libfrida-core.so \
  -ldl \
  -lm \
  -pthread \
  -lrt

# Build x86_64 shared library
gcc -shared \
  -fPIC \
  -o libfrida-core-x86_64.so \
  -Wl,--whole-archive,/linux-x86_64/libfrida-core.a \
  -Wl,--no-whole-archive \
  -Wl,-soname,libfrida-core.so \
  -ldl \
  -lm \
  -pthread \
  -lrt

# Verify
file libfrida-core-arm64.so
file libfrida-core-x86_64.so