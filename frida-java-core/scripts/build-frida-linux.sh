#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="${SCRIPT_DIR}/../../"
readonly TARGET_DIR="${PROJECT_DIR}/frida-java-core/frida-devkit"
readonly FRIDA_VERSION="17.5.1"
readonly FRIDA_URL="https://github.com/frida/frida/releases/download"

get_arch() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)   echo "x86_64" ;;
    i386|i686) echo "x86" ;;
    arm64|aarch64) echo "arm64" ;;
    *)        echo "unknown" ;;
  esac
}

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

# Detect current architecture
CURRENT_ARCH="$(get_arch)"

if [ "$CURRENT_ARCH" != "x86_64" ] && [ "$CURRENT_ARCH" != "arm64" ]; then
  echo "Unsupported architecture: $(uname -m)"
  exit 1
fi

echo "Building for current architecture: $CURRENT_ARCH"

# Check if devkit already exists, otherwise download
if [ ! -d "linux-${CURRENT_ARCH}" ]; then
  echo "Linux ${CURRENT_ARCH} devkit not found. Proceeding to download..."
  fetch_arch_devkit "$CURRENT_ARCH"
fi

# Build shared library for current architecture
gcc -shared \
  -fPIC \
  -o "libfrida-core-${CURRENT_ARCH}.so" \
  -Wl,--whole-archive,"linux-${CURRENT_ARCH}/libfrida-core.a" \
  -Wl,--no-whole-archive \
  -Wl,-soname,libfrida-core.so \
  -Wl,-z,noexecstack \
  -ldl \
  -lm \
  -pthread \
  -lrt

# Verify
file "libfrida-core-${CURRENT_ARCH}.so"