#!/usr/bin/env bash
# Build Frida for Linux using GCC toolchain
# Bash script to download and build Frida Core for Linux

# Copyright (C) 2026 Axel Koolhaas
#
# This file is part of frida-java.
#
# frida-java is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# frida-java is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with frida-java.  If not, see <https://www.gnu.org/licenses/>.

# Set error handling - exit on any error, undefined variables, or pipe failures
set -euo pipefail

# Optional: Enable debug mode (uncomment for troubleshooting)
# set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="${SCRIPT_DIR}/../../"
readonly TARGET_DIR="${PROJECT_DIR}/frida-java-core/frida-devkit"

load_frida_config() {
    local config_file="${SCRIPT_DIR}/build.properties"

    if [[ ! -f "$config_file" ]]; then
        echo "Error: Configuration file not found: $config_file"
        exit 1
    fi

    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        # Skip comments and empty lines
        [[ $key =~ ^[[:space:]]*# ]] && continue
        [[ -z $key ]] && continue

        # Remove leading/trailing whitespace
        key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Export the variable
        export "$key"="$value"
    done < "$config_file"
}

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

# Load configuration
load_frida_config

# Check if curl is installed
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

################################################################################
## Define compilation flags
################################################################################
# -shared:  Create a shared library (.so)
# -fPIC:    Generate position-independent code
CFLAGS="-shared -fPIC"

## Linker flags
# -Wl,--whole-archive:    Include all object files from the static library
# -Wl,--no-whole-archive: Stop including all object files
# -Wl,-soname:            Set the shared library name
# -Wl,-z,noexecstack:     Mark the stack as non-executable
LDFLAGS="-Wl,--whole-archive,linux-${CURRENT_ARCH}/libfrida-core.a \
         -Wl,--no-whole-archive \
         -Wl,-soname,libfrida-core.so \
         -Wl,-z,noexecstack"

## Libraries to link against
# -ldl:     Dynamic linking
# -lm:      Math library
# -pthread: POSIX threads
# -lrt:     Real-time extensions
LIBS="-ldl -lm -pthread -lrt"

## Optional: optimization flags
# -O2:                Optimize
# -DNDEBUG:           Disable debug assertions
# -Wl,--gc-sections:  Remove unused sections
# -Wl,-s:             Strip symbols
OPTFLAGS="-O2 -DNDEBUG -Wl,--gc-sections -Wl,-s"
#################################################################################

# Build shared library for current architecture
gcc $CFLAGS $OPTFLAGS \
  -o "libfrida-core-${CURRENT_ARCH}.so" \
  $LDFLAGS \
  $LIBS

# Verify
file "libfrida-core-${CURRENT_ARCH}.so"