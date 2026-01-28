#!/usr/bin/env bash
# Build Frida for MacOS using Clang toolchain
# Bash script to download and build Frida Core for MacOS

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

function fetch_arch_devkit() {
  local arch="$1"
  echo "Fetching macOS ${arch} devkit..."
  mkdir -p "macos-${arch}"
  curl --progress-bar --location --output - \
    "$FRIDA_URL/$FRIDA_VERSION/frida-core-devkit-$FRIDA_VERSION-macos-$arch.tar.xz" \
    | tar -x -J --directory "macos-${arch}"
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

# Check if arm devkit already exists, otherwise download
if [ ! -d "macos-arm64" ]; then
  echo "macOS arm64 devkit not found. Proceeding to download..."
  fetch_arch_devkit "arm64"
fi

if [ ! -d "macos-x86_64" ]; then
  echo "macOS x86_64 devkit not found. Proceeding to download..."
  fetch_arch_devkit "x86_64"
fi

################################################################################
## Define compilation flags
################################################################################
# -shared: Create a shared library (.dylib)
CFLAGS="-shared"

## Linker flags
# -Wl,-force_load:    Include all object files from the static library (macOS equivalent of --whole-archive)
# -Wl,-install_name:  Set the dylib install name for runtime loading
# -Wl,-w:             Suppress alignment warnings on x86_64
LDFLAGS_COMMON="-Wl,-install_name,@rpath/libfrida-core.dylib"
LDFLAGS_ARM64="$LDFLAGS_COMMON -Wl,-force_load,macos-arm64/libfrida-core.a"
LDFLAGS_X86_64="$LDFLAGS_COMMON -Wl,-force_load,macos-x86_64/libfrida-core.a -Wl,-w"

## Frameworks and libraries to link against
# Core system frameworks required by Frida
FRAMEWORKS="-framework CoreFoundation \
           -framework Foundation \
           -framework AppKit \
           -framework IOKit \
           -framework Security"

## System libraries
# -bsm:     Basic Security Module library
# -dl:      Dynamic linking library
# -m:       Math library
# -resolv:  DNS resolution library
LIBS="-lbsm -ldl -lm -lresolv"

## Optional: optimization flags
# -O2:              Optimize
# -DNDEBUG:         Disable debug assertions
# -Wl,-dead_strip:  Remove unused code (macOS equivalent of --gc-sections)
# -Wl,-x:           Strip local symbols
OPTFLAGS="-O2 -DNDEBUG -Wl,-dead_strip -Wl,-x"
#################################################################################

# Build ARM dylib with all required frameworks
if [ ! -f "libfrida-core-arm64.dylib" ]; then
  clang $CFLAGS \
    -arch arm64 \
    $OPTFLAGS \
    -o libfrida-core-arm64.dylib \
    $LDFLAGS_ARM64 \
    $FRAMEWORKS \
    $LIBS
fi

# Build x86_64 dylib with all required frameworks
if [ ! -f "libfrida-core-x86_64.dylib" ]; then
  clang $CFLAGS \
    -arch x86_64 \
    $OPTFLAGS \
    -o libfrida-core-x86_64.dylib \
    $LDFLAGS_X86_64 \
    $FRAMEWORKS \
    $LIBS
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
