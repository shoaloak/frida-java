#!/usr/bin/env bash

readonly FRIDA_VERSION="17.5.1"
readonly BASE_URL="https://github.com/frida/frida/releases/download"

get_os() {
  local os_name
  os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "${os_name}" in
    linux*)  echo "linux" ;;
    darwin*) echo "macos" ;;
    *)       echo "unsupported" ;;
  esac
}

get_arch() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)   echo "x86_amd64" ;;
    i386|i686) echo "x86" ;;
    arm64|aarch64) echo "arm64" ;;
    *)        echo "unknown" ;;
  esac
}

function fetch_devkit() {
  local os
  local arch

  os=$(get_os)
  arch=$(get_arch)

  # Create the frida-devkit directory if it doesn't exist
  if [ ! -d "frida-devkit" ]; then
      mkdir frida-devkit
  fi

  # For macOS, fetch both x86_64 and arm64 devkits
  if [ "${os}" = "macos" ]; then
    echo "Fetching devkits for both x86_64 and arm64 architectures..."

    # Create directories for each architecture
    if [ ! -d "frida-devkit/x86_64" ]; then
        mkdir -p frida-devkit/x86_64
    fi
    if [ ! -d "frida-devkit/arm64" ]; then
        mkdir -p frida-devkit/arm64
    fi

    # Define architectures to fetch
    local architectures=("x86_64" "arm64")

    for target_arch in "${architectures[@]}"; do
      echo "Downloading ${target_arch} devkit..."

      # Construct the correct URL format
      local file_name="frida-core-devkit-${FRIDA_VERSION}-${os}-${target_arch}.tar.xz"
      local download_url="${BASE_URL}/${FRIDA_VERSION}/${file_name}"

      echo "URL: ${download_url}"

      # Download and extract
      if ! curl --progress-bar --location --output - "${download_url}" | tar -x --directory "frida-devkit/${target_arch}"; then
        echo "Error: Failed to download or extract ${target_arch} devkit"
        exit 1
      fi
    done

    echo "Architecture-specific devkits downloaded successfully"
    echo "Note: Headers are kept separate per architecture to avoid conflicts"

  else
    # For non-macOS, use the original single-architecture approach
    local file_name="frida-core-devkit-${FRIDA_VERSION}-${os}-${arch}.tar.xz"
    local download_url="${BASE_URL}/${FRIDA_VERSION}/${file_name}"

    curl --progress-bar --location --output - "${download_url}" \
      | tar -x --directory frida-devkit
  fi
}

function main() {
  echo "Fetching and extracting Frida DevKit..."
  fetch_devkit
}

main "$@"