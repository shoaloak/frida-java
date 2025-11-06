#!/usr/bin/env bash

readonly FRIDA_VERSION="17.5.1"
readonly BASE_URL="https://github.com/frida/frida/releases/download"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEVKIT_DIR="${SCRIPT_DIR}/../frida-devkit"

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

download_and_extract() {
  local os="$1"
  local arch="$2"
  local target_dir="$3"

  local file_name="frida-core-devkit-${FRIDA_VERSION}-${os}-${arch}.tar.xz"
  local download_url="${BASE_URL}/${FRIDA_VERSION}/${file_name}"

  echo "Downloading ${arch} devkit..."
  echo "URL: ${download_url}"

  # Create target directory if it doesn't exist
  mkdir -p "${target_dir}"

  # Download and extract
  if ! curl --progress-bar --location --output - "${download_url}" | tar -x --directory "${target_dir}"; then
    echo "Error: Failed to download or extract ${arch} devkit"
    return 1
  fi

  echo "Successfully downloaded and extracted ${arch} devkit"
  return 0
}

function fetch_devkit() {
  local os
  local arch

  os=$(get_os)
  arch=$(get_arch)

  # Create the frida-devkit directory if it doesn't exist
  mkdir -p "${DEVKIT_DIR}"

  # For macOS, fetch both x86_64 and arm64 devkits
  if [ "${os}" = "macos" ]; then
    echo "Fetching devkits for both x86_64 and arm64 architectures..."

    # Define architectures to fetch
    local architectures=("x86_64" "arm64")

    for target_arch in "${architectures[@]}"; do
      if ! download_and_extract "${os}" "${target_arch}" "${DEVKIT_DIR}/${target_arch}"; then
        exit 1
      fi
    done

    echo "Architecture-specific devkits downloaded successfully"
    echo "Note: Headers are kept separate per architecture to avoid conflicts"

  else
    # For non-macOS, use the original single-architecture approach
    if ! download_and_extract "${os}" "${arch}" "${DEVKIT_DIR}"; then
      exit 1
    fi
  fi
}

function main() {
  echo "Fetching and extracting Frida DevKit..."
  fetch_devkit
}

main "$@"