#!/usr/bin/env bash

# TODO make this version configurable via command line argument...
readonly FRIDA_VERSION="17.5.1"
readonly BASE_URL="https://github.com/frida/frida/releases/download"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEVKIT_DIR="${SCRIPT_DIR}/../frida-devkit"

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
  if ! curl --progress-bar --location --output - "${download_url}" | tar -x -J --directory "${target_dir}"; then
    echo "Error: Failed to download or extract ${arch} devkit"
    return 1
  fi

  echo "Successfully downloaded and extracted ${arch} devkit"
  return 0
}

fetch_macos_devkits() {
  echo "Fetching devkits for macOS (both x86_64 and arm64 architectures)..."

  local architectures=("x86_64" "arm64")

  for target_arch in "${architectures[@]}"; do
    local target_dir="${DEVKIT_DIR}/macos-${target_arch}"
    if ! download_and_extract "macos" "${target_arch}" "${target_dir}"; then
      return 1
    fi
  done

  echo "macOS devkits downloaded successfully"
  return 0
}

fetch_linux_devkits() {
  echo "Fetching devkits for Linux (both x86_64 and arm64 architectures)..."

  local architectures=("x86_64" "arm64")

  for target_arch in "${architectures[@]}"; do
    local target_dir="${DEVKIT_DIR}/linux-${target_arch}"

    if ! download_and_extract "linux" "${target_arch}" "${target_dir}"; then
      return 1
    fi
  done

  echo "Linux devkits downloaded successfully"
  return 0
}

fetch_windows_devkits() {
  echo "Fetching devkits for Windows (both x86_64 and arm64 architectures)..."

  local architectures=("x86_64" "arm64")

  for target_arch in "${architectures[@]}"; do
    local target_dir="${DEVKIT_DIR}/windows-${target_arch}"

    if ! download_and_extract "windows" "${target_arch}" "${target_dir}"; then
      return 1
    fi
  done

  echo "Windows devkits downloaded successfully"
  return 0
}

fetch_devkit() {
  if [ -d "${DEVKIT_DIR}" ]; then
    echo "Devkit directory already exists"
    return 0
  fi

  # Create the frida-devkit directory
  mkdir -p "${DEVKIT_DIR}"

  echo "Fetching devkits for all platforms (macOS, Linux, Windows)..."

  # Fetch devkits for all platforms
  if ! fetch_macos_devkits; then
    echo "Error: Failed to fetch macOS devkits"
    return 1
  fi

  if ! fetch_linux_devkits; then
    echo "Error: Failed to fetch Linux devkits"
    return 1
  fi

  if ! fetch_windows_devkits; then
    echo "Error: Failed to fetch Windows devkits"
    return 1
  fi

  return 0
}

main() {
  echo "Downloading Frida devkits..."

  if ! fetch_devkit; then
    echo "Error: Failed to fetch devkits"
    exit 1
  fi

  echo "All devkit(s) downloaded successfully"
  return 0
}

main "$@"