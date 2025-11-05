#!/usr/bin/env bash

readonly FRIDA_VERSION="17.5.0"

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

  # Construct the download URL
  local base_url="https://github.com/frida/frida/releases/download"
  local file_name="frida-core-devkit-${FRIDA_VERSION}-${os}-${arch}.tar.xz"
  local download_url="${base_url}/${FRIDA_VERSION}/${file_name}"

  if [ ! -d "frida-devkit" ]; then
      mkdir frida-devkit
  fi

  curl --progress-bar --location --output - "${download_url}" \
    | tar -x --directory frida-devkit
}

function main() {
  echo "Fetching and extracting Frida DevKit..."
  fetch_devkit
}

main "$@"