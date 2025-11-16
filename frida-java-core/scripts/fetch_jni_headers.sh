#!/usr/bin/env bash

readonly JDK_REPO_URL="https://github.com/openjdk/jdk.git"
# TODO make this version configurable via command line argument...
readonly JDK_TAG="jdk-21+35"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly JNI_DIR="${SCRIPT_DIR}/../jni-headers"

# Temporary directory for cloning
readonly TEMP_JDK_DIR="/tmp/openjdk-jni-$$"

clone_jdk_repo() {
  echo "Cloning OpenJDK (tag: $JDK_TAG) to temporary directory..."

  if ! git clone --depth 1 --branch "$JDK_TAG" --single-branch \
    "$JDK_REPO_URL" "$TEMP_JDK_DIR"; then
    echo "Error: Failed to clone OpenJDK repository"
    return 1
  fi

  echo "Successfully cloned OpenJDK repository"
  return 0
}

copy_headers_for_os() {
  local os="$1"

  case "$os" in
    linux|macos)
      # Unix variant headers are used for both Linux and macOS
      local jni_md_path="$TEMP_JDK_DIR/src/java.base/unix/native/include/jni_md.h"
      ;;
    windows)
      # Windows-specific headers
      local jni_md_path="$TEMP_JDK_DIR/src/java.base/windows/native/include/jni_md.h"
      ;;
    *)
      echo "Error: Unknown OS key: $os" >&2
      return 1
      ;;
  esac

  local jni_common_path="$TEMP_JDK_DIR/src/java.base/share/native/include/jni.h"

  if [ ! -f "$jni_common_path" ]; then
    echo "Error: Missing jni.h at $jni_common_path" >&2
    return 1
  fi

  if [ ! -f "$jni_md_path" ]; then
    echo "Error: Missing jni_md.h for $os at $jni_md_path" >&2
    return 1
  fi

  local dest_dir="$JNI_DIR/$os"
  mkdir -p "$dest_dir"

  echo "Copying JNI headers for $os -> $dest_dir"
  if ! cp "$jni_common_path" "$dest_dir/jni.h"; then
    echo "Error: Failed to copy jni.h for $os"
    return 1
  fi

  if ! cp "$jni_md_path" "$dest_dir/jni_md.h"; then
    echo "Error: Failed to copy jni_md.h for $os"
    return 1
  fi

  echo "Successfully copied JNI headers for $os"
  return 0
}

fetch_jni_headers() {
  echo "Fetching JNI headers for all platforms (Linux, macOS, Windows)..."

  if [ -d "$JNI_DIR" ]; then
    echo "JNI headers directory already exists, removing..."
    rm -rf "$JNI_DIR"
  fi

  # Create the JNI headers directory
  mkdir -p "$JNI_DIR"

  # Clone the OpenJDK repository to a temporary directory
  if ! clone_jdk_repo; then
    echo "Error: Failed to clone OpenJDK repository"
    return 1
  fi

  # Copy headers for all platforms
  local platforms=("linux" "macos" "windows")

  for platform in "${platforms[@]}"; do
    if ! copy_headers_for_os "$platform"; then
      echo "Error: Failed to copy headers for $platform"
      return 1
    fi
  done

  # Clean up temporary directory
  echo "Cleaning up temporary directory..."
  rm -rf "$TEMP_JDK_DIR"

  return 0
}

main() {
  echo "Downloading JNI headers..."

  if ! fetch_jni_headers; then
    echo "Error: Failed to fetch JNI headers"
    exit 1
  fi

  echo "JNI headers downloaded successfully"
  echo "Headers are available in: $JNI_DIR"
  echo "    - $JNI_DIR/linux"
  echo "    - $JNI_DIR/macos"
  echo "    - $JNI_DIR/windows"
  return 0
}

main "$@"
