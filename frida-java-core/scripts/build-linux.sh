#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="${SCRIPT_DIR}/../../"
readonly DOCKER_IMAGE_NAME="frida-java-linux-build"
readonly DOCKER_CONTAINER_NAME="frida-java-linux-exec"

# check if docker is installed
if ! command -v docker &> /dev/null
then
    echo "Docker could not be found. Please install Docker to proceed."
    exit 1
fi

# Build the Docker image for Linux frida-java
docker build -f "${PROJECT_DIR}/frida-java-core/docker/linux-builder.Dockerfile" -t "${DOCKER_IMAGE_NAME}" "${PROJECT_DIR}"

# Create and run a container from the image
docker run --name "${DOCKER_CONTAINER_NAME}" "${DOCKER_IMAGE_NAME}"

# Ensure target directory exists
mkdir -p "${PROJECT_DIR}/frida-java-core/target"

# Copy libraries to target directory
docker cp "${DOCKER_CONTAINER_NAME}":/app/frida-java-core/target/libfrida-java-linux-x86_64.so "${PROJECT_DIR}/frida-java-core/target/"
docker cp "${DOCKER_CONTAINER_NAME}":/app/frida-java-core/target/libfrida-java-linux-arm64.so "${PROJECT_DIR}/frida-java-core/target/"

# Clean up the container
docker rm "${DOCKER_CONTAINER_NAME}"

echo "Linux native libraries built successfully and copied to target directory"
echo "If you don't need it anymore, please remove the Docker image using:"
echo "  docker rmi ${DOCKER_IMAGE_NAME}"
