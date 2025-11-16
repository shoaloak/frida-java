FROM debian:forky

# Install system dependencies
RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install --yes --no-install-recommends \
    clang lld llvm \
    libc6-dev-amd64-cross libc6-dev-arm64-cross \
    openjdk-21-jdk-headless maven \
    python3 msitools ca-certificates \
    git curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Download and set up MSVC using msvc-wine
RUN cd /tmp \
    && git clone https://github.com/mstorsjo/msvc-wine.git \
    && cd msvc-wine \
    && python3 vsdownload.py --accept-license --dest /opt/msvc \
    && ./install.sh /opt/msvc \
    && cd / \
    && rm -rf /tmp/msvc-wine

# Set environment variables for clang cross-compilation with MSVC headers/libs
ENV MSVC_ROOT=/opt/msvc
ENV PATH="$PATH:/opt/msvc/bin/x64:/opt/msvc/bin/arm64"

# Set up build environment
WORKDIR /app
# copy parent project into container
COPY . /app

# Install project dependencies
RUN mvn --errors --define aether.dependencyCollector.impl=bf --define maven.artifact.threads=16 dependency:go-offline

# Set up MSVC environment for cross-compilation
RUN echo '#!/bin/bash\nBIN=/opt/msvc/bin/x64 . /tmp/msvcenv-native.sh\nexec "$@"' > /usr/local/bin/with-msvc-x64 \
    && chmod +x /usr/local/bin/with-msvc-x64 \
    && echo '#!/bin/bash\nBIN=/opt/msvc/bin/arm64 . /tmp/msvcenv-native.sh\nexec "$@"' > /usr/local/bin/with-msvc-arm64 \
    && chmod +x /usr/local/bin/with-msvc-arm64

# Copy msvcenv-native.sh script to /tmp for environment setup
RUN cd /tmp \
    && git clone --depth 1 https://github.com/mstorsjo/msvc-wine.git msvc-wine-scripts \
    && cp msvc-wine-scripts/msvcenv-native.sh /tmp/ \
    && rm -rf msvc-wine-scripts

RUN BIN=/opt/msvc/bin/x64 . /tmp/msvcenv-native.sh && mvn compile \
    --projects frida-java-core \
    -Dtarget=windows-x86_64

CMD ["bash"]
