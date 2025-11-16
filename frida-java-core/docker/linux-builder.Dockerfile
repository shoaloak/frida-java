FROM debian:forky

# Install system dependencies
RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install --yes --no-install-recommends \
    clang lld \
    libc6-dev-amd64-cross libc6-amd64-cross \
    libc6-dev-arm64-cross libc6-arm64-cross \
    crossbuild-essential-amd64 crossbuild-essential-arm64 \
    openjdk-21-jdk-headless maven \
    curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Set up build environment
WORKDIR /app
# copy parent project into container
COPY . /app

# Install project dependencies
RUN mvn --errors --define aether.dependencyCollector.impl=bf --define maven.artifact.threads=16 dependency:go-offline

# x86_64
RUN mvn compile \
    --projects frida-java-core \
    -Dtarget=linux-x86_64

# arm64
RUN mvn compile \
    --projects frida-java-core \
    -Dtarget=linux-arm64

CMD ["bash"]