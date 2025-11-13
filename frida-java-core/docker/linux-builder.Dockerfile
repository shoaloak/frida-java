FROM debian:forky

# Install system dependencies
RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install --yes --no-install-recommends \
    gcc-x86-64-linux-gnu libc6-dev-amd64-cross \
    gcc-aarch64-linux-gnu libc-dev-arm64-cross \
    openjdk-21-jdk-headless maven \
    curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Set up build environment
WORKDIR /app
# copy parent project into container
COPY . /app

# Install project dependencies
RUN bash /app/frida-java-core/scripts/fetch_devkit.sh \
    && mvn --errors --define aether.dependencyCollector.impl=bf --define maven.artifact.threads=16 dependency:go-offline

# x86_64
RUN mvn compile \
    --projects frida-java-core \
    -Dtarget.arch=x86_64 \
    -Dnative.compiler.linux=x86_64-linux-gnu-gcc \
    -Dnative.linker.linux=x86_64-linux-gnu-ld

# arm64
RUN mvn compile \
    --projects frida-java-core \
    -Dtarget.arch=arm64 \
    -Dnative.compiler.linux=aarch64-linux-gnu-gcc \
    -Dnative.linker.linux=aarch64-linux-gnu-ld

CMD ["bash"]