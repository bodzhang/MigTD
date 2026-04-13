FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c

# Adding rust binaries to PATH.
ENV PATH="$PATH:/root/.cargo/bin"
WORKDIR /root

# Install all required packages in one go to optimize the image
# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# DEBIAN_FRONTEND is set for tzdata.
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    build-essential=12.10ubuntu1 \
    unzip=6.0-28ubuntu4.1 \
    ca-certificates=20240203 \
    curl=8.5.0-2ubuntu10.8 \
    gcc=4:13.2.0-7ubuntu1 \
    git=1:2.43.0-1ubuntu7.3 \
    libssl-dev=3.0.13-0ubuntu3.9 \
    pkg-config=1.8.1-2build1 \
    ssh=1:9.6p1-3ubuntu13.15 \
    clang=1:18.0-59~exp2 \
    llvm=1:18.0-59~exp2 \
    nasm=2.16.01-1build1 \
    ocaml=4.14.1-1ubuntu1 \
    ocamlbuild=0.14.3-1 \
    wget=1.21.4-1ubuntu4.1 \
    libtool=2.4.7-7build1 \
    autoconf=2.71-3 \
    autotools-dev=20220109.1 \
    automake=1:1.16.5-1.3ubuntu1 \
    screen=4.9.1-1ubuntu1 \
    expect=5.45.4-3 \
    python3=3.12.3-0ubuntu2.1 \
    python3-pip=24.0+dfsg-1ubuntu1.3 \
    && pip install pytest==9.0.3 --break-system-packages \
    # cleanup
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install rustup and a fixed version of Rust.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.88.0
RUN rustup component add rust-src
RUN cargo install cargo-xbuild@0.6.6
RUN rustup target add x86_64-unknown-none

RUN git clone --recursive --branch v0.6.0 --depth 1 https://github.com/intel/MigTD.git
