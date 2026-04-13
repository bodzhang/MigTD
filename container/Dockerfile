FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c AS buildenv

# Adding rust binaries to PATH.
ENV PATH="$PATH:/root/.cargo/bin"
WORKDIR /root

# Install all required packages in one go to optimize the image
# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# DEBIAN_FRONTEND is set for tzdata.
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    build-essential \
    unzip \
    ca-certificates \
    curl \
    gcc \
    git \
    libssl-dev \
    pkg-config \
    ssh \
    clang \
    llvm \
    nasm \
    ocaml \
    ocamlbuild \
    wget \
    libtool \
    autoconf \
    autotools-dev \
    automake \
    screen \
    expect \
    python3 \
    python3-pip \
    && pip install pytest --break-system-packages \
    # cleanup
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install rustup and a fixed version of Rust.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.88.0
RUN rustup component add rust-src
RUN cargo install cargo-xbuild
RUN rustup target add x86_64-unknown-none

# clang targeting x86_64-unknown-none-elf does not search the Ubuntu 24.04
# multiarch directory by default, causing ring's C code to fail when it reaches
# bits/libc-header-start.h via the system stdint.h.  Point cc-rs at the right
# directory so the C compilation succeeds.
ENV CFLAGS_x86_64_unknown_none="-I/usr/include/x86_64-linux-gnu"

FROM buildenv AS full

ARG MIGTD_COMMIT=""
RUN git clone https://github.com/intel/MigTD.git && \
    cd MigTD && \
    if [ -n "${MIGTD_COMMIT}" ]; then git checkout ${MIGTD_COMMIT}; fi && \
    git submodule update --init --recursive
