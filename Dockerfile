# Multi-stage Docker build for stooge network traffic replayer
FROM ubuntu:latest

# Install build tools and g++-14 (required for C++23 support)
RUN apt-get update && apt-get install -y \
    software-properties-common \
    && add-apt-repository ppa:ubuntu-toolchain-r/test -y \
    && apt-get update \
    && apt-get install -y \
    build-essential \
    cmake \
    g++-14 \
    libpcap-dev \
    liblua5.4-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set g++-14 as default compiler
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 100 \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100

WORKDIR /app

# Copy all source files into container
COPY . .

# Build using CMake
RUN cmake -B build && cmake --build build

# Entry point - run stooge binary with PCAP file argument
ENTRYPOINT ["./build/stooge"]
