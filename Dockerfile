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
    git \
    && rm -rf /var/lib/apt/lists/*

# Install FTXUI for terminal UI
RUN git clone https://github.com/ArthurSonzogni/FTXUI.git /tmp/ftxui \
    && cd /tmp/ftxui \
    && mkdir build && cd build \
    && cmake .. -DCMAKE_CXX_COMPILER=g++-14 \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/ftxui

# Download IEEE OUI database for MAC vendor lookup
RUN apt-get update && apt-get install -y wget \
    && wget -q https://standards-oui.ieee.org/oui/oui.txt -O /usr/share/oui.txt \
    && apt-get remove -y wget \
    && apt-get autoremove -y \
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
