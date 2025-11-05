# Multi-stage Docker build for stooge network traffic replayer
FROM ubuntu:devel

# Install build tools (ubuntu:devel has latest GCC)
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    gdb \
    libpcap-dev \
    liblua5.4-dev \
    pkg-config \
    git \
    catch2 \
    ieee-data \
    && rm -rf /var/lib/apt/lists/*

# Install FTXUI for terminal UI
RUN git clone https://github.com/ArthurSonzogni/FTXUI.git /tmp/ftxui \
    && cd /tmp/ftxui \
    && mkdir build && cd build \
    && cmake .. \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/ftxui

# Show compiler version
RUN g++ --version

WORKDIR /app

# Copy all source files into container
COPY . .

# Build using CMake (parallel build with all available cores)
RUN cmake -B build && cmake --build build --parallel

# Entry point - run stooge binary with PCAP file argument
ENTRYPOINT ["./build/stooge"]
