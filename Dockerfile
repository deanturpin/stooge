# Multi-stage Docker build for stooge network traffic replayer
FROM ubuntu:devel

# Install build tools (ubuntu:devel has latest GCC)
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    libpcap-dev \
    liblua5.4-dev \
    pkg-config \
    git \
    catch2 \
    && rm -rf /var/lib/apt/lists/*

# Install FTXUI for terminal UI
RUN git clone https://github.com/ArthurSonzogni/FTXUI.git /tmp/ftxui \
    && cd /tmp/ftxui \
    && mkdir build && cd build \
    && cmake .. \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/ftxui

# Download IEEE OUI database for MAC vendor lookup
RUN apt-get update && apt-get install -y wget \
    && wget -q https://standards-oui.ieee.org/oui/oui.txt -O /usr/share/oui.txt \
    && apt-get remove -y wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Show compiler version
RUN g++ --version

WORKDIR /app

# Copy all source files into container
COPY . .

# Build using CMake
RUN cmake -B build && cmake --build build

# Entry point - run stooge binary with PCAP file argument
ENTRYPOINT ["./build/stooge"]
