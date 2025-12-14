# Multi-stage Docker build for stooge network traffic analyser
# Stage 1: Builder - compile FTXUI and stooge (cached separately for efficiency)
FROM ubuntu:devel AS builder

# Install build tools and development libraries
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

# Build and install FTXUI (this layer gets cached separately from source changes)
RUN git clone https://github.com/ArthurSonzogni/FTXUI.git /tmp/ftxui \
    && cd /tmp/ftxui \
    && mkdir build && cd build \
    && cmake .. \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/ftxui

WORKDIR /app

# Copy source files and build stooge
COPY . .
RUN cmake -B build && cmake --build build --parallel

# Stage 2: Runtime - minimal image with only runtime dependencies
FROM ubuntu:devel

# Install only runtime libraries and essential tools
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    liblua5.4-0 \
    arp-scan \
    figlet \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled binary from builder stage
COPY --from=builder /app/build/stooge /app/stooge

# Copy FTXUI runtime libraries from builder stage
COPY --from=builder /usr/local/lib/libftxui* /usr/local/lib/

# Copy Lua dissectors for protocol analysis
COPY --from=builder /app/dissectors /app/dissectors

# Copy recent commits file for splash screen
COPY --from=builder /app/recent-commits.txt /app/recent-commits.txt

# Update linker cache to find FTXUI libraries
RUN ldconfig

# Entry point - run stooge with splash screen wrapper
ENTRYPOINT ["sh", "-c", "clear && figlet stooge && cat /etc/os-release && echo && cat /app/recent-commits.txt && echo && sleep 2 && exec /app/stooge \"$@\"", "--"]
