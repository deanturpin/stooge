# Multi-stage Docker build for stooge network traffic replayer
FROM ubuntu:devel

# Install build tools and network diagnostics (ubuntu:devel has latest GCC)
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
    arp-scan \
    iputils-ping \
    nmap \
    curl \
    wget \
    tcpdump \
    netcat-openbsd \
    dnsutils \
    figlet \
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

# Remove git history to reduce image size (commits already captured in Makefile)
RUN rm -rf /app/.git

# Entry point - run stooge with splash screen wrapper
ENTRYPOINT ["sh", "-c", "clear && figlet stooge && cat /etc/os-release && echo && echo 'Recent commits:' && cat /app/recent-commits.txt && echo && sleep 2 && exec ./build/stooge \"$@\"", "--"]
