FROM ubuntu:latest

# Install build tools and g++-14
RUN apt-get update && apt-get install -y \
    software-properties-common \
    && add-apt-repository ppa:ubuntu-toolchain-r/test -y \
    && apt-get update \
    && apt-get install -y \
    build-essential \
    cmake \
    g++-14 \
    && rm -rf /var/lib/apt/lists/*

# Set g++-14 as default
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 100 \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100

WORKDIR /app

# Copy source files
COPY . .

# Build
RUN cmake -B build && cmake --build build

# Run
CMD ["./build/stooge"]
