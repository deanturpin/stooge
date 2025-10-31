# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**stooge** is a network traffic replayer that impersonates captured sessions from Wireshark PCAP files. Currently in evaluation phase (see [issue #23](https://github.com/deanturpin/projects/issues/23)).

## Technology Stack

- **Language**: Modern C++ (latest standard)
- **Build System**: CMake
- **Container**: Ubuntu (latest) Docker container
- **Key Libraries**: `libpcap` for PCAP parsing
- **Deployment**: Docker with multi-stage builds

## Planned Architecture

When implemented, the codebase will follow this structure:

- `main.cpp` - CLI entry point
- `parser/` - PCAP file parsing using libpcap
- `replayer/` - Timing engine and network injection with proper TCP state handling
- `CMakeLists.txt` - CMake build configuration
- `Dockerfile` - Ubuntu-based container with build environment

## Core Functionality

The tool needs to:
1. Parse PCAP files (Wireshark/tcpdump format)
2. Extract connection parameters (IP, port, credentials)
3. Honour original packet timing for realistic replay
4. Handle application-layer replay with proper TCP state management

## Development Commands

All development happens inside Docker containers:

Building and running:
- `docker build -t stooge .` - Build the Docker image
- `docker run stooge` - Run the application
- `docker run stooge <pcap-file>` - Run with PCAP file

CMake workflow (inside container):
- `cmake -B build` - Configure build
- `cmake --build build` - Build the binary
- `ctest --test-dir build` - Run tests
- `make deploy` - Auto-commit and push changes
