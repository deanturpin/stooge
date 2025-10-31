# stooge

A network traffic replayer that impersonates captured sessions - like a
theatrical stooge performing a scripted role.

## Overview

**stooge** is a tool for replaying network traffic from Wireshark PCAP files,
preserving timing and connection parameters. It's designed to help with
interface design and testing by simulating real network interactions based on
captured logs.

## Features

- Parse PCAP files captured by Wireshark/tcpdump
- Extract connection parameters (IP, port, credentials)
- Honour original packet timing for realistic replay
- Application-layer replay with proper TCP state handling
- Docker deployment for easy distribution

## Technology

- **Language**: Go - for excellent networking libraries and easy deployment
- **Key Libraries**: `gopacket` for PCAP parsing
- **Deployment**: Docker with multi-stage builds for minimal image size

## Project Status

Currently in evaluation phase. See
[issue #23](https://github.com/deanturpin/projects/issues/23) for progress.

### Roadmap

1. Evaluate existing tools (tcpliveplay, Ostinato, Scapy)
2. Decide build vs buy based on requirements
3. If building:
   - Implement PCAP parser
   - Build timing engine
   - Create network replayer
   - Add Docker support

## Why "stooge"?

A stooge is someone who pretends to be genuine while actually performing a
scripted role - exactly what this tool does with network traffic. It's the
perfect theatrical metaphor for replaying captured sessions.

## Development

Project structure:

```text
stooge/
├── main.go              # CLI entry point
├── parser/
│   └── pcap.go         # PCAP file parsing
├── replayer/
│   └── replay.go       # Timing and network injection
├── Dockerfile
└── go.mod
```

## Use Cases

- Interface design and testing
- Network simulation without live systems
- Performance testing with realistic traffic patterns
- Replaying production issues in development

## Licence

To be determined

## Contributing

This is currently an experimental project. Contributions and suggestions
welcome via issues.
