# stooge

Network traffic replayer with Lua dissector support - replay PCAP files with timing preservation and protocol analysis.

## Quick Start

Run with a PCAP file:

```bash
docker run --rm -v $(pwd):/data deanturpin/stooge /data/capture.pcapng
```

Live capture mode (requires elevated privileges):

```bash
docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW --net=host deanturpin/stooge
```

## Features

- Replays network traffic from Wireshark PCAP files
- Preserves original packet timing (configurable speed multiplier)
- Background DNS reverse lookups for hostname resolution
- Lua dissector support (DNS, HTTP) for protocol analysis
- Live capture mode for real-time traffic monitoring

## Building

```bash
docker build -t deanturpin/stooge .
```

## Options

The replay speed can be adjusted by modifying `SPEEDUP_FACTOR` in the source (default: 4x).

## Protocol Dissectors

Includes Wireshark-compatible Lua dissectors for:
- DNS queries and responses
- HTTP traffic (ports 80, 8080)

## Licence

GPL-3.0-or-later
