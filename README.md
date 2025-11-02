# stooge

**⚠️ Work in Progress - Early Development**

Network traffic replayer with Lua dissector support - replay PCAP files with timing preservation and protocol analysis.

**Source:** [github.com/deanturpin/stooge](https://github.com/deanturpin/stooge)

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

- Split-screen terminal UI with colour-coded packet display
- Replays network traffic from Wireshark PCAP files
- Preserves original packet timing (configurable speed multiplier)
- Background DNS reverse lookups for hostname resolution
- Lua dissector support (DNS, HTTP) for protocol analysis
- Live capture mode for real-time traffic monitoring
