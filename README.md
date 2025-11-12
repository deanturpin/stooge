# stooge

Network traffic replayer with Lua dissector support: replay PCAP files with timing preservation and protocol analysis. Also supports live capture mode.

**Source:** [github.com/deanturpin/stooge](https://github.com/deanturpin/stooge)

## Quick Start

Run with a PCAP file (requires `-it` for interactive TUI):

```bash
docker run --rm -it -v $(pwd):/data deanturpin/stooge /data/capture.pcapng
```

Live capture mode (requires elevated privileges):

```bash
docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW --net=host deanturpin/stooge
```

## Features

- Split-screen terminal UI with colour-coded packet display
- Replays network traffic from Wireshark PCAP files
- Preserves original packet timing during replay
- Background DNS reverse lookups for hostname resolution
- Lua dissector support (DNS, HTTP) for protocol analysis
- Live capture mode for real-time traffic monitoring

## Colour Coding

The TUI uses different colours to distinguish protocol types and IP versions:

**IPv4 Packets and Endpoints:**
- TCP: Green
- UDP: Yellow
- Other protocols: White

**IPv6 Packets and Endpoints:**
- TCP: Light Green
- UDP: Light Yellow
- Other protocols: Light Cyan

**Known Network Vendors:**
- Always displayed in Cyan (regardless of IP version)

**Note:** Interactive TUI mode requires Docker `-it` flags. Without these flags, the tool automatically falls back to text-only output mode.
