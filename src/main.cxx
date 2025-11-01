// Network traffic replayer - reads PCAP files and replays timing with DNS
// resolution
#include "dissector.hxx"
#include "dns.hxx"
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <csignal>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <optional>
#include <pcap/pcap.h>
#include <print>
#include <set>
#include <string>
#include <thread>

// Replay speed multiplier - 4x means packets play back 4 times faster than
// captured
constexpr auto SPEEDUP_FACTOR = 4.0;

// Global flag for signal handling
static volatile sig_atomic_t stop_capture = 0;

// Signal handler for graceful shutdown
static void signal_handler(int signum) {
  stop_capture = 1;
}

// Compile-time validation
static_assert(SPEEDUP_FACTOR > 0.0, "Speedup factor must be positive");
static_assert(SPEEDUP_FACTOR <= 1000.0,
              "Speedup factor seems unreasonably high");
static_assert(sizeof(uint16_t) == 2, "Port numbers must be 16-bit");

// Parsed network packet metadata
struct packet_info {
  std::string src_ip;
  std::string dst_ip;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  std::string protocol;
  size_t length = 0;
  const uint8_t *payload = nullptr; // Application-layer payload
  size_t payload_length = 0;

  // Format packet information as human-readable string with hostnames
  std::string describe() const {
    auto src_host = dns::reverse_lookup(src_ip);
    auto dst_host = dns::reverse_lookup(dst_ip);

    // Helper to format IP:port with optional hostname
    auto format_endpoint = [](const std::string &ip, uint16_t port,
                              const std::string &host) {
      if (!host.empty() && host != ip) {
        if (port > 0)
          return std::format("{}:{} ({})", ip, port, host);
        return std::format("{} ({})", ip, host);
      }
      if (port > 0)
        return std::format("{}:{}", ip, port);
      return ip;
    };

    auto src = format_endpoint(src_ip, src_port, src_host);
    auto dst = format_endpoint(dst_ip, dst_port, dst_host);

    return std::format("{} {} → {} ({} bytes)", protocol, src, dst, length);
  }
};

// Parse raw packet data into structured packet_info
// Returns std::nullopt if packet is malformed or not IPv4
std::optional<packet_info> parse_packet(const u_char *packet,
                                        const struct pcap_pkthdr *header) {
  // Verify minimum Ethernet header size
  if (header->caplen < sizeof(struct ether_header))
    return std::nullopt;

  auto eth = reinterpret_cast<const struct ether_header *>(packet);

  // Only process IPv4 packets
  if (ntohs(eth->ether_type) != ETHERTYPE_IP)
    return std::nullopt;

  auto iph =
      reinterpret_cast<const struct ip *>(packet + sizeof(struct ether_header));

  // Verify we have complete IP header
  if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
    return std::nullopt;

  auto info = packet_info{};
  auto src_ip = std::array<char, INET_ADDRSTRLEN>{};
  auto dst_ip = std::array<char, INET_ADDRSTRLEN>{};
  inet_ntop(AF_INET, &(iph->ip_src), src_ip.data(), INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(iph->ip_dst), dst_ip.data(), INET_ADDRSTRLEN);
  info.src_ip = src_ip.data();
  info.dst_ip = dst_ip.data();
  info.length = header->len;

  // Extract TCP port numbers and payload if available
  if (iph->ip_p == IPPROTO_TCP) {
    auto tcph = reinterpret_cast<const struct tcphdr *>(
        packet + sizeof(struct ether_header) + sizeof(struct ip));
    if (header->caplen >= sizeof(struct ether_header) + sizeof(struct ip) +
                              sizeof(struct tcphdr)) {
      info.protocol = "TCP";
      info.src_port = ntohs(tcph->th_sport);
      info.dst_port = ntohs(tcph->th_dport);

      // Calculate TCP header length (data offset is in 32-bit words)
      auto tcp_header_len = tcph->th_off * 4;
      auto payload_offset =
          sizeof(struct ether_header) + sizeof(struct ip) + tcp_header_len;

      if (header->caplen > payload_offset) {
        info.payload = packet + payload_offset;
        info.payload_length = header->caplen - payload_offset;
      }
    }
  } else if (iph->ip_p == IPPROTO_UDP) {
    // Extract UDP port numbers and payload if available
    auto udph = reinterpret_cast<const struct udphdr *>(
        packet + sizeof(struct ether_header) + sizeof(struct ip));
    if (header->caplen >= sizeof(struct ether_header) + sizeof(struct ip) +
                              sizeof(struct udphdr)) {
      info.protocol = "UDP";
      info.src_port = ntohs(udph->uh_sport);
      info.dst_port = ntohs(udph->uh_dport);

      auto payload_offset = sizeof(struct ether_header) + sizeof(struct ip) +
                            sizeof(struct udphdr);

      if (header->caplen > payload_offset) {
        info.payload = packet + payload_offset;
        info.payload_length = header->caplen - payload_offset;
      }
    }
  } else {
    // Other IP protocols (ICMP, etc.)
    info.protocol = "IP";
  }

  return info;
}

// Network endpoint for connection tracking (currently unused)
struct endpoint {
  std::string ip;
  uint16_t port;
  std::string protocol;
  mutable std::string hostname; // Cached hostname, lazy-loaded

  std::string to_string() const {
    if (hostname.empty())
      hostname = dns::reverse_lookup(ip);
    if (!hostname.empty() && hostname != ip)
      return std::format("{}:{} ({}) [{}]", ip, port, protocol, hostname);
    return std::format("{}:{} ({})", ip, port, protocol);
  }

  // Lexicographic ordering for std::set
  bool operator<(const endpoint &other) const {
    if (ip != other.ip)
      return ip < other.ip;
    if (port != other.port)
      return port < other.port;
    return protocol < other.protocol;
  }
};

int main(int argc, char *argv[]) {
  // Install signal handler for Ctrl+C
  std::signal(SIGINT, signal_handler);

  auto errbuf = std::array<char, PCAP_ERRBUF_SIZE>{};
  pcap_t *handle = nullptr;
  auto live_mode = false;

  // Determine mode: live capture or file replay
  if (argc == 1) {
    // Live mode - capture from default interface
    live_mode = true;

    // Find default device
    auto dev = pcap_lookupdev(errbuf.data());
    if (!dev) {
      std::print("Error finding default interface: {}\n", errbuf.data());
      std::print("Try specifying a file: {} <pcap-file>\n", argv[0]);
      return 1;
    }

    // Open live capture
    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf.data());
    if (!handle) {
      std::print("Error opening interface {}: {}\n", dev, errbuf.data());
      std::print("\nLive capture requires elevated privileges.\n");
      std::print("Try one of:\n");
      std::print("  1. Run with sudo: sudo {} {}\n", argv[0],
                 argc > 1 ? argv[1] : "");
      std::print("  2. Grant capabilities: sudo setcap "
                 "cap_net_raw,cap_net_admin=eip {}\n",
                 argv[0]);
      return 1;
    }

    std::print("Live capture on {} (press Ctrl+C to stop)\n\n", dev);
  } else if (argc == 2) {
    // Replay mode - read from file
    auto filename = argv[1];
    handle = pcap_open_offline(filename, errbuf.data());
    if (!handle) {
      std::print("Error opening file {}: {}\n", filename, errbuf.data());
      return 1;
    }

    std::print("Successfully opened PCAP file: {}\n", filename);
    std::print("Replay speed: {}x\n\n", SPEEDUP_FACTOR);
  } else {
    std::print("Usage:\n");
    std::print("  {}              # Live capture mode\n", argv[0]);
    std::print("  {} <pcap-file>  # Replay mode\n", argv[0]);
    return 1;
  }

  // Initialise dissector runtime
  auto dissectors = dissector::runtime{};
  dissectors.load("dissectors/http.lua");
  dissectors.load("dissectors/dns.lua");
  std::print("Loaded dissectors\n\n");

  // Display data link layer information
  auto datalink = pcap_datalink(handle);
  std::print("Data link type: {} ({})\n\n", pcap_datalink_val_to_name(datalink),
             pcap_datalink_val_to_description(datalink));

  // Packet iteration state
  auto header = static_cast<struct pcap_pkthdr *>(nullptr);
  auto packet = static_cast<const u_char *>(nullptr);
  auto packet_count = 0;
  auto start_time = std::optional<std::chrono::steady_clock::time_point>{};
  auto first_packet_time = std::optional<struct timeval>{};

  if (!live_mode)
    std::print("Beginning replay...\n\n");

  // Process packets
  while (!stop_capture && pcap_next_ex(handle, &header, &packet) == 1) {
    packet_count++;

    auto packet_offset = 0.0;

    // Only do timing for replay mode
    if (!live_mode) {
      // Record start time on first packet
      if (!first_packet_time) {
        first_packet_time = header->ts;
        start_time = std::chrono::steady_clock::now();
      }

      // Calculate time offset from first packet
      packet_offset = (header->ts.tv_sec - first_packet_time->tv_sec) +
                      (header->ts.tv_usec - first_packet_time->tv_usec) /
                          1000000.0;

      // Scale the delay and calculate target wake time
      auto scaled_offset =
          std::chrono::duration<double>(packet_offset / SPEEDUP_FACTOR);
      auto target_time =
          *start_time +
          std::chrono::duration_cast<std::chrono::steady_clock::duration>(
              scaled_offset);

      // Sleep until it's time to display this packet
      std::this_thread::sleep_until(target_time);
    }

    // Parse and display packet information
    auto info = parse_packet(packet, header);
    if (info) {
      if (live_mode)
        std::print("[{:6d}] {}\n", packet_count, info->describe());
      else
        std::print("[{:6d}] {:8.3f}s: {}\n", packet_count, packet_offset,
                   info->describe());

      // Try to dissect application-layer protocol
      if (info->payload && info->payload_length > 0) {
        auto dissected =
            dissectors.dissect(info->payload, info->payload_length,
                               info->src_port, info->dst_port, info->protocol);
        if (dissected)
          std::print("         └─ {} {}\n", dissected->protocol,
                     dissected->info);
      }
    }
  }

  if (live_mode)
    std::print("\n\nCapture complete!\n");
  else
    std::print("\n\nReplay complete!\n");
  std::print("Total packets: {}\n", packet_count);

  // Wait for any remaining DNS lookups to complete
  std::print("\nWaiting for DNS resolution to complete...\n");
  dns::wait_for_resolution();
  std::print("DNS resolution complete.\n");

  pcap_close(handle);
  return 0;
}
