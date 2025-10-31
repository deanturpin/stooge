// Network traffic replayer - reads PCAP files and replays timing with DNS
// resolution
#include "dns.hxx"
#include <arpa/inet.h>
#include <array>
#include <chrono>
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

// Replay speed multiplier - 10x means packets play back 10 times faster than
// captured
constexpr double SPEEDUP_FACTOR = 10.0;

// Compile-time validation
static_assert(SPEEDUP_FACTOR > 0.0, "Speedup factor must be positive");
static_assert(SPEEDUP_FACTOR <= 1000.0,
              "Speedup factor seems unreasonably high");
static_assert(sizeof(uint16_t) == 2, "Port numbers must be 16-bit");

// Parsed network packet metadata
struct PacketInfo {
  std::string src_ip;
  std::string dst_ip;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  std::string protocol;
  size_t length = 0;

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

// Parse raw packet data into structured PacketInfo
// Returns std::nullopt if packet is malformed or not IPv4
std::optional<PacketInfo> parse_packet(const u_char *packet,
                                       const struct pcap_pkthdr *header) {
  // Verify minimum Ethernet header size
  if (header->caplen < sizeof(struct ether_header))
    return std::nullopt;

  auto eth = reinterpret_cast<const struct ether_header *>(packet);

  // Only process IPv4 packets
  if (ntohs(eth->ether_type) != ETHERTYPE_IP)
    return std::nullopt;

  auto iph = reinterpret_cast<const struct ip *>(
      packet + sizeof(struct ether_header));

  // Verify we have complete IP header
  if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
    return std::nullopt;

  auto info = PacketInfo{};
  auto src_ip = std::array<char, INET_ADDRSTRLEN>{};
  auto dst_ip = std::array<char, INET_ADDRSTRLEN>{};
  inet_ntop(AF_INET, &(iph->ip_src), src_ip.data(), INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(iph->ip_dst), dst_ip.data(), INET_ADDRSTRLEN);
  info.src_ip = src_ip.data();
  info.dst_ip = dst_ip.data();
  info.length = header->len;

  // Extract TCP port numbers if available
  if (iph->ip_p == IPPROTO_TCP) {
    auto tcph = reinterpret_cast<const struct tcphdr *>(
        packet + sizeof(struct ether_header) + sizeof(struct ip));
    if (header->caplen >= sizeof(struct ether_header) + sizeof(struct ip) +
                              sizeof(struct tcphdr)) {
      info.protocol = "TCP";
      info.src_port = ntohs(tcph->th_sport);
      info.dst_port = ntohs(tcph->th_dport);
    }
  } else if (iph->ip_p == IPPROTO_UDP) {
    // Extract UDP port numbers if available
    auto udph = reinterpret_cast<const struct udphdr *>(
        packet + sizeof(struct ether_header) + sizeof(struct ip));
    if (header->caplen >= sizeof(struct ether_header) + sizeof(struct ip) +
                              sizeof(struct udphdr)) {
      info.protocol = "UDP";
      info.src_port = ntohs(udph->uh_sport);
      info.dst_port = ntohs(udph->uh_dport);
    }
  } else {
    // Other IP protocols (ICMP, etc.)
    info.protocol = "IP";
  }

  return info;
}

// Network endpoint for connection tracking (currently unused)
struct Endpoint {
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
  bool operator<(const Endpoint &other) const {
    if (ip != other.ip)
      return ip < other.ip;
    if (port != other.port)
      return port < other.port;
    return protocol < other.protocol;
  }
};

int main(int argc, char *argv[]) {
  // Validate command line arguments
  if (argc != 2) {
    std::print("Usage: {} <pcap-file>\n", argv[0]);
    return 1;
  }

  auto filename = argv[1];
  auto errbuf = std::array<char, PCAP_ERRBUF_SIZE>{};

  // Open PCAP file for offline analysis
  auto handle = pcap_open_offline(filename, errbuf.data());
  if (!handle) {
    std::print("Error opening file {}: {}\n", filename, errbuf.data());
    return 1;
  }

  std::print("Successfully opened PCAP file: {}\n", filename);
  std::print("Replay speed: {}x\n\n", SPEEDUP_FACTOR);

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

  std::print("Beginning replay...\n\n");

  // Process packets, honouring original timing scaled by SPEEDUP_FACTOR
  while (pcap_next_ex(handle, &header, &packet) == 1) {
    packet_count++;

    // Record start time on first packet
    if (!first_packet_time) {
      first_packet_time = header->ts;
      start_time = std::chrono::steady_clock::now();
    }

    // Calculate time offset from first packet
    auto packet_offset =
        (header->ts.tv_sec - first_packet_time->tv_sec) +
        (header->ts.tv_usec - first_packet_time->tv_usec) / 1000000.0;

    // Scale the delay and calculate target wake time
    auto scaled_offset =
        std::chrono::duration<double>(packet_offset / SPEEDUP_FACTOR);
    auto target_time =
        *start_time +
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            scaled_offset);

    // Sleep until it's time to display this packet
    std::this_thread::sleep_until(target_time);

    // Parse and display packet information
    auto info = parse_packet(packet, header);
    if (info)
      std::print("[{:6d}] {:8.3f}s: {}\n", packet_count, packet_offset,
                 info->describe());
  }

  std::print("\n\nReplay complete!\n");
  std::print("Total packets: {}\n", packet_count);

  pcap_close(handle);
  return 0;
}
