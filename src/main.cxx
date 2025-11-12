// Network traffic replayer - reads PCAP files and replays timing with DNS
// resolution
//
// Threading Architecture (4 threads total):
//
// 1. Main Thread (packet processing)
//    - Reads packets from PCAP file or live capture using libpcap
//    - Parses packet headers (Ethernet, IP, TCP/UDP)
//    - Extracts endpoint information (IP, port, protocol, MAC, vendor)
//    - Updates data_store with packet and endpoint information
//    - Respects original packet timing for realistic replay
//    - Notifies DNS thread when new endpoints are added
//
// 2. DNS Resolver Thread (background hostname resolution)
//    - Waits for notification of new endpoints (or 5s timeout)
//    - Scans data_store endpoint map for unresolved IPs
//    - Performs reverse DNS lookups with 2-second timeout per IP
//    - Updates all endpoints with resolved hostnames (or IP if failed)
//    - Tracks resolved IPs to prevent duplicate lookups
//    - Runs continuously until stop_resolver() is called
//
// 3. TUI Render Thread (terminal interface)
//    - Manages FTXUI screen and component lifecycle
//    - Renders endpoint list (left pane) and packet list (right pane)
//    - Handles keyboard shortcuts (q/Esc=quit, p=pause, h=help)
//    - Reads from data_store (thread-safe with mutexes)
//    - Displays live capture vs PCAP replay mode indicator
//    - Shows packet timestamp and total packet count
//
// 4. TUI Refresh Thread (periodic screen updates)
//    - Wakes up every 100ms to trigger screen refresh
//    - Posts custom event to FTXUI screen to redraw
//    - Only refreshes when not paused
//    - Ensures UI updates smoothly during packet processing
//
// Thread Safety:
// - data_store uses std::mutex with std::scoped_lock for all operations
// - DNS resolver thread safely reads and writes data_store
// - TUI threads safely read data_store for rendering
// - Signal handler safely stops TUI renderer
//
#include "dissector.hxx"
#include "dns.hxx"
#include "oui.hxx"
#include "tui.hxx"
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <csignal>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <optional>
#include <pcap/pcap.h>
#include <print>
#include <string>
#include <thread>
#include <unistd.h>

// Replay speed multiplier - 4x means packets play back 4 times faster than
// captured
constexpr auto SPEEDUP_FACTOR = 1.0;

// Global flag for signal handling
static volatile sig_atomic_t stop_capture = 0;
static std::shared_ptr<tui::renderer> global_renderer{nullptr};
static std::mutex global_renderer_mutex;

// Signal handler for graceful shutdown
static void signal_handler(int signum) {
  stop_capture = 1;
  auto lock = std::scoped_lock{global_renderer_mutex};
  if (global_renderer != nullptr)
    global_renderer->stop();
}

// Compile-time validation
static_assert(SPEEDUP_FACTOR > 0.0, "Speedup factor must be positive");
static_assert(SPEEDUP_FACTOR <= 1000.0,
              "Speedup factor seems unreasonably high");
static_assert(SPEEDUP_FACTOR >= 0.1, "Speedup factor too slow (< 0.1x)");
static_assert(SPEEDUP_FACTOR <= 100.0, "Speedup factor too fast (> 100x)");
static_assert(sizeof(uint16_t) == 2, "Port numbers must be 16-bit");
static_assert(sizeof(uint8_t) == 1, "Byte must be 8 bits");
static_assert(INET_ADDRSTRLEN >= 16,
              "IPv4 string buffer must fit xxx.xxx.xxx.xxx");

namespace {
// Constexpr protocol validation helpers
constexpr bool is_tcp_protocol(int protocol) { return protocol == IPPROTO_TCP; }

constexpr bool is_udp_protocol(int protocol) { return protocol == IPPROTO_UDP; }

constexpr bool is_known_ip_protocol(int protocol) {
  return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP ||
         protocol == IPPROTO_ICMP;
}

// Constexpr port validation helpers
constexpr bool is_valid_port(uint16_t port) {
  return port > 0; // Port 0 is reserved
}

constexpr bool is_well_known_port(uint16_t port) {
  return port > 0 && port < 1024;
}

constexpr bool is_ephemeral_port(uint16_t port) {
  return port >= 49152 && port <= 65535;
}

// Compile-time unit tests for protocol and port helpers
static_assert(is_tcp_protocol(IPPROTO_TCP), "TCP protocol check failed");
static_assert(is_udp_protocol(IPPROTO_UDP), "UDP protocol check failed");
static_assert(!is_tcp_protocol(IPPROTO_UDP), "TCP should not match UDP");
static_assert(is_known_ip_protocol(IPPROTO_TCP), "TCP is known protocol");
static_assert(is_known_ip_protocol(IPPROTO_UDP), "UDP is known protocol");

static_assert(is_well_known_port(80), "HTTP is well-known port");
static_assert(is_well_known_port(443), "HTTPS is well-known port");
static_assert(!is_well_known_port(8080), "8080 is not well-known");
static_assert(is_ephemeral_port(50000), "50000 is ephemeral");
static_assert(!is_ephemeral_port(80), "80 is not ephemeral");
static_assert(is_valid_port(80), "80 is valid port");
static_assert(!is_valid_port(0), "0 is not valid port");
} // namespace

// Map common port numbers to protocol/service names
std::string port_to_service(uint16_t port) {
  // Use system service database (/etc/services)
  // Try TCP
  if (auto *serv = getservbyport(htons(port), "tcp"); serv != nullptr)
    return serv->s_name;

  // Try UDP
  if (auto *serv = getservbyport(htons(port), "udp"); serv != nullptr)
    return serv->s_name;

  return {};
}

// Parsed network packet metadata
struct packet_info {
  std::string src_ip_;
  std::string dst_ip_;
  std::array<uint8_t, 6> src_mac_{};
  std::array<uint8_t, 6> dst_mac_{};
  uint16_t src_port_ = 0;
  uint16_t dst_port_ = 0;
  std::string protocol_;
  size_t length_ = 0uz;
  const uint8_t *payload_ = nullptr; // Application-layer payload
  size_t payload_length_ = 0uz;
};

// Helper: Parse IPv4 packet
std::optional<packet_info> parse_ipv4(const u_char *packet,
                                      const struct pcap_pkthdr *header,
                                      const struct ether_header *eth) {
  auto info = packet_info{};

  // Extract MAC addresses
  std::memcpy(info.src_mac_.data(), eth->ether_shost, 6);
  std::memcpy(info.dst_mac_.data(), eth->ether_dhost, 6);

  auto iph =
      reinterpret_cast<const struct ip *>(packet + sizeof(struct ether_header));

  // Verify we have complete IP header
  if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
    return std::nullopt;

  auto src_ip = std::array<char, INET_ADDRSTRLEN>{};
  auto dst_ip = std::array<char, INET_ADDRSTRLEN>{};
  inet_ntop(AF_INET, &(iph->ip_src), src_ip.data(), INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(iph->ip_dst), dst_ip.data(), INET_ADDRSTRLEN);
  info.src_ip_ = src_ip.data();
  info.dst_ip_ = dst_ip.data();
  info.length_ = header->len;

  // Extract TCP port numbers and payload if available
  if (iph->ip_p == IPPROTO_TCP) {
    auto ip_header_len = iph->ip_hl * 4; // IP header length in bytes
    auto tcph = reinterpret_cast<const struct tcphdr *>(
        packet + sizeof(struct ether_header) + ip_header_len);
    if (header->caplen >=
        sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) {
      info.protocol_ = "TCP";
      info.src_port_ = ntohs(tcph->th_sport);
      info.dst_port_ = ntohs(tcph->th_dport);

      // Calculate TCP header length (data offset is in 32-bit words)
      auto tcp_header_len = tcph->th_off * 4;
      auto payload_offset =
          sizeof(struct ether_header) + sizeof(struct ip) + tcp_header_len;

      if (header->caplen > payload_offset) {
        info.payload_ = packet + payload_offset;
        info.payload_length_ = header->caplen - payload_offset;
      }
    }
  } else if (iph->ip_p == IPPROTO_UDP) {
    // Extract UDP port numbers and payload if available
    auto ip_header_len = iph->ip_hl * 4; // IP header length in bytes
    auto udph = reinterpret_cast<const struct udphdr *>(
        packet + sizeof(struct ether_header) + ip_header_len);
    if (header->caplen >=
        sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr)) {
      info.protocol_ = "UDP";
      info.src_port_ = ntohs(udph->uh_sport);
      info.dst_port_ = ntohs(udph->uh_dport);

      auto payload_offset =
          sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);

      if (header->caplen > payload_offset) {
        info.payload_ = packet + payload_offset;
        info.payload_length_ = header->caplen - payload_offset;
      }
    }
  } else {
    // Other IP protocols (ICMP, etc.)
    info.protocol_ = "IP";
  }

  return info;
}

// Helper: Parse IPv6 packet
std::optional<packet_info> parse_ipv6(const u_char *packet,
                                      const struct pcap_pkthdr *header,
                                      const struct ether_header *eth) {
  auto info = packet_info{};

  // Extract MAC addresses
  std::memcpy(info.src_mac_.data(), eth->ether_shost, 6);
  std::memcpy(info.dst_mac_.data(), eth->ether_dhost, 6);

  // IPv6 header is 40 bytes minimum
  constexpr auto ipv6_header_size = 40uz;
  if (header->caplen < sizeof(struct ether_header) + ipv6_header_size)
    return std::nullopt;

  auto ipv6_start = packet + sizeof(struct ether_header);

  // Parse IPv6 addresses (128-bit each, at offset 8 and 24)
  auto src_ip = std::array<char, INET6_ADDRSTRLEN>{};
  auto dst_ip = std::array<char, INET6_ADDRSTRLEN>{};
  inet_ntop(AF_INET6, ipv6_start + 8, src_ip.data(), INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, ipv6_start + 24, dst_ip.data(), INET6_ADDRSTRLEN);
  info.src_ip_ = src_ip.data();
  info.dst_ip_ = dst_ip.data();
  info.length_ = header->len;

  // Next header field (at offset 6)
  auto next_header = ipv6_start[6];

  // Extract TCP/UDP ports if present
  auto transport_start = ipv6_start + ipv6_header_size;

  if (next_header == IPPROTO_TCP) {
    if (header->caplen >= sizeof(struct ether_header) + ipv6_header_size +
                              sizeof(struct tcphdr)) {
      auto tcph = reinterpret_cast<const struct tcphdr *>(transport_start);
      info.protocol_ = "TCP";
      info.src_port_ = ntohs(tcph->th_sport);
      info.dst_port_ = ntohs(tcph->th_dport);

      auto tcp_header_len = tcph->th_off * 4;
      auto payload_offset =
          sizeof(struct ether_header) + ipv6_header_size + tcp_header_len;

      if (header->caplen > payload_offset) {
        info.payload_ = packet + payload_offset;
        info.payload_length_ = header->caplen - payload_offset;
      }
    }
  } else if (next_header == IPPROTO_UDP) {
    if (header->caplen >= sizeof(struct ether_header) + ipv6_header_size +
                              sizeof(struct udphdr)) {
      auto udph = reinterpret_cast<const struct udphdr *>(transport_start);
      info.protocol_ = "UDP";
      info.src_port_ = ntohs(udph->uh_sport);
      info.dst_port_ = ntohs(udph->uh_dport);

      auto payload_offset = sizeof(struct ether_header) + ipv6_header_size +
                            sizeof(struct udphdr);

      if (header->caplen > payload_offset) {
        info.payload_ = packet + payload_offset;
        info.payload_length_ = header->caplen - payload_offset;
      }
    }
  } else {
    // Other IPv6 protocols (ICMPv6, etc.)
    info.protocol_ = "IPv6";
  }

  return info;
}

// Helper: Parse ARP packet
std::optional<packet_info> parse_arp(const u_char *packet,
                                     const struct pcap_pkthdr *header,
                                     const struct ether_header *eth) {
  auto info = packet_info{};

  // Extract MAC addresses
  std::memcpy(info.src_mac_.data(), eth->ether_shost, 6);
  std::memcpy(info.dst_mac_.data(), eth->ether_dhost, 6);

  // ARP packet structure: 28 bytes minimum
  // Hardware type (2), Protocol type (2), HW len (1), Proto len (1), Operation
  // (2) Sender HW addr (6), Sender Proto addr (4), Target HW addr (6), Target
  // Proto addr (4)
  constexpr auto arp_header_size = 28uz;
  if (header->caplen < sizeof(struct ether_header) + arp_header_size)
    return std::nullopt;

  auto arp_start = packet + sizeof(struct ether_header);

  // Parse sender and target IPv4 addresses
  auto sender_ip = std::array<char, INET_ADDRSTRLEN>{};
  auto target_ip = std::array<char, INET_ADDRSTRLEN>{};
  inet_ntop(AF_INET, arp_start + 14, sender_ip.data(),
            INET_ADDRSTRLEN); // Sender IP at offset 14
  inet_ntop(AF_INET, arp_start + 24, target_ip.data(),
            INET_ADDRSTRLEN); // Target IP at offset 24

  info.src_ip_ = sender_ip.data();
  info.dst_ip_ = target_ip.data();
  info.protocol_ = "ARP";
  info.length_ = header->len;

  return info;
}

// Helper: Parse unknown EtherType packets
std::optional<packet_info> parse_generic(const u_char *packet,
                                         const struct pcap_pkthdr *header,
                                         const struct ether_header *eth) {
  auto info = packet_info{};

  // Extract MAC addresses
  std::memcpy(info.src_mac_.data(), eth->ether_shost, 6);
  std::memcpy(info.dst_mac_.data(), eth->ether_dhost, 6);

  // Show EtherType as protocol
  auto ether_type = ntohs(eth->ether_type);
  info.protocol_ = std::format("0x{:04X}", ether_type);

  // Use MAC addresses as endpoints
  info.src_ip_ =
      std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", info.src_mac_[0],
                  info.src_mac_[1], info.src_mac_[2], info.src_mac_[3],
                  info.src_mac_[4], info.src_mac_[5]);
  info.dst_ip_ =
      std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", info.dst_mac_[0],
                  info.dst_mac_[1], info.dst_mac_[2], info.dst_mac_[3],
                  info.dst_mac_[4], info.dst_mac_[5]);
  info.length_ = header->len;

  return info;
}

// Parse raw packet data into structured packet_info
// Returns packet_info for all EtherTypes (IPv4, IPv6, ARP, and unknown)
std::optional<packet_info> parse_packet(const u_char *packet,
                                        const struct pcap_pkthdr *header,
                                        bool is_sll = false) {
  // Linux SLL (cooked) capture has 16-byte header instead of 14-byte Ethernet
  auto header_size = is_sll ? 16uz : sizeof(struct ether_header);

  if (header->caplen < header_size)
    return std::nullopt;

  auto ether_type = uint16_t{};
  auto fake_eth = ether_header{};
  const struct ether_header *eth_ptr = nullptr;

  if (is_sll) {
    // SLL header: protocol type is at offset 14-15 (2 bytes, big-endian)
    ether_type = (packet[14] << 8) | packet[15];

    // Extract MAC address from SLL (source MAC at offset 6-11, 6 bytes)
    std::memcpy(fake_eth.ether_shost, packet + 6, 6);
    // SLL doesn't have dest MAC, set to zero
    std::memset(fake_eth.ether_dhost, 0, 6);
    fake_eth.ether_type = htons(ether_type);

    // Adjust packet pointer to skip SLL header (16 bytes) as if it were
    // Ethernet (14 bytes) so parsers see payload at +14
    packet = packet + 2;
    eth_ptr = &fake_eth;
  } else {
    eth_ptr = reinterpret_cast<const struct ether_header *>(packet);
    ether_type = ntohs(eth_ptr->ether_type);
  }

  // Route to appropriate parser based on EtherType
  switch (ether_type) {
  case ETHERTYPE_IP: // 0x0800 - IPv4
    return parse_ipv4(packet, header, eth_ptr);

  case 0x86DD: // IPv6
    return parse_ipv6(packet, header, eth_ptr);

  case 0x0806: // ARP
    return parse_arp(packet, header, eth_ptr);

  default: // Unknown EtherType
    return parse_generic(packet, header, eth_ptr);
  }
}

int main(int argc, char *argv[]) {
  // Disable stdout buffering for real-time output in Docker
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  // Install signal handlers for graceful shutdown
  std::signal(SIGINT, signal_handler);  // Ctrl+C
  std::signal(SIGTERM, signal_handler); // docker stop/kill

  // Custom deleter for pcap_t RAII wrapper
  auto pcap_deleter = [](pcap_t *p) {
    if (p != nullptr)
      pcap_close(p);
  };

  auto errbuf = std::array<char, PCAP_ERRBUF_SIZE>{};
  auto handle =
      std::unique_ptr<pcap_t, decltype(pcap_deleter)>{nullptr, pcap_deleter};
  auto live_mode = false;
  // Auto-detect TTY: enable TUI only if stdin is a terminal
  auto use_tui = isatty(STDIN_FILENO) != 0;

  // Parse command-line arguments
  auto pcap_file = std::string{};
  for (auto i = 1; i < argc; ++i) {
    auto arg = std::string{argv[i]};
    if (arg == "--no-tui" || arg == "-n")
      use_tui = false;
    else if (arg == "--help" || arg == "-h") {
      std::print("Usage:\n");
      std::print("  {}              # Live capture mode\n", argv[0]);
      std::print("  {} <pcap-file>  # Replay mode\n", argv[0]);
      std::print("\nOptions:\n");
      std::print("  --no-tui, -n    Disable TUI (for non-interactive "
                 "environments)\n");
      std::print("  --help, -h      Show this help message\n");
      return 0;
    } else if (pcap_file.empty())
      pcap_file = arg;
  }

  // Determine mode: live capture or file replay
  if (pcap_file.empty()) {
    // Live mode - capture from default interface
    live_mode = true;

    // Use "any" pseudo-device to capture from all interfaces
    auto dev_name = std::string{"any"};

    // Open live capture
    handle.reset(
        pcap_open_live(dev_name.c_str(), 65535, 1, 1000, errbuf.data()));

    if (!handle) {
      std::print("Error opening interface {}: {}\n", dev_name, errbuf.data());
      std::print("\nLive capture failed. Possible causes:\n");
      std::print("  1. Insufficient privileges (need root/sudo)\n");
      std::print("  2. Running in Docker without host network access\n");
      std::print("  3. Interface not available in current network namespace\n");
      std::print("\nSolutions:\n");
      std::print("  - Native: sudo {} (requires elevated privileges)\n",
                 argv[0]);
      std::print("  - Docker: docker run --network=host --cap-add=NET_RAW -it "
                 "deanturpin/stooge\n");
      std::print("  - Recommended: Use file replay mode with a PCAP file\n");
      std::print("    Example: {} samples/traffic.pcapng\n", argv[0]);
      return 1;
    }

    if (dev_name == "any")
      std::print("Live capture on all interfaces (device: {})\n", dev_name);
    else
      std::print("Live capture on interface: {}\n", dev_name);
    std::print("Press Ctrl+C to stop\n\n");
  } else {
    // Replay mode - read from file
    handle.reset(pcap_open_offline(pcap_file.c_str(), errbuf.data()));
    if (!handle) {
      std::print("Error opening file {}: {}\n", pcap_file, errbuf.data());
      return 1;
    }

    std::print("Successfully opened PCAP file: {}\n", pcap_file);
    std::print("Replay speed: {}x\n", SPEEDUP_FACTOR);
    if (!use_tui)
      std::print("TUI disabled (text mode)\n");
    std::print("\n");
  }

  // Check data link type
  auto datalink = pcap_datalink(handle.get());
  auto is_sll = datalink == 113; // DLT_LINUX_SLL
  if (is_sll)
    std::print("Note: Using Linux cooked capture (SLL) format\n\n");

  // Initialise dissector runtime
  auto dissectors = dissector::runtime{};
  dissectors.load("dissectors/http.lua");
  dissectors.load("dissectors/dns.lua");

  // Initialise TUI data store (but don't start renderer yet)
  auto tui_store = std::make_shared<tui::data_store>();
  tui_store->set_capture_mode(live_mode); // Set mode before packet processing
  std::shared_ptr<tui::renderer> tui_renderer;

  // Start DNS resolver thread to work on endpoint map (with 2s timeout)
  dns::start_resolver(tui_store);

  // Packet iteration state (shared between TUI and non-TUI modes)
  auto header = static_cast<struct pcap_pkthdr *>(nullptr);
  auto packet = static_cast<const u_char *>(nullptr);
  auto packet_count = 0uz;
  auto start_time = std::optional<std::chrono::steady_clock::time_point>{};
  auto first_packet_time = std::optional<struct timeval>{};

  if (use_tui) {
    tui_renderer = std::make_shared<tui::renderer>(tui_store);
    {
      auto lock = std::scoped_lock{global_renderer_mutex};
      global_renderer = tui_renderer;
    }

    // Set quit callback to stop packet capture when user presses q/Esc
    tui_renderer->set_quit_callback([]() { stop_capture = 1; });

    // Set packet processor callback - this runs in background thread
    tui_renderer->set_packet_processor([&](std::stop_token st) {
      // Packet processing loop (runs in background thread)
      auto capture_result = 0;
      try {
        tui_store->set_status("DEBUG: Starting packet processing loop");

        while (!stop_capture && !st.stop_requested() &&
               (capture_result =
                    pcap_next_ex(handle.get(), &header, &packet)) >= 0) {
          if (capture_result == 0)
            continue; // Timeout, try again
          if (capture_result == -2)
            break; // End of file

          packet_count++;

          if (packet_count % 100 == 0)
            tui_store->set_status(
                std::format("Processing packet {}", packet_count));

          auto packet_offset = 0.0;

          // Timing logic for replay vs live mode
          if (!live_mode) {
            if (!first_packet_time) {
              first_packet_time = header->ts;
              start_time = std::chrono::steady_clock::now();
            }

            packet_offset =
                (header->ts.tv_sec - first_packet_time->tv_sec) +
                (header->ts.tv_usec - first_packet_time->tv_usec) / 1000000.0;

            auto scaled_offset =
                std::chrono::duration<double>(packet_offset / SPEEDUP_FACTOR);
            auto target_time =
                *start_time +
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    scaled_offset);

            std::this_thread::sleep_until(target_time);
          } else {
            if (!start_time)
              start_time = std::chrono::steady_clock::now();

            auto now = std::chrono::steady_clock::now();
            auto elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - *start_time)
                    .count();
            packet_offset = elapsed / 1000.0;
          }

          if (start_time)
            tui_store->set_capture_time(packet_offset);

          // Store actual wall-clock timestamp from PCAP header
          tui_store->set_last_packet_timestamp(header->ts.tv_sec,
                                               header->ts.tv_usec);

          auto info = parse_packet(packet, header, is_sll);
          if (info) {
            auto src_vendor = oui::lookup_vendor(info->src_mac_);
            auto dst_vendor = oui::lookup_vendor(info->dst_mac_);

            auto src_mac_str = std::format(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", info->src_mac_[0],
                info->src_mac_[1], info->src_mac_[2], info->src_mac_[3],
                info->src_mac_[4], info->src_mac_[5]);
            auto dst_mac_str = std::format(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", info->dst_mac_[0],
                info->dst_mac_[1], info->dst_mac_[2], info->dst_mac_[3],
                info->dst_mac_[4], info->dst_mac_[5]);

            // Only add endpoints for known protocols (IPv4, IPv6, ARP)
            // Skip generic unknown EtherType packets (protocol starts with
            // "0x")
            if (!info->protocol_.starts_with("0x")) {
              tui_store->add_endpoint(info->src_ip_, info->src_port_,
                                      info->protocol_, "", src_vendor,
                                      src_mac_str);
              tui_store->add_endpoint(info->dst_ip_, info->dst_port_,
                                      info->protocol_, "", dst_vendor,
                                      dst_mac_str);

              dns::notify_new_work();
            }

            auto format_endpoint = [](std::string_view ip, uint16_t port) {
              if (port == 0)
                return std::string{ip};

              auto service = port_to_service(port);
              auto port_display = service.empty()
                                      ? std::format("{}", port)
                                      : std::format("{}/{}", port, service);

              return std::format("{}:{}", ip, port_display);
            };

            auto pkt = tui::packet_entry{};
            pkt.number_ = packet_count;
            pkt.timestamp_ = packet_offset;
            pkt.protocol_ = info->protocol_;
            pkt.src_ = format_endpoint(info->src_ip_, info->src_port_);
            pkt.dst_ = format_endpoint(info->dst_ip_, info->dst_port_);
            pkt.bytes_ = info->length_;

            if (info->payload_ && info->payload_length_ > 0) {
              auto dissected = dissectors.dissect(
                  info->payload_, info->payload_length_, info->src_port_,
                  info->dst_port_, info->protocol_);
              if (dissected)
                pkt.dissection_ = std::format("{} {}", dissected->protocol_,
                                              dissected->info_);
            }

            if (packet_count % 500 == 0)
              tui_store->set_status(std::format("Last packet: {} {} → {}",
                                                pkt.protocol_, pkt.src_,
                                                pkt.dst_));

            tui_store->add_packet(pkt);
          }
        }
      } catch (const std::exception &e) {
        std::print(stderr, "Packet processing error: {}\n", e.what());
      }
    });

    // Start TUI renderer - this will take over the screen
    // The packet processor will run in background thread
    try {
      tui_renderer->start();
    } catch (const std::exception &e) {
      std::print("Error starting TUI: {}\n", e.what());
      std::print("\nTUI requires a proper terminal.\n");
      std::print("Solutions:\n");
      std::print("  - Run with 'docker run -it' (interactive + TTY)\n");
      std::print("  - Use --no-tui flag for non-interactive environments\n");
      std::print("    Example: {} --no-tui {}\n", argv[0],
                 pcap_file.empty() ? "<pcap-file>" : pcap_file);
      return 1;
    }
  }

  // Process packets with error handling (non-TUI mode only)
  // In TUI mode, packet processing happens in background thread
  auto capture_result = 0;

  if (!use_tui) {
    try {
      // Check if handle is valid before processing packets
      if (handle == nullptr) {
        std::print("Error: Invalid pcap handle\n");
        return 1;
      }

      while (!stop_capture && (capture_result = pcap_next_ex(
                                   handle.get(), &header, &packet)) >= 0) {
        // Handle pcap_next_ex return values:
        // 1 = packet read successfully
        // 0 = timeout elapsed (live capture)
        // -1 = error
        // -2 = end of file (savefile)
        if (capture_result == 0)
          continue; // Timeout, try again

        if (capture_result == -2)
          break; // End of file (normal for replay mode)

        packet_count++;

        // Timing for replay mode (honour original packet timing)
        if (!live_mode) {
          if (!first_packet_time) {
            first_packet_time = header->ts;
            start_time = std::chrono::steady_clock::now();
          }

          auto packet_offset =
              (header->ts.tv_sec - first_packet_time->tv_sec) +
              (header->ts.tv_usec - first_packet_time->tv_usec) / 1000000.0;

          auto scaled_offset =
              std::chrono::duration<double>(packet_offset / SPEEDUP_FACTOR);
          auto target_time =
              *start_time +
              std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                  scaled_offset);

          std::this_thread::sleep_until(target_time);
        }

        // Parse and display packet information (non-TUI text mode)
        auto info = parse_packet(packet, header);
        if (info) {
          auto format_endpoint = [](std::string_view ip, uint16_t port) {
            if (port == 0)
              return std::string{ip};

            auto service = port_to_service(port);
            auto port_display = service.empty()
                                    ? std::format("{}", port)
                                    : std::format("{}/{}", port, service);

            return std::format("{}:{}", ip, port_display);
          };

          auto src = format_endpoint(info->src_ip_, info->src_port_);
          auto dst = format_endpoint(info->dst_ip_, info->dst_port_);

          std::print("[{}] {} {} → {} ({} bytes)", packet_count,
                     info->protocol_, src, dst, info->length_);

          // Try to dissect application-layer protocol
          if (info->payload_ && info->payload_length_ > 0) {
            auto dissected = dissectors.dissect(
                info->payload_, info->payload_length_, info->src_port_,
                info->dst_port_, info->protocol_);
            if (dissected)
              std::print(" | {} {}", dissected->protocol_, dissected->info_);
          }

          std::print("\n");
        }
      }
    } catch (const std::exception &e) {
      std::print("\n\nFatal error during packet processing at packet {}: {}\n",
                 packet_count, e.what());
      dns::stop_resolver();
      return 1;
    } catch (...) {
      std::print(
          "\n\nFatal error during packet processing (unknown exception)\n");
      dns::stop_resolver();
      return 1;
    }
  }

  // Stop TUI renderer gracefully
  if (use_tui && tui_renderer) {
    try {
      tui_renderer->stop();
    } catch (const std::exception &e) {
      // TUI cleanup failed, but continue shutdown
      std::print("Warning: TUI cleanup error: {}\n", e.what());
    }
  }
  {
    auto lock = std::scoped_lock{global_renderer_mutex};
    global_renderer.reset();
  }

  // Check if capture ended due to error
  if (capture_result == -1) {
    std::print("\n\nCapture error: {}\n", pcap_geterr(handle.get()));
    std::print("This can happen when:\n");
    std::print("  - Network interface goes down\n");
    std::print("  - Running in restricted Docker environment\n");
    std::print("  - Insufficient permissions during capture\n");
  } else if (stop_capture) {
    std::print("\n\nCapture stopped by user (Ctrl+C)\n");
  } else {
    if (live_mode)
      std::print("\n\nCapture complete!\n");
    else
      std::print("\n\nReplay complete!\n");
  }

  std::print("Total packets processed: {}\n", packet_count);

  // Stop DNS resolver thread
  dns::stop_resolver();

  // pcap handle will be automatically closed by unique_ptr destructor
  return capture_result == -1 ? 1 : 0;
}
