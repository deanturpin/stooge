// Network traffic replayer - reads PCAP files and replays timing with DNS
// resolution
#include "dissector.hxx"
#include "dns.hxx"
#include "oui.hxx"
#include "tui.hxx"
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <csignal>
#include <cstring>
#include <map>
#include <memory>
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
constexpr auto SPEEDUP_FACTOR = 1.0;

// Global flag for signal handling
static volatile sig_atomic_t stop_capture = 0;
static tui::renderer *global_renderer = nullptr;

// Signal handler for graceful shutdown
static void signal_handler(int signum) {
  stop_capture = 1;
  if (global_renderer)
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
  std::string src_ip;
  std::string dst_ip;
  std::array<uint8_t, 6> src_mac{};
  std::array<uint8_t, 6> dst_mac{};
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  std::string protocol;
  size_t length = 0uz;
  const uint8_t *payload = nullptr; // Application-layer payload
  size_t payload_length = 0uz;

  // Format packet information as human-readable string with hostnames
  std::string describe() const {
    auto src_host = dns::reverse_lookup(src_ip);
    auto dst_host = dns::reverse_lookup(dst_ip);

    // Helper to format IP:port with optional hostname and service
    auto format_endpoint = [](std::string_view ip, uint16_t port,
                              std::string_view host) {
      if (port == 0)
        return host.empty() || host == ip ? std::string{ip}
                                          : std::format("{} ({})", ip, host);

      auto service = port_to_service(port);

      // Build port display: "80/HTTP" or just "80"
      auto port_display = service.empty() ? std::format("{}", port)
                                          : std::format("{}/{}", port, service);

      return !host.empty() && host != ip
                 ? std::format("{}:{} ({})", ip, port_display, host)
                 : std::format("{}:{}", ip, port_display);
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

  auto info = packet_info{};

  // Extract MAC addresses
  std::memcpy(info.src_mac.data(), eth->ether_shost, 6);
  std::memcpy(info.dst_mac.data(), eth->ether_dhost, 6);

  auto iph =
      reinterpret_cast<const struct ip *>(packet + sizeof(struct ether_header));

  // Verify we have complete IP header
  if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
    return std::nullopt;

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
    return !hostname.empty() && hostname != ip
               ? std::format("{}:{} ({}) [{}]", ip, port, protocol, hostname)
               : std::format("{}:{} ({})", ip, port, protocol);
  }

  // Lexicographic ordering for std::set
  constexpr bool operator<(const endpoint &other) const {
    if (ip != other.ip)
      return ip < other.ip;
    if (port != other.port)
      return port < other.port;
    return protocol < other.protocol;
  }
};

// Compile-time unit tests for endpoint comparison
namespace {
constexpr auto test_endpoint_ordering_by_ip() {
  auto ep1 = endpoint{"192.168.1.1", 80, "TCP", ""};
  auto ep2 = endpoint{"192.168.1.2", 80, "TCP", ""};
  return ep1 < ep2; // Should be true (IP comparison)
}

constexpr auto test_endpoint_ordering_by_port() {
  auto ep1 = endpoint{"192.168.1.1", 80, "TCP", ""};
  auto ep2 = endpoint{"192.168.1.1", 443, "TCP", ""};
  return ep1 < ep2; // Should be true (port comparison)
}

constexpr auto test_endpoint_ordering_by_protocol() {
  auto ep1 = endpoint{"192.168.1.1", 80, "TCP", ""};
  auto ep2 = endpoint{"192.168.1.1", 80, "UDP", ""};
  return ep1 < ep2; // Should be true ("TCP" < "UDP")
}

static_assert(test_endpoint_ordering_by_ip(),
              "Endpoint ordering by IP should work");
static_assert(test_endpoint_ordering_by_port(),
              "Endpoint ordering by port should work");
static_assert(test_endpoint_ordering_by_protocol(),
              "Endpoint ordering by protocol should work");
} // namespace

int main(int argc, char *argv[]) {
  // Disable stdout buffering for real-time output in Docker
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  // Install signal handlers for graceful shutdown
  std::signal(SIGINT, signal_handler);  // Ctrl+C
  std::signal(SIGTERM, signal_handler); // docker stop/kill

  auto errbuf = std::array<char, PCAP_ERRBUF_SIZE>{};
  pcap_t *handle = nullptr;
  auto live_mode = false;
  auto use_tui = true; // Enable TUI by default

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

    // Find best network interface (prefer en0 on macOS, eth0 on Linux)
    pcap_if_t *alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf.data()) == -1 || !alldevs) {
      std::print("Error finding network interfaces: {}\n", errbuf.data());
      std::print("Try specifying a file: {} <pcap-file>\n", argv[0]);
      return 1;
    }

    // Try to find en0 (macOS Wi-Fi) or eth0 (Linux), otherwise use first
    // non-loopback interface
    std::string dev_name;
    for (auto d = alldevs; d != nullptr; d = d->next) {
      if (std::string{d->name} == "en0" || std::string{d->name} == "eth0") {
        dev_name = d->name;
        break;
      }
      if (dev_name.empty() && std::string{d->name} != "lo" &&
          std::string{d->name} != "lo0")
        dev_name = d->name; // Fallback to first non-loopback
    }

    if (dev_name.empty()) {
      std::print("No suitable network interface found\n");
      pcap_freealldevs(alldevs);
      return 1;
    }

    // List available interfaces for debugging
    auto interface_count = 0uz;
    for (auto d = alldevs; d != nullptr; d = d->next)
      interface_count++;

    // Open live capture
    handle = pcap_open_live(dev_name.c_str(), 65535, 1, 1000, errbuf.data());
    pcap_freealldevs(alldevs);

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

    std::print("Live capture on {} ({} interfaces available)\n", dev_name,
               interface_count);
    std::print("Press Ctrl+C to stop\n\n");
  } else {
    // Replay mode - read from file
    handle = pcap_open_offline(pcap_file.c_str(), errbuf.data());
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

  // Initialise dissector runtime
  auto dissectors = dissector::runtime{};
  dissectors.load("dissectors/http.lua");
  dissectors.load("dissectors/dns.lua");

  // Initialise TUI data store (but don't start renderer yet)
  auto tui_store = std::make_shared<tui::data_store>();
  std::unique_ptr<tui::renderer> tui_renderer;

  if (use_tui) {
    tui_renderer = std::make_unique<tui::renderer>(tui_store);
    global_renderer = tui_renderer.get();

    // Start TUI renderer - this will take over the screen
    // Wrap in try-catch to handle terminal/TTY errors gracefully
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
      pcap_close(handle);
      return 1;
    }
  }

  // Packet iteration state
  auto header = static_cast<struct pcap_pkthdr *>(nullptr);
  auto packet = static_cast<const u_char *>(nullptr);
  auto packet_count = 0uz;
  auto start_time = std::optional<std::chrono::steady_clock::time_point>{};
  auto first_packet_time = std::optional<struct timeval>{};

  // Process packets with error handling
  auto capture_result = 0;
  while (!stop_capture &&
         (capture_result = pcap_next_ex(handle, &header, &packet)) >= 0) {
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

    auto packet_offset = 0.0;

    // Only do timing for replay mode
    if (!live_mode) {
      // Record start time on first packet
      if (!first_packet_time) {
        first_packet_time = header->ts;
        start_time = std::chrono::steady_clock::now();
      }

      // Calculate time offset from first packet
      packet_offset =
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
    } else {
      // Live mode - initialise start time on first packet
      if (!start_time)
        start_time = std::chrono::steady_clock::now();

      // Calculate elapsed time since first packet for live mode
      auto now = std::chrono::steady_clock::now();
      auto elapsed =
          std::chrono::duration_cast<std::chrono::seconds>(now - *start_time)
              .count();
      packet_offset = static_cast<double>(elapsed);
    }

    // Update TUI clock with current timing
    if (start_time)
      tui_store->set_capture_time(*start_time, packet_offset);

    // Parse and display packet information
    auto info = parse_packet(packet, header);
    if (info) {
      // Add endpoint information to TUI
      auto src_host = dns::reverse_lookup(info->src_ip);
      auto dst_host = dns::reverse_lookup(info->dst_ip);
      auto src_vendor = oui::lookup_vendor(info->src_mac);
      auto dst_vendor = oui::lookup_vendor(info->dst_mac);

      // Format MAC addresses
      auto src_mac_str =
          std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                      info->src_mac[0], info->src_mac[1], info->src_mac[2],
                      info->src_mac[3], info->src_mac[4], info->src_mac[5]);
      auto dst_mac_str =
          std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                      info->dst_mac[0], info->dst_mac[1], info->dst_mac[2],
                      info->dst_mac[3], info->dst_mac[4], info->dst_mac[5]);

      tui_store->add_endpoint(info->src_ip, info->src_port, info->protocol,
                              src_host, src_vendor, src_mac_str);
      tui_store->add_endpoint(info->dst_ip, info->dst_port, info->protocol,
                              dst_host, dst_vendor, dst_mac_str);

      // Build packet entry
      auto format_endpoint = [](std::string_view ip, uint16_t port,
                                std::string_view host) {
        if (port == 0)
          return host.empty() || host == ip ? std::string{ip}
                                            : std::format("{} ({})", ip, host);

        auto service = port_to_service(port);
        auto port_display = service.empty()
                                ? std::format("{}", port)
                                : std::format("{}/{}", port, service);

        return !host.empty() && host != ip
                   ? std::format("{}:{} ({})", ip, port_display, host)
                   : std::format("{}:{}", ip, port_display);
      };

      auto pkt = tui::packet_entry{};
      pkt.number = packet_count;
      pkt.timestamp = packet_offset;
      pkt.protocol = info->protocol;
      pkt.src = format_endpoint(info->src_ip, info->src_port, src_host);
      pkt.dst = format_endpoint(info->dst_ip, info->dst_port, dst_host);
      pkt.bytes = info->length;

      // Try to dissect application-layer protocol
      if (info->payload && info->payload_length > 0) {
        auto dissected =
            dissectors.dissect(info->payload, info->payload_length,
                               info->src_port, info->dst_port, info->protocol);
        if (dissected)
          pkt.dissection =
              std::format("{} {}", dissected->protocol, dissected->info);
      }

      tui_store->add_packet(pkt);

      // Print text output if TUI is disabled
      if (!use_tui) {
        std::print("[{}] {} {} → {} ({} bytes)", pkt.number, pkt.protocol,
                   pkt.src, pkt.dst, pkt.bytes);
        if (!pkt.dissection.empty())
          std::print(" | {}", pkt.dissection);
        std::print("\n");
      }
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
  global_renderer = nullptr;

  // Check if capture ended due to error
  if (capture_result == -1) {
    std::print("\n\nCapture error: {}\n", pcap_geterr(handle));
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

  // Wait for any remaining DNS lookups to complete
  if (packet_count > 0) {
    std::print("\nWaiting for DNS resolution to complete...\n");
    dns::wait_for_resolution();
    std::print("DNS resolution complete.\n");
  }

  pcap_close(handle);
  return capture_result == -1 ? 1 : 0;
}
