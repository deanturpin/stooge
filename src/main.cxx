#include "dns.hxx"
#include <arpa/inet.h>
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

constexpr double SPEEDUP_FACTOR = 10.0;

struct PacketInfo {
  std::string src_ip;
  std::string dst_ip;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  std::string protocol;
  size_t length = 0;

  std::string describe() const {
    std::string src_host = dns::reverse_lookup(src_ip);
    std::string dst_host = dns::reverse_lookup(dst_ip);

    auto format_endpoint = [](const std::string &ip, uint16_t port,
                              const std::string &host) {
      if (!host.empty() && host != ip) {
        if (port > 0) {
          return std::format("{}:{} ({})", ip, port, host);
        }
        return std::format("{} ({})", ip, host);
      }
      if (port > 0) {
        return std::format("{}:{}", ip, port);
      }
      return ip;
    };

    std::string src = format_endpoint(src_ip, src_port, src_host);
    std::string dst = format_endpoint(dst_ip, dst_port, dst_host);

    return std::format("{} {} → {} ({} bytes)", protocol, src, dst, length);
  }
};

std::optional<PacketInfo> parse_packet(const u_char *packet,
                                       const struct pcap_pkthdr *header) {
  if (header->caplen < sizeof(struct ether_header))
    return std::nullopt;

  struct ether_header *eth = (struct ether_header *)packet;

  if (ntohs(eth->ether_type) != ETHERTYPE_IP)
    return std::nullopt;

  struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));

  if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
    return std::nullopt;

  PacketInfo info;
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);
  info.src_ip = src_ip;
  info.dst_ip = dst_ip;
  info.length = header->len;

  if (iph->ip_p == IPPROTO_TCP) {
    struct tcphdr *tcph =
        (struct tcphdr *)(packet + sizeof(struct ether_header) +
                          sizeof(struct ip));
    if (header->caplen >= sizeof(struct ether_header) + sizeof(struct ip) +
                              sizeof(struct tcphdr)) {
      info.protocol = "TCP";
      info.src_port = ntohs(tcph->th_sport);
      info.dst_port = ntohs(tcph->th_dport);
    }
  } else if (iph->ip_p == IPPROTO_UDP) {
    struct udphdr *udph =
        (struct udphdr *)(packet + sizeof(struct ether_header) +
                          sizeof(struct ip));
    if (header->caplen >= sizeof(struct ether_header) + sizeof(struct ip) +
                              sizeof(struct udphdr)) {
      info.protocol = "UDP";
      info.src_port = ntohs(udph->uh_sport);
      info.dst_port = ntohs(udph->uh_dport);
    }
  } else {
    info.protocol = "IP";
  }

  return info;
}

struct Endpoint {
  std::string ip;
  uint16_t port;
  std::string protocol;
  mutable std::string hostname;

  std::string to_string() const {
    if (hostname.empty()) {
      hostname = dns::reverse_lookup(ip);
    }
    if (!hostname.empty() && hostname != ip) {
      return std::format("{}:{} ({}) [{}]", ip, port, protocol, hostname);
    }
    return std::format("{}:{} ({})", ip, port, protocol);
  }

  bool operator<(const Endpoint &other) const {
    if (ip != other.ip)
      return ip < other.ip;
    if (port != other.port)
      return port < other.port;
    return protocol < other.protocol;
  }
};

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::print("Usage: {} <pcap-file>\n", argv[0]);
    return 1;
  }

  const char *filename = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *handle = pcap_open_offline(filename, errbuf);
  if (!handle) {
    std::print("Error opening file {}: {}\n", filename, errbuf);
    return 1;
  }

  std::print("Successfully opened PCAP file: {}\n", filename);
  std::print("Replay speed: {}x\n\n", SPEEDUP_FACTOR);

  int datalink = pcap_datalink(handle);
  std::print("Data link type: {} ({})\n\n", pcap_datalink_val_to_name(datalink),
             pcap_datalink_val_to_description(datalink));

  struct pcap_pkthdr *header;
  const u_char *packet;
  int packet_count = 0;
  std::optional<std::chrono::steady_clock::time_point> start_time;
  std::optional<struct timeval> first_packet_time;

  std::print("Beginning replay...\n\n");

  while (pcap_next_ex(handle, &header, &packet) == 1) {
    packet_count++;

    if (!first_packet_time) {
      first_packet_time = header->ts;
      start_time = std::chrono::steady_clock::now();
    }

    double packet_offset =
        (header->ts.tv_sec - first_packet_time->tv_sec) +
        (header->ts.tv_usec - first_packet_time->tv_usec) / 1000000.0;

    auto scaled_offset =
        std::chrono::duration<double>(packet_offset / SPEEDUP_FACTOR);
    auto target_time =
        *start_time +
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            scaled_offset);

    std::this_thread::sleep_until(target_time);

    auto info = parse_packet(packet, header);
    if (info) {
      std::print("[{:6d}] {:8.3f}s: {}\n", packet_count, packet_offset,
                 info->describe());
    }
  }

  std::print("\n\nReplay complete!\n");
  std::print("Total packets: {}\n", packet_count);

  auto dns_cache = dns::get_cache();
  std::print("DNS cache entries: {}\n\n", dns_cache.size());

  std::print("Resolved hostnames:\n");
  for (const auto &[ip, hostname] : dns_cache) {
    if (!hostname.empty() && hostname != ip) {
      std::print("  {} → {}\n", ip, hostname);
    }
  }

  pcap_close(handle);
  return 0;
}
