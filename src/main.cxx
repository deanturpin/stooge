#include <print>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <set>
#include <string>
#include <cstring>

std::string reverse_dns_lookup(const std::string& ip) {
    struct sockaddr_in sa;
    char host[NI_MAXHOST];

    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), nullptr, 0, 0) == 0) {
        return host;
    }
    return "";
}

struct Endpoint {
    std::string ip;
    uint16_t port;
    std::string protocol;
    mutable std::string hostname;

    std::string to_string() const {
        if (hostname.empty()) {
            hostname = reverse_dns_lookup(ip);
        }
        if (!hostname.empty() && hostname != ip) {
            return std::format("{}:{} ({}) [{}]", ip, port, protocol, hostname);
        }
        return std::format("{}:{} ({})", ip, port, protocol);
    }

    bool operator<(const Endpoint& other) const {
        if (ip != other.ip) return ip < other.ip;
        if (port != other.port) return port < other.port;
        return protocol < other.protocol;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::print("Usage: {} <pcap-file>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        std::print("Error opening file {}: {}\n", filename, errbuf);
        return 1;
    }

    std::print("Successfully opened PCAP file: {}\n\n", filename);

    int datalink = pcap_datalink(handle);
    std::print("Data link type: {} ({})\n",
               pcap_datalink_val_to_name(datalink),
               pcap_datalink_val_to_description(datalink));

    struct pcap_pkthdr* header;
    const u_char* packet;
    int packet_count = 0;
    std::set<Endpoint> endpoints;

    while (pcap_next_ex(handle, &header, &packet) == 1) {
        packet_count++;

        if (header->caplen < sizeof(struct ether_header)) continue;

        struct ether_header* eth = (struct ether_header*)packet;

        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            struct ip* iph = (struct ip*)(packet + sizeof(struct ether_header));

            if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
                continue;

            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);

            if (iph->ip_p == IPPROTO_TCP) {
                struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

                if (header->caplen >= sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr)) {
                    endpoints.insert({src_ip, ntohs(tcph->th_sport), "TCP"});
                    endpoints.insert({dst_ip, ntohs(tcph->th_dport), "TCP"});
                }
            } else if (iph->ip_p == IPPROTO_UDP) {
                struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

                if (header->caplen >= sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)) {
                    endpoints.insert({src_ip, ntohs(udph->uh_sport), "UDP"});
                    endpoints.insert({dst_ip, ntohs(udph->uh_dport), "UDP"});
                }
            }
        }
    }

    std::print("\nTotal packets: {}\n", packet_count);
    std::print("Unique endpoints: {}\n\n", endpoints.size());

    std::print("Endpoints:\n");
    for (const auto& endpoint : endpoints) {
        std::print("  {}\n", endpoint.to_string());
    }

    pcap_close(handle);
    return 0;
}
