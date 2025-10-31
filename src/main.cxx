#include <print>
#include <pcap/pcap.h>
#include <cstring>

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

    std::print("Successfully opened PCAP file: {}\n", filename);

    int datalink = pcap_datalink(handle);
    std::print("Data link type: {} ({})\n",
               pcap_datalink_val_to_name(datalink),
               pcap_datalink_val_to_description(datalink));

    struct pcap_pkthdr* header;
    const u_char* packet;
    int packet_count = 0;

    while (pcap_next_ex(handle, &header, &packet) == 1) {
        packet_count++;
    }

    std::print("Total packets: {}\n", packet_count);

    pcap_close(handle);
    return 0;
}
