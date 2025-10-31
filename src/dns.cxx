#include "dns.hxx"
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>

namespace dns {
    std::string reverse_lookup(const std::string& ip) {
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
}
