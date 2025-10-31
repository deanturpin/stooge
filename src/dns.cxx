#include "dns.hxx"
#include <arpa/inet.h>
#include <cstring>
#include <map>
#include <netdb.h>

namespace dns {

std::string reverse_lookup(const std::string &ip) {
  static std::map<std::string, std::string> cache;

  if (auto it = cache.find(ip); it != cache.end()) {
    return it->second;
  }

  struct sockaddr_in sa;
  char host[NI_MAXHOST];

  std::memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

  std::string hostname;
  if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host),
                  nullptr, 0, 0) == 0) {
    hostname = host;
  }

  cache[ip] = hostname;
  return hostname;
}

} // namespace dns
