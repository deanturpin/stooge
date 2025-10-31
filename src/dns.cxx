#include "dns.hxx"
#include <arpa/inet.h>
#include <cstring>
#include <map>
#include <netdb.h>

namespace dns {

// Perform reverse DNS lookup for an IP address, with caching
// Returns hostname if found, empty string if lookup fails
std::string reverse_lookup(const std::string &ip) {
  // Static cache persists across calls, thread-safe initialisation guaranteed
  // since C++11
  static std::map<std::string, std::string> cache;

  // Return cached result if available
  if (auto it = cache.find(ip); it != cache.end()) {
    return it->second;
  }

  // Prepare sockaddr structure for getnameinfo()
  struct sockaddr_in sa;
  char host[NI_MAXHOST];

  std::memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

  // Attempt reverse DNS lookup
  std::string hostname;
  if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host),
                  nullptr, 0, 0) == 0) {
    hostname = host;
  }

  // Cache the result (empty string on failure) and return
  cache[ip] = hostname;
  return hostname;
}

} // namespace dns
