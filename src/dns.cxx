#include "dns.hxx"
#include <arpa/inet.h>
#include <cstring>
#include <map>
#include <mutex>
#include <netdb.h>
#include <thread>
#include <vector>

namespace dns {

namespace {
// Shared cache with mutex for thread-safe access
std::map<std::string, std::string> cache;
std::mutex cache_mutex;

// Background worker threads
std::vector<std::thread> workers;

// Perform blocking DNS lookup (internal helper)
std::string resolve_blocking(const std::string &ip) {
  struct sockaddr_in sa;
  auto host = std::array<char, NI_MAXHOST>{};

  std::memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

  auto hostname = std::string{};
  if (getnameinfo(reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa),
                  host.data(), host.size(), nullptr, 0, 0) == 0)
    hostname = host.data();

  return hostname;
}
} // anonymous namespace

// Perform reverse DNS lookup for an IP address, with caching
// Returns hostname if found, empty string if lookup fails or not yet resolved
// Automatically starts background resolution on first lookup
std::string reverse_lookup(const std::string &ip) {
  {
    auto lock = std::scoped_lock{cache_mutex};

    // Return cached result if available
    if (cache.contains(ip))
      return cache[ip];

    // Mark IP as being resolved (empty string in cache)
    cache[ip] = {};
  }

  // Not in cache - start background resolution (outside lock)
  workers.emplace_back([ip]() {
    auto hostname = resolve_blocking(ip);

    // Store result in cache
    auto lock = std::scoped_lock{cache_mutex};
    cache[ip] = hostname;
  });

  // Return empty string for now (will be populated by background thread)
  return {};
}

// Wait for all background DNS lookups to complete
void wait_for_resolution() {
  for (auto &worker : workers)
    if (worker.joinable())
      worker.join();
  workers.clear();
}

} // namespace dns
