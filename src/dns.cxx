#include "dns.hxx"
#include <arpa/inet.h>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <map>
#include <mutex>
#include <netdb.h>
#include <queue>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace dns {

namespace {
// Shared cache with mutex for thread-safe access
std::map<std::string, std::string> cache;
std::mutex cache_mutex;

// Thread pool for DNS resolution
constexpr auto MAX_WORKERS = 10;
std::vector<std::thread> workers;
std::queue<std::string> work_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;
auto shutdown = false;

// Perform blocking DNS lookup (internal helper)
std::string resolve_blocking(const std::string &ip) {
  auto sa = sockaddr_in{};
  auto host = std::array<char, NI_MAXHOST>{};

  sa.sin_family = AF_INET;
  inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

  auto hostname = std::string{};
  if (getnameinfo(reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa),
                  host.data(), host.size(), nullptr, 0, 0) == 0)
    hostname = host.data();

  return hostname;
}

// Worker thread function
void worker_thread() {
  while (true) {
    auto ip = std::string{};

    {
      auto lock = std::unique_lock{queue_mutex};
      queue_cv.wait(lock, []() { return shutdown || !work_queue.empty(); });

      if (shutdown && work_queue.empty())
        return;

      ip = work_queue.front();
      work_queue.pop();
    }

    // Resolve DNS (outside lock)
    auto hostname = resolve_blocking(ip);

    // Store result in cache
    auto lock = std::scoped_lock{cache_mutex};
    cache[ip] = hostname;
  }
}

// Initialize thread pool
void init_workers() {
  static auto initialized = false;
  if (initialized)
    return;

  for (auto i = 0; i < MAX_WORKERS; ++i)
    workers.emplace_back(worker_thread);

  initialized = true;
}
} // anonymous namespace

// Perform reverse DNS lookup for an IP address, with caching
// Returns hostname if found, empty string if lookup fails or not yet resolved
// Automatically starts background resolution on first lookup
std::string reverse_lookup(const std::string &ip) {
  init_workers();

  {
    auto lock = std::scoped_lock{cache_mutex};

    // Return cached result if available
    if (cache.contains(ip))
      return cache[ip];

    // Mark IP as being resolved (empty string in cache)
    cache[ip] = {};
  }

  // Queue for background resolution
  {
    auto lock = std::scoped_lock{queue_mutex};
    work_queue.push(ip);
  }
  queue_cv.notify_one();

  // Return empty string for now (will be populated by background thread)
  return {};
}

// Wait for all background DNS lookups to complete
void wait_for_resolution() {
  // Wait for queue to drain
  while (true) {
    auto lock = std::unique_lock{queue_mutex};
    if (work_queue.empty())
      break;
    lock.unlock();
    std::this_thread::sleep_for(10ms);
  }

  // Shutdown workers
  {
    auto lock = std::scoped_lock{queue_mutex};
    shutdown = true;
  }
  queue_cv.notify_all();

  // Join all worker threads
  for (auto &worker : workers)
    if (worker.joinable())
      worker.join();

  workers.clear();
  shutdown = false;
}

} // namespace dns
