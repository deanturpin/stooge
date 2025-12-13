// DNS reverse lookup with async resolution working on endpoint map
#include "dns.hxx"
#include "tui.hxx"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <format>
#include <future>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <set>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace dns {

namespace {
// Single DNS resolution thread
auto dns_thread = std::unique_ptr<std::thread>{};
auto shutdown = std::atomic<bool>{false};
auto store_ptr = std::shared_ptr<tui::traffic_monitor>{};
auto dns_cv = std::condition_variable{};
auto dns_mutex = std::mutex{};

// Perform blocking DNS lookup (internal helper)
std::string resolve_blocking(std::string_view ip) {
  auto sa = sockaddr_in{};
  auto host = std::array<char, NI_MAXHOST>{};

  sa.sin_family = AF_INET;
  inet_pton(AF_INET, std::string{ip}.c_str(), &sa.sin_addr);

  auto hostname = std::string{};
  if (getnameinfo(reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa),
                  host.data(), host.size(), nullptr, 0, 0) == 0)
    hostname = host.data();

  return hostname;
}

// Resolve DNS with interruptible timeout (5 second limit)
// Checks shutdown flag every 100ms for quick exit
std::string resolve_with_timeout(std::string_view ip) {
  // Launch async DNS lookup
  auto future =
      std::async(std::launch::async, [ip] { return resolve_blocking(ip); });

  // Wait for result with interruptible timeout (check every 100ms)
  auto elapsed = 0ms;
  constexpr auto timeout = 5s;
  constexpr auto check_interval = 100ms;

  while (elapsed < timeout && !shutdown) {
    if (future.wait_for(check_interval) == std::future_status::ready)
      return future.get();
    elapsed += check_interval;
  }

  // Timeout or shutdown - return empty string
  return {};
}

// DNS resolution thread function
void dns_resolver_thread() {
  auto resolved_ips = std::set<std::string>{};
  auto iteration_count = 0uz;

  while (!shutdown) {
    // Safety check: ensure store is still valid
    if (store_ptr == nullptr)
      return;

    // Wait for work (new endpoints or timeout)
    // Predicate in wait_for_work ensures we only wake when there's work
    store_ptr->wait_for_work(dns_cv, dns_mutex);

    // Check again after waking - store could have been reset during shutdown
    if (shutdown || store_ptr == nullptr)
      return;

    // Get list of IPs that need resolution
    auto unresolved = store_ptr->get_unresolved_ips();

    // Skip if no work to do (spurious wakeup or timeout)
    if (unresolved.empty())
      continue;

    // Filter out already-resolved IPs
    auto new_ips = std::vector<std::string>{};
    for (const auto &ip : unresolved) {
      if (!resolved_ips.contains(ip))
        new_ips.push_back(ip);
    }

    // Skip if no new work
    if (new_ips.empty())
      continue;

    store_ptr->set_status(std::format("DNS: Resolving {} IPs", new_ips.size()));

    // Resolve each new IP
    for (const auto &ip : new_ips) {
      if (shutdown)
        return;

      store_ptr->set_status(std::format("DNS: Resolving {}", ip));

      // Resolve DNS with 2 second timeout
      auto hostname = resolve_with_timeout(ip);

      // Increment DNS query counter (track network noise)
      store_ptr->increment_dns_queries();

      // Update all endpoints with this IP (use IP itself for failed lookups)
      if (!hostname.empty())
        store_ptr->update_hostname(ip, hostname);
      else
        store_ptr->update_hostname(ip, ip); // Mark as attempted (IP = hostname)

      // Mark as resolved (even if it failed, don't retry)
      resolved_ips.insert(ip);
    }

    // Clear status when done
    store_ptr->set_status("");
  }
}
} // anonymous namespace

// Start DNS resolution thread that works on endpoint map
void start_resolver(std::shared_ptr<tui::traffic_monitor> store) {
  if (dns_thread)
    return; // Already running

  store_ptr = store;
  shutdown = false;
  dns_thread = std::make_unique<std::thread>(dns_resolver_thread);
}

// Stop DNS resolution thread
void stop_resolver() {
  std::fprintf(stderr, "DNS: Stopping resolver...\n");
  shutdown = true;
  dns_cv.notify_one(); // Wake up DNS thread to check shutdown flag

  std::fprintf(stderr, "DNS: Waiting for thread to join...\n");
  if (dns_thread && dns_thread->joinable())
    dns_thread->join();

  std::fprintf(stderr, "DNS: Thread joined, cleaning up...\n");
  dns_thread.reset();
  store_ptr.reset();
  std::fprintf(stderr, "DNS: Resolver stopped\n");
}

// Notify DNS thread that new endpoints have been added
void notify_new_work() {
  if (store_ptr != nullptr) {
    store_ptr->notify_new_endpoints(dns_cv);
  } else {
    // Store has been reset during shutdown - skip notification
    // This prevents bad_function_call race condition
  }
}

} // namespace dns
