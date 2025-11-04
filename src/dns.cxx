// DNS reverse lookup with async resolution working on endpoint map
#include "dns.hxx"
#include "tui.hxx"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <format>
#include <future>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <set>
#include <thread>

using namespace std::chrono_literals;

namespace dns {

namespace {
// Single DNS resolution thread
auto dns_thread = std::unique_ptr<std::thread>{};
auto shutdown = std::atomic<bool>{false};
auto store_ptr = std::shared_ptr<tui::data_store>{};
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

// Resolve DNS with timeout (2 second limit)
std::string resolve_with_timeout(std::string_view ip) {
  // Launch async DNS lookup
  auto future =
      std::async(std::launch::async, [ip] { return resolve_blocking(ip); });

  // Wait for result with 2 second timeout
  if (future.wait_for(2s) == std::future_status::ready)
    return future.get();

  // Timeout - return empty string
  return {};
}

// DNS resolution thread function
void dns_resolver_thread() {
  auto resolved_ips = std::set<std::string>{};

  while (!shutdown) {
    // Wait for work (new endpoints or timeout)
    {
      auto lock = std::unique_lock{dns_mutex};
      store_ptr->wait_for_work(lock, dns_cv);
    }

    if (shutdown)
      return;

    // Get list of IPs that need resolution
    auto unresolved = store_ptr->get_unresolved_ips();

    // Show progress if there are IPs to resolve
    if (!unresolved.empty())
      store_ptr->set_status(
          std::format("DNS: {} unresolved", unresolved.size()));

    // Count how many from this batch still need resolution
    auto unresolved_count = std::ranges::count_if(
        unresolved, [&](const auto &ip) { return !resolved_ips.contains(ip); });

    // Resolve each IP that hasn't been resolved yet
    for (const auto &ip : unresolved) {
      if (shutdown)
        return;

      // Skip if we've already tried to resolve this IP
      if (resolved_ips.contains(ip))
        continue;

      // Update status bar with current resolution
      store_ptr->set_status(std::format("DNS: Resolving {} ({} remaining)", ip,
                                        unresolved_count));

      // Resolve DNS with 2 second timeout
      auto hostname = resolve_with_timeout(ip);

      // Update all endpoints with this IP (use IP itself for failed lookups)
      if (!hostname.empty())
        store_ptr->update_hostname(ip, hostname);
      else
        store_ptr->update_hostname(ip, ip); // Mark as attempted (IP = hostname)

      // Mark as resolved (even if it failed, don't retry)
      resolved_ips.insert(ip);
      unresolved_count--;
    }

    // Clear status when all done
    if (unresolved.empty() || resolved_ips.size() == unresolved.size())
      store_ptr->set_status("");
  }
}
} // anonymous namespace

// Start DNS resolution thread that works on endpoint map
void start_resolver(std::shared_ptr<tui::data_store> store) {
  if (dns_thread)
    return; // Already running

  store_ptr = store;
  shutdown = false;
  dns_thread = std::make_unique<std::thread>(dns_resolver_thread);
}

// Stop DNS resolution thread
void stop_resolver() {
  shutdown = true;
  dns_cv.notify_one(); // Wake up DNS thread to check shutdown flag

  if (dns_thread && dns_thread->joinable())
    dns_thread->join();

  dns_thread.reset();
  store_ptr.reset();
}

// Notify DNS thread that new endpoints have been added
void notify_new_work() { store_ptr->notify_new_endpoints(dns_cv); }

} // namespace dns
