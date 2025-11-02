// Terminal UI for displaying packet capture in split-screen layout
#pragma once

#include <atomic>
#include <chrono>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace ftxui {
class ScreenInteractive;
}

namespace tui {

// Endpoint information with packet statistics
struct endpoint_stats {
  std::string ip;
  uint16_t port;
  std::string protocol;
  std::string hostname;      // Cached DNS lookup
  std::string vendor;        // MAC vendor
  std::string mac_address;   // MAC address (formatted as XX:XX:XX:XX:XX:XX)
  size_t packet_count = 0;
  std::chrono::steady_clock::time_point last_seen;

  std::string to_string() const;
};

// Packet information for display
struct packet_entry {
  size_t number;
  double timestamp;     // Seconds from start (0 for live mode)
  std::string protocol; // TCP, UDP, etc.
  std::string src;      // Source IP:port with hostname
  std::string dst;      // Dest IP:port with hostname
  size_t bytes;
  std::string dissection; // Optional protocol dissection info
};

// Thread-safe data store for TUI
class data_store {
public:
  // Add or update endpoint statistics
  void add_endpoint(const std::string &ip, uint16_t port,
                    const std::string &protocol, const std::string &hostname,
                    const std::string &vendor = "",
                    const std::string &mac_address = "");

  // Add packet entry to scrolling feed
  void add_packet(const packet_entry &entry);

  // Get current endpoint list sorted by packet count
  std::vector<endpoint_stats> get_endpoints() const;

  // Get recent packets (last N entries)
  std::vector<packet_entry> get_recent_packets(size_t count) const;

  // Get total packet count
  size_t get_total_packets() const;

private:
  mutable std::mutex mutex_;
  std::map<std::string, endpoint_stats> endpoints_; // Key: "ip:port:protocol"
  std::deque<packet_entry> packets_;
  size_t total_packets_ = 0;
  static constexpr size_t MAX_PACKETS = 1000; // Ringbuffer size
};

// Main TUI renderer - manages screen updates
class renderer {
public:
  renderer(std::shared_ptr<data_store> store);
  ~renderer();

  // Start rendering loop (runs in separate thread)
  void start();

  // Stop rendering and restore terminal
  void stop();

  // Check if renderer is running
  bool is_running() const;

private:
  std::shared_ptr<data_store> store_;
  std::atomic<bool> running_{false};
  bool paused_ = false;
  bool show_help_ = false;
  std::unique_ptr<std::thread> render_thread_;
  ftxui::ScreenInteractive *screen_ = nullptr; // Pointer to FTXUI screen for cleanup

  void render_loop();
};

} // namespace tui
