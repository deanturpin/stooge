// Terminal UI for displaying packet capture in split-screen layout
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
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
  std::string hostname;    // Cached DNS lookup
  std::string vendor;      // MAC vendor
  std::string mac_address; // MAC address (formatted as XX:XX:XX:XX:XX:XX)
  size_t packet_count = 0uz;
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
  void add_endpoint(std::string_view ip, uint16_t port,
                    std::string_view protocol, std::string_view hostname,
                    std::string_view vendor = "",
                    std::string_view mac_address = "");

  // Add packet entry to scrolling feed
  void add_packet(const packet_entry &entry);

  // Get current endpoint list sorted by packet count
  std::vector<endpoint_stats> get_endpoints() const;

  // Get recent packets (last N entries)
  std::vector<packet_entry> get_recent_packets(size_t count) const;

  // Get total packet count
  size_t get_total_packets() const;

  // Set capture start time and current packet time
  void set_capture_time(std::chrono::steady_clock::time_point start,
                        double current_seconds);

  // Get elapsed time string (for live) or packet time string (for replay)
  std::string get_time_display() const;

  // Check if we're in live capture mode
  bool is_live() const;

  // Get list of IPs that need DNS resolution (empty hostname field)
  std::vector<std::string> get_unresolved_ips() const;

  // Update hostname for a specific IP address across all endpoints
  void update_hostname(std::string_view ip, std::string_view hostname);

  // Set status message (e.g., "Resolving <IP>")
  void set_status(std::string_view message);

  // Get current status message
  std::string get_status() const;

  // Wait for new unresolved IPs (blocks until notified or timeout)
  // Takes ownership of the condition variable to wait on
  void wait_for_work(std::condition_variable &cv, std::mutex &cv_mutex) const;

  // Notify waiting threads that new endpoints have been added
  void notify_new_endpoints(std::condition_variable &cv);

private:
  mutable std::mutex mutex_;
  std::map<std::string, endpoint_stats> endpoints_; // Key: "ip:port:protocol"
  std::deque<packet_entry> packets_;
  size_t total_packets_ = 0uz;
  static constexpr auto MAX_PACKETS = 1000uz; // Ringbuffer size

  // Timing information
  std::chrono::steady_clock::time_point capture_start_;
  double current_packet_time_ =
      0.0; // Seconds from PCAP start or elapsed live time
  bool is_live_capture_ = false;

  // Status message (e.g., DNS resolution progress)
  std::string status_message_;
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
  std::string status_message_; // Status line message
  std::mutex status_mutex_;    // Protect status message updates
  std::unique_ptr<std::thread> render_thread_;
  std::optional<std::reference_wrapper<ftxui::ScreenInteractive>>
      screen_; // Reference to FTXUI screen for cleanup

  void render_loop();
  void set_status(std::string_view message);
};

} // namespace tui
