// Terminal UI for displaying packet capture in split-screen layout
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
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
  std::string ip_;
  uint16_t port_;
  std::string protocol_;
  std::string hostname_;    // Cached DNS lookup
  std::string vendor_;      // MAC vendor
  std::string mac_address_; // MAC address (formatted as XX:XX:XX:XX:XX:XX)
  size_t packet_count_ = 0uz;
  std::chrono::steady_clock::time_point last_seen_;

  std::string to_string() const;
};

// Packet information for display
struct packet_entry {
  size_t number_;
  double timestamp_;     // Seconds from start (0 for live mode)
  std::string protocol_; // TCP, UDP, etc.
  std::string src_;      // Source IP:port with hostname
  std::string dst_;      // Dest IP:port with hostname
  size_t bytes_;
  std::string dissection_; // Optional protocol dissection info
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

  // Get packets per second rate
  double get_packets_per_second() const;

  // Set capture mode (live vs replay) - call once during initialization
  void set_capture_mode(bool is_live);

  // Set current packet time
  void set_capture_time(double current_seconds);

  // Set last packet's actual timestamp (from PCAP header)
  void set_last_packet_timestamp(time_t seconds, suseconds_t microseconds);

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
  std::atomic<size_t> total_packets_{0uz};    // Lock-free counter
  static constexpr auto MAX_PACKETS = 1000uz; // Ringbuffer size

  // Timing information (lock-free atomics)
  std::atomic<double> current_packet_time_{
      0.0}; // Seconds from PCAP start or elapsed live time
  std::atomic<bool> is_live_capture_{false};
  std::atomic<time_t> last_packet_timestamp_{
      0}; // Actual wall-clock time from PCAP
  std::chrono::steady_clock::time_point start_time_{
      std::chrono::steady_clock::now()}; // When capture started

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

  // Set callback for when user quits (presses q/Esc)
  void set_quit_callback(std::function<void()> callback);

  // Set callback for packet processing (runs in background thread)
  void set_packet_processor(std::function<void(std::stop_token)> processor);

private:
  std::shared_ptr<data_store> store_;
  std::string status_message_; // Status line message
  std::mutex status_mutex_;    // Protect status message updates
  std::optional<std::reference_wrapper<ftxui::ScreenInteractive>>
      screen_; // Reference to FTXUI screen for cleanup
  std::atomic<bool> screen_active_{
      false}; // Thread-safe flag for screen validity

  // Braille spinner animation state (thread-safe)
  std::atomic<size_t> spinner_frame_{0uz};
  static constexpr std::array<const char *, 8> SPINNER_FRAMES = {
      "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"};

  // Callback invoked when user quits
  std::function<void()> quit_callback_;

  // Callback for packet processing (invoked in background thread)
  std::function<void(std::stop_token)> packet_processor_;

  void render_loop();
  void set_status(std::string_view);
};

} // namespace tui
