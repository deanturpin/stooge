// Terminal UI implementation
#include "tui.hxx"
#include <algorithm>
#include <format>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <print>
#include <set>
#include <thread>

namespace tui {

std::string endpoint_stats::to_string() const {
  // Format: IP:port Protocol MAC Vendor Hostname Pkts
  auto ip_port = std::string{port > 0 ? std::format("{}:{}", ip, port) : ip};
  auto mac_str = std::string{mac_address.empty() ? "-" : mac_address};
  auto vendor_str = std::string{vendor.empty() ? "-" : vendor};
  auto host_str =
      std::string{hostname.empty() || hostname == ip ? "-" : hostname};

  return std::format("{:21} {:8} {:17} {:20} {:30} {:5}", ip_port.substr(0, 21),
                     protocol.substr(0, 8), mac_str.substr(0, 17),
                     vendor_str.substr(0, 20), host_str.substr(0, 30),
                     packet_count);
}

// data_store implementation
void data_store::add_endpoint(std::string_view ip, uint16_t port,
                              std::string_view protocol,
                              std::string_view hostname,
                              std::string_view vendor,
                              std::string_view mac_address) {
  auto lock = std::scoped_lock{mutex_};
  auto key = std::string{std::format("{}:{}:{}", ip, port, protocol)};

  auto &ep = endpoints_[key];
  ep.ip = ip;
  ep.port = port;
  ep.protocol = protocol;
  if (!hostname.empty())
    ep.hostname = hostname;
  if (!vendor.empty())
    ep.vendor = vendor;
  if (!mac_address.empty())
    ep.mac_address = mac_address;
  ep.packet_count++;
  ep.last_seen = std::chrono::steady_clock::now();
}

void data_store::add_packet(const packet_entry &entry) {
  auto lock = std::scoped_lock{mutex_};
  packets_.push_back(entry);
  if (packets_.size() > MAX_PACKETS)
    packets_.pop_front();
  total_packets_++;
}

std::vector<endpoint_stats> data_store::get_endpoints() const {
  auto lock = std::scoped_lock{mutex_};
  auto result = std::vector<endpoint_stats>{};
  result.reserve(endpoints_.size());

  for (const auto &[key, ep] : endpoints_)
    result.push_back(ep);

  // Sort by packet count (descending)
  std::sort(result.begin(), result.end(), [](const auto &a, const auto &b) {
    return a.packet_count > b.packet_count;
  });

  return result;
}

std::vector<packet_entry> data_store::get_recent_packets(size_t count) const {
  auto lock = std::scoped_lock{mutex_};
  auto result = std::vector<packet_entry>{};

  auto start = packets_.size() > count ? packets_.size() - count : 0;
  for (size_t i = start; i < packets_.size(); i++)
    result.push_back(packets_[i]);

  return result;
}

size_t data_store::get_total_packets() const {
  // Atomic counter - no lock needed
  return total_packets_.load();
}

void data_store::set_capture_time(std::chrono::steady_clock::time_point start,
                                  double current_seconds) {
  auto lock = std::scoped_lock{mutex_};
  capture_start_ = start;
  current_packet_time_ = current_seconds;
  is_live_capture_ = (current_seconds == 0.0); // Live if time is 0
}

std::string data_store::get_time_display() const {
  auto lock = std::scoped_lock{mutex_};

  // Show timestamp from most recent packet
  auto total_seconds = static_cast<int>(current_packet_time_);
  auto hours = total_seconds / 3600;
  auto minutes = (total_seconds % 3600) / 60;
  auto seconds = total_seconds % 60;
  return std::format("{:02d}:{:02d}:{:02d}", hours, minutes, seconds);
}

bool data_store::is_live() const {
  auto lock = std::scoped_lock{mutex_};
  return is_live_capture_;
}

std::vector<std::string> data_store::get_unresolved_ips() const {
  auto lock = std::scoped_lock{mutex_};
  auto unresolved = std::vector<std::string>{};

  // Collect unique IPs that don't have hostnames yet
  auto seen_ips = std::set<std::string>{};
  for (const auto &[key, ep] : endpoints_) {
    if (ep.hostname.empty() && !seen_ips.contains(ep.ip)) {
      unresolved.push_back(ep.ip);
      seen_ips.insert(ep.ip);
    }
  }

  return unresolved;
}

void data_store::update_hostname(std::string_view ip,
                                 std::string_view hostname) {
  auto lock = std::scoped_lock{mutex_};

  // Update all endpoints with this IP address
  for (auto &[key, ep] : endpoints_) {
    if (ep.ip == ip)
      ep.hostname = hostname;
  }
}

void data_store::set_status(std::string_view message) {
  auto lock = std::scoped_lock{mutex_};
  status_message_ = message;
}

std::string data_store::get_status() const {
  auto lock = std::scoped_lock{mutex_};
  return status_message_;
}

void data_store::wait_for_work(std::condition_variable &cv,
                               std::mutex &cv_mutex) const {
  // Wait until notified or timeout after 5 seconds
  // Predicate is checked with cv_mutex held, which condition_variable
  // releases/reacquires automatically during wait
  auto lock = std::unique_lock{cv_mutex};
  cv.wait_for(lock, std::chrono::seconds(5));

  // After waking up, check if there's actually work to do
  // (no predicate needed, caller will check get_unresolved_ips())
}

void data_store::notify_new_endpoints(std::condition_variable &cv) {
  // No lock needed - just notify waiting threads
  cv.notify_one();
}

// renderer implementation
renderer::renderer(std::shared_ptr<data_store> store) : store_(store) {}

renderer::~renderer() { stop(); }

void renderer::start() {
  if (running_)
    return;

  running_ = true;
  render_thread_ = std::make_unique<std::thread>([this] { render_loop(); });
}

void renderer::stop() {
  // Use exchange to atomically check and set - only first caller proceeds
  auto was_running = running_.exchange(false);
  if (!was_running)
    return; // Already stopped

  // Exit the screen loop if it's still active
  if (screen_.has_value()) {
    try {
      screen_->get().Exit();
    } catch (...) {
      // Suppress exceptions during shutdown
    }
  }

  // Join the render thread if it exists and is joinable
  if (render_thread_ && render_thread_->joinable())
    render_thread_->join();
}

bool renderer::is_running() const { return running_; }

void renderer::set_status(std::string_view message) {
  auto lock = std::scoped_lock{status_mutex_};
  status_message_ = message;
}

void renderer::render_loop() {
  using namespace ftxui;

  auto screen = ScreenInteractive::Fullscreen();
  screen_ = std::ref(screen); // Store screen reference for cleanup

  // Component that renders the UI
  auto component = Renderer([&] {
    // If help is shown, display help overlay
    if (show_help_) {
      auto help_lines = Elements{
          text("Keyboard Shortcuts") | bold | center,
          separator(),
          text(""),
          text("  q / Esc     Quit application"),
          text("  p           Pause/unpause display"),
          text("  h / ?       Toggle this help"),
          text("  Ctrl+C      Quit application"),
          text(""),
          text("Press any key to close") | dim | center,
      };

      auto help_content = vbox(help_lines) | border | bgcolor(Color::Blue) |
                          size(WIDTH, EQUAL, 40) | size(HEIGHT, EQUAL, 12) |
                          center | vcenter;

      return help_content | clear_under;
    }

    // Get current data (frozen if paused)
    auto endpoints = store_->get_endpoints();
    auto packets = store_->get_recent_packets(500);
    auto total = store_->get_total_packets();

    // Build endpoint list (left pane)
    auto endpoint_elements = std::vector<Element>{};
    endpoint_elements.push_back(text("Endpoints") | bold | color(Color::Cyan));
    endpoint_elements.push_back(separator());

    // Column headers
    auto header = std::string{std::format("{:21} {:8} {:17} {:20} {:30} {:5}",
                                          "IP:Port", "Protocol", "MAC",
                                          "Vendor", "Hostname", "Pkts")};
    endpoint_elements.push_back(text(header) | bold | color(Color::White));
    endpoint_elements.push_back(separator());

    for (const auto &ep : endpoints) {
      auto ep_text = text(ep.to_string());
      // Colourize by protocol
      if (ep.protocol == "TCP")
        ep_text = ep_text | color(Color::Green);
      else if (ep.protocol == "UDP")
        ep_text = ep_text | color(Color::Yellow);
      else
        ep_text = ep_text | color(Color::White);

      endpoint_elements.push_back(ep_text);
    }

    auto endpoint_pane =
        vbox(endpoint_elements) | vscroll_indicator | frame | flex;

    // Build packet list (right pane)
    auto packet_elements = std::vector<Element>{};
    auto time_display = store_->get_time_display();
    auto mode_text =
        std::string{store_->is_live() ? "Live Capture" : "PCAP Replay"};
    auto status_text =
        std::string{paused_ ? "PAUSED" : std::format("Total: {}", total)};
    packet_elements.push_back(text(std::format("{} ({}) | Time: {}", mode_text,
                                               status_text, time_display)) |
                              bold | color(paused_ ? Color::Red : Color::Cyan));
    packet_elements.push_back(separator());

    // Column headers for packets
    auto pkt_header =
        std::string{std::format("{:8} {:8} {:22} {:22} {:10}", "Number",
                                "Protocol", "Source", "Destination", "Bytes")};
    packet_elements.push_back(text(pkt_header) | bold | color(Color::White));
    packet_elements.push_back(separator());

    for (const auto &pkt : packets) {
      auto pkt_line =
          text(std::format("{:<8d} {:<8} {:<22} {:<22} {:<10}", pkt.number,
                           pkt.protocol, pkt.src, pkt.dst, pkt.bytes));

      // Colourize by protocol
      if (pkt.protocol == "TCP")
        pkt_line = pkt_line | color(Color::Green);
      else if (pkt.protocol == "UDP")
        pkt_line = pkt_line | color(Color::Yellow);
      else
        pkt_line = pkt_line | color(Color::White);

      packet_elements.push_back(pkt_line);

      // Add dissection info if present
      if (!pkt.dissection.empty()) {
        packet_elements.push_back(text("  └─ " + pkt.dissection) |
                                  color(Color::Magenta));
      }
    }

    auto packet_pane = vbox(packet_elements) | vscroll_indicator | frame | flex;

    // Status bar with shortcuts hint and status message
    // Check DNS status from data_store first, then renderer status
    auto dns_status = store_->get_status();
    auto status_msg = std::string{};
    {
      auto lock = std::scoped_lock{status_mutex_};
      status_msg = status_message_;
    }

    // Prioritise DNS status over renderer status
    auto final_status = !dns_status.empty() ? dns_status : status_msg;

    auto status_bar = Element{};
    if (!final_status.empty()) {
      // Show status message when present (DNS or renderer)
      status_bar = hbox({text(final_status) | bold | color(Color::Yellow)}) |
                   bgcolor(Color::GrayDark);
    } else {
      // Show shortcuts when no status message
      status_bar = hbox({text("Shortcuts: ") | dim, text("q") | bold,
                         text("/Esc=Quit ") | dim, text("p") | bold,
                         text("=Pause ") | dim, text("h") | bold,
                         text("/?=Help") | dim}) |
                   bgcolor(Color::GrayDark);
    }

    // Combine panes horizontally with status bar
    return vbox(
        {hbox({endpoint_pane, separator(), packet_pane}) | border | flex,
         status_bar});
  });

  // Capture component to handle keyboard shortcuts
  auto component_with_shortcuts = CatchEvent(component, [&](Event event) {
    // Quit shortcuts: q, Esc, Ctrl+C
    if (event == Event::Character('q') || event == Event::Escape ||
        (event.is_character() && event.character() == "c" &&
         event.input() == "\x03")) {
      running_ = false;
      screen.Exit();
      return true;
    }

    // Toggle help: h or ?
    if (event == Event::Character('h') || event == Event::Character('?')) {
      show_help_ = !show_help_;
      return true;
    }

    // Close help with any key when showing help
    if (show_help_ && event.is_character()) {
      show_help_ = false;
      return true;
    }

    // Pause/unpause: p
    if (event == Event::Character('p')) {
      paused_ = !paused_;
      return true;
    }

    return false;
  });

  // Refresh periodically (only when not paused)
  std::thread refresh_thread([&]() {
    try {
      while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (running_ && !paused_)
          screen.PostEvent(Event::Custom);
      }
    } catch (...) {
      // Suppress exceptions during shutdown
    }
  });

  screen.Loop(component_with_shortcuts);

  // Ensure refresh thread stops before cleanup
  set_status("Shutting down...");
  running_ = false;
  if (refresh_thread.joinable())
    refresh_thread.join();

  // Explicitly reset terminal to clean up any leftover escape codes
  screen_.reset();
  std::print("\033[0m\033[?25h"); // Reset attributes and show cursor
}

} // namespace tui
