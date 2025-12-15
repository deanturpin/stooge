// Terminal UI implementation
#include "tui.hxx"
#include "network_utils.hxx"
#include <algorithm>
#include <cctype>
#include <ctime>
#include <format>
#include <ftxui/component/component.hpp>
#include <ftxui/component/loop.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <print>
#include <set>
#include <thread>

namespace tui {

namespace {
// Case-insensitive substring search
bool contains_case_insensitive(std::string_view haystack,
                               std::string_view needle) {
  auto it = std::search(
      haystack.begin(), haystack.end(), needle.begin(), needle.end(),
      [](char a, char b) { return std::tolower(a) == std::tolower(b); });
  return it != haystack.end();
}
} // anonymous namespace

std::string endpoint_stats::to_string() const {
  // Format: IP MAC Vendor Packets Hostname
  // Consolidated by MAC - single entry per physical device

  auto mac_str = mac_address_.empty() ? "-" : mac_address_;
  auto vendor_str = vendor_.empty() || vendor_ == "-" ? "-" : vendor_;
  auto host_str = hostname_.empty() || hostname_ == ip_ ? "-" : hostname_;
  auto ip_str = ip_.empty() ? "-" : ip_;

  // Packets column before hostname to keep alignment consistent
  // IPv6 addresses can be up to 39 characters, IPv4 up to 15
  return std::format("{:39} {:17} {:20} {:<7} {}", ip_str,
                     mac_str.substr(0, 17), vendor_str.substr(0, 20),
                     packet_count_, host_str);
}

// traffic_monitor implementation
void traffic_monitor::add_endpoint(std::string_view ip, uint16_t port,
                                   std::string_view protocol,
                                   std::string_view hostname,
                                   std::string_view vendor,
                                   std::string_view mac_address) {
  auto lock = std::scoped_lock{mutex_};

  // Key by MAC only - consolidate all IPs for the same physical device
  // This shows one entry per device regardless of IP address changes
  auto key = std::string{mac_address};

  auto &ep = endpoints_[key];

  // Track all IPs seen for this MAC
  if (!ip.empty()) {
    ep.all_ips_.insert(std::string{ip});
    ep.ip_ = ip; // Most recently seen IP becomes primary
  }

  // Keep most recent port seen (could track all ports in future)
  ep.port_ = port;
  ep.protocol_ = protocol;

  if (!hostname.empty())
    ep.hostname_ = hostname;

  if (!vendor.empty())
    ep.vendor_ = vendor;

  if (!mac_address.empty())
    ep.mac_address_ = mac_address;

  ++ep.packet_count_;
  ep.last_seen_ = std::chrono::steady_clock::now();
}

void traffic_monitor::add_packet(const packet_entry &entry) {
  auto lock = std::scoped_lock{mutex_};
  packets_.push_back(entry);
  if (packets_.size() > MAX_PACKETS)
    packets_.pop_front();
  total_packets_++;
  total_bytes_ += entry.bytes_;

  auto now = std::chrono::steady_clock::now();

  // Add bandwidth sample for rolling calculation
  bandwidth_samples_.push_back({now, entry.bytes_});

  // Remove bandwidth samples older than the window
  auto bandwidth_cutoff = now - BANDWIDTH_WINDOW;
  while (!bandwidth_samples_.empty() &&
         bandwidth_samples_.front().timestamp < bandwidth_cutoff)
    bandwidth_samples_.pop_front();

  // Add packet timestamp for rate calculation
  packet_timestamps_.push_back(now);

  // Remove packet timestamps older than the window
  auto rate_cutoff = now - PACKET_RATE_WINDOW;
  while (!packet_timestamps_.empty() &&
         packet_timestamps_.front() < rate_cutoff)
    packet_timestamps_.pop_front();
}

std::vector<endpoint_stats> traffic_monitor::get_endpoints() const {
  auto lock = std::scoped_lock{mutex_};
  auto result = std::vector<endpoint_stats>{};
  result.reserve(endpoints_.size());

  for (const auto &[key, ep] : endpoints_)
    result.push_back(ep);

  // Sort: known vendors first, then resolved hostnames, then by packet count
  std::stable_sort(
      result.begin(), result.end(), [](const auto &a, const auto &b) {
        auto a_has_vendor = !a.vendor_.empty() && a.vendor_ != "-";
        auto b_has_vendor = !b.vendor_.empty() && b.vendor_ != "-";
        auto a_has_hostname =
            !a.hostname_.empty() && a.hostname_ != "-" && a.hostname_ != a.ip_;
        auto b_has_hostname =
            !b.hostname_.empty() && b.hostname_ != "-" && b.hostname_ != b.ip_;

        // Priority 1: Known vendors first
        if (a_has_vendor != b_has_vendor)
          return a_has_vendor;

        // Priority 2: Resolved hostnames (within same vendor group)
        if (a_has_hostname != b_has_hostname)
          return a_has_hostname;

        // Priority 3: Sort by packet count
        if (a.packet_count_ != b.packet_count_)
          return a.packet_count_ > b.packet_count_;

        // Priority 4: Tie-breaker by IP to prevent shuffling
        return a.ip_ < b.ip_;
      });

  return result;
}

std::vector<packet_entry>
traffic_monitor::get_recent_packets(size_t count) const {
  auto lock = std::scoped_lock{mutex_};
  auto result = std::vector<packet_entry>{};

  auto start = packets_.size() > count ? packets_.size() - count : 0;
  for (size_t i = start; i < packets_.size(); i++)
    result.push_back(packets_[i]);

  return result;
}

size_t traffic_monitor::get_total_packets() const {
  // Atomic counter - no lock needed
  return total_packets_.load();
}

double traffic_monitor::get_packets_per_second() const {
  auto lock = std::scoped_lock{mutex_};

  if (packet_timestamps_.empty())
    return 0.0;

  // Calculate elapsed time since first packet, capped at window size
  auto now = std::chrono::steady_clock::now();
  auto elapsed = now - packet_timestamps_.front();

  // Cap at window size to prevent rate from decreasing as timestamps age out
  auto window_seconds =
      std::chrono::duration_cast<std::chrono::duration<double>>(
          PACKET_RATE_WINDOW)
          .count();
  auto elapsed_seconds =
      std::chrono::duration_cast<std::chrono::duration<double>>(elapsed)
          .count();
  auto seconds = std::min(elapsed_seconds, window_seconds);

  // Need at least 0.1 seconds of data for meaningful rate
  if (seconds < 0.1)
    return 0.0;

  return static_cast<double>(packet_timestamps_.size()) / seconds;
}

double traffic_monitor::get_bits_per_second() const {
  auto lock = std::scoped_lock{mutex_};

  if (bandwidth_samples_.empty())
    return 0.0;

  // Calculate total bytes in the window
  auto total_bytes = 0uz;
  for (const auto &sample : bandwidth_samples_)
    total_bytes += sample.bytes;

  // Calculate elapsed time since first sample, capped at window size
  auto now = std::chrono::steady_clock::now();
  auto elapsed = now - bandwidth_samples_.front().timestamp;

  // Cap at window size to prevent rate from decreasing as samples age out
  auto window_seconds =
      std::chrono::duration_cast<std::chrono::duration<double>>(
          BANDWIDTH_WINDOW)
          .count();
  auto elapsed_seconds =
      std::chrono::duration_cast<std::chrono::duration<double>>(elapsed)
          .count();
  auto seconds = std::min(elapsed_seconds, window_seconds);

  // Need at least 0.1 seconds of data for meaningful rate
  if (seconds < 0.1)
    return 0.0;

  return static_cast<double>(total_bytes) * 8.0 / seconds;
}

void traffic_monitor::increment_dns_queries() {
  // Atomic increment - no lock needed
  dns_query_count_.fetch_add(1);
}

size_t traffic_monitor::get_dns_query_count() const {
  // Atomic read - no lock needed
  return dns_query_count_.load();
}

void traffic_monitor::set_capture_mode(bool is_live,
                                       std::string_view interface_name) {
  // Set capture mode once during initialization
  is_live_capture_.store(is_live);
  auto lock = std::scoped_lock{mutex_};
  interface_name_ = interface_name;
}

void traffic_monitor::set_capture_time(double current_seconds) {
  // Atomic write - no lock needed
  current_packet_time_.store(current_seconds);
}

void traffic_monitor::set_last_packet_timestamp(time_t seconds,
                                                suseconds_t microseconds) {
  // Store actual wall-clock timestamp from PCAP header
  last_packet_timestamp_.store(seconds);
}

std::string traffic_monitor::get_time_display() const {
  // Get actual timestamp if available, otherwise fall back to elapsed time
  auto timestamp = last_packet_timestamp_.load();

  if (timestamp > 0) {
    // Format actual wall-clock time from PCAP
    auto tm_buf = std::tm{};
    auto time_val = timestamp;
    localtime_r(&time_val, &tm_buf);
    auto buffer = std::array<char, 64>{};
    std::strftime(buffer.data(), buffer.size(), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return buffer.data();
  }

  // Fallback: show elapsed time for live captures
  auto total_seconds = static_cast<int>(current_packet_time_.load());
  auto hours = total_seconds / 3600;
  auto minutes = (total_seconds % 3600) / 60;
  auto seconds = total_seconds % 60;
  return std::format("{:02d}:{:02d}:{:02d}", hours, minutes, seconds);
}

bool traffic_monitor::is_live() const {
  // Atomic read - no lock needed
  return is_live_capture_.load();
}

std::string traffic_monitor::get_interface_name() const {
  auto lock = std::scoped_lock{mutex_};
  return interface_name_;
}

std::vector<std::string> traffic_monitor::get_unresolved_ips() const {
  auto lock = std::scoped_lock{mutex_};
  auto unresolved = std::vector<std::string>{};

  // Collect unique IPs that don't have hostnames yet
  auto seen_ips = std::set<std::string>{};
  for (const auto &[key, ep] : endpoints_) {
    if (ep.hostname_.empty() && !seen_ips.contains(ep.ip_)) {
      unresolved.push_back(ep.ip_);
      seen_ips.insert(ep.ip_);
    }
  }

  return unresolved;
}

void traffic_monitor::update_hostname(std::string_view ip,
                                      std::string_view hostname) {
  auto lock = std::scoped_lock{mutex_};

  // Update all endpoints with this IP address
  for (auto &[key, ep] : endpoints_) {
    if (ep.ip_ == ip)
      ep.hostname_ = hostname;
  }
}

void traffic_monitor::set_status(std::string_view message) {
  auto lock = std::scoped_lock{mutex_};
  status_message_ = message;
}

std::string traffic_monitor::get_status() const {
  auto lock = std::scoped_lock{mutex_};
  return status_message_;
}

void traffic_monitor::wait_for_work(std::condition_variable &cv,
                                    std::mutex &cv_mutex) const {
  // Wait until notified or timeout after 1 second (allow quick shutdown)
  // Predicate ensures we only wake when there's actual work to do
  auto lock = std::unique_lock{cv_mutex};
  cv.wait_for(lock, std::chrono::seconds(1), [this] {
    // Only wake if there are unresolved IPs
    return !get_unresolved_ips().empty();
  });
}

void traffic_monitor::notify_new_endpoints(std::condition_variable &cv) {
  // No lock needed - just notify waiting threads
  cv.notify_one();
}

// renderer implementation
renderer::renderer(std::shared_ptr<traffic_monitor> store) : store_(store) {}

renderer::~renderer() { stop(); }

void renderer::start() {
  // Run render loop on main thread (blocks until user quits)
  auto start_time = std::chrono::steady_clock::now();
  try {
    render_loop();
  } catch (const std::exception &e) {
    // Log error and ensure clean termination
    std::print(stderr, "\nFatal error in render loop: {}\n", e.what());
  } catch (...) {
    std::print(stderr, "\nUnknown fatal error in render loop\n");
  }

  auto duration = std::chrono::steady_clock::now() - start_time;
  auto seconds =
      std::chrono::duration_cast<std::chrono::seconds>(duration).count();
  std::print(stderr, "Render loop exited after {}s\n", seconds);
}

void renderer::stop() {
  // Exit the screen loop if it's still active
  if (screen_.has_value()) {
    try {
      screen_->get().Exit();
    } catch (...) {
      // Suppress exceptions during shutdown
    }
  }
}

bool renderer::is_running() const {
  // Check if screen is active
  return screen_active_.load();
}

void renderer::set_status(std::string_view message) {
  auto lock = std::scoped_lock{status_mutex_};
  status_message_ = message;
}

void renderer::set_quit_callback(std::function<void()> callback) {
  auto lock = std::scoped_lock{
      status_mutex_}; // Protect against race with render thread
  quit_callback_ = std::move(callback);
}

void renderer::set_packet_processor(
    std::function<void(std::stop_token)> processor) {
  auto lock = std::scoped_lock{status_mutex_};
  packet_processor_ = std::move(processor);
}

void renderer::render_loop() {
  using namespace ftxui;

  auto screen = ScreenInteractive::Fullscreen();
  screen_ = std::ref(screen); // Store screen reference for cleanup
  screen_active_.store(true); // Mark screen as active

  // Mouse support disabled - using cursor keys for navigation

  // Start packet processing thread
  // This thread will populate the traffic_monitor while the main thread renders
  auto packet_thread = std::jthread{[this](std::stop_token st) {
    std::print(stderr, "Packet processing thread started\n");

    // Invoke the packet processor callback if set
    auto processor = std::function<void(std::stop_token)>{};
    {
      auto lock = std::scoped_lock{status_mutex_};
      processor = packet_processor_;
    }

    if (processor) {
      processor(st);
    } else {
      std::print(stderr, "Warning: No packet processor callback set\n");
    }

    std::print(stderr, "Packet processing thread exiting\n");
  }};

  // Component that renders the UI with forced animation refresh
  // Make component "animated" so FTXUI continuously calls render function
  auto last_packet_count = std::atomic<size_t>{0uz};
  auto force_refresh = std::atomic<bool>{true};

  // View mode: 0=endpoints, 1=packets, 2=hostnames (cycle through three views)
  auto view_mode = std::atomic<int>{0};

  // Pause state: when true, freeze display for easier copying
  auto is_paused = std::atomic<bool>{false};

  auto component = Renderer([this, &last_packet_count, &force_refresh,
                             &view_mode, &is_paused] {
    using namespace ftxui;

    // When paused, use cached data snapshot to freeze display
    static auto cached_endpoints = std::vector<endpoint_stats>{};
    static auto cached_packets = std::vector<packet_entry>{};
    static auto cached_total_packets = 0uz;
    static auto cached_time_display = std::string{};
    static auto cached_is_live = false;
    static auto cached_pps = 0.0;
    static auto cached_bps = 0.0;
    static auto cached_dns_queries = 0uz;

    // Get data from store (or use cached data if paused)
    auto paused = is_paused.load();
    auto endpoints = std::vector<endpoint_stats>{};
    auto packets = std::vector<packet_entry>{};
    auto total_packets = 0uz;
    auto time_display = std::string{};
    auto is_live = false;
    auto pps = 0.0;
    auto bps = 0.0;
    auto dns_queries = 0uz;

    if (paused) {
      // Use cached data when paused
      endpoints = cached_endpoints;
      packets = cached_packets;
      total_packets = cached_total_packets;
      time_display = cached_time_display;
      is_live = cached_is_live;
      pps = cached_pps;
      bps = cached_bps;
      dns_queries = cached_dns_queries;
    } else {
      // Fetch fresh data and update cache
      endpoints = store_->get_endpoints();
      packets = store_->get_recent_packets(50); // Last 50 packets
      total_packets = store_->get_total_packets();
      time_display = store_->get_time_display();
      is_live = store_->is_live();
      pps = store_->get_packets_per_second();
      bps = store_->get_bits_per_second();
      dns_queries = store_->get_dns_query_count();

      // Update cache for next pause
      cached_endpoints = endpoints;
      cached_packets = packets;
      cached_total_packets = total_packets;
      cached_time_display = time_display;
      cached_is_live = is_live;
      cached_pps = pps;
      cached_bps = bps;
      cached_dns_queries = dns_queries;
    }

    // Force component re-evaluation by checking if packet count changed
    auto current_count = total_packets;
    auto prev_count = last_packet_count.exchange(current_count);
    (void)prev_count; // Suppress unused warning

    // Build endpoint list (top pane)
    auto endpoint_elements = std::vector<Element>{};
    endpoint_elements.reserve(endpoints.size() + 1);

    // Calculate maximum address width for dynamic column sizing
    auto max_addr_width = 7uz; // Minimum for "Address" header
    for (const auto &ep : endpoints)
      max_addr_width = std::max(max_addr_width, ep.ip_.length());

    // Endpoint header with dynamic address column width
    endpoint_elements.push_back(
        text(std::format("{:<{}} {:17} {:20} {:<7} {}", "Address",
                         max_addr_width, "MAC", "Vendor", "Packets",
                         "Hostname")) |
        bold | color(Color::White));

    // Endpoint rows with vendor and IP version colourisation
    for (const auto &ep : endpoints) {
      // Format with dynamic address width
      auto ep_str = std::format(
          "{:<{}} {:17} {:20} {:<7} {}", ep.ip_.empty() ? "-" : ep.ip_,
          max_addr_width,
          ep.mac_address_.empty() ? "-" : ep.mac_address_.substr(0, 17),
          (ep.vendor_.empty() || ep.vendor_ == "-") ? "-"
                                                    : ep.vendor_.substr(0, 20),
          ep.packet_count_,
          (ep.hostname_.empty() || ep.hostname_ == ep.ip_) ? "-"
                                                           : ep.hostname_);
      auto ep_text = text(ep_str);

      // Detect IPv6 (contains ':') vs IPv4 (contains '.')
      auto is_ipv6 = ep.ip_.find(':') != std::string::npos;
      auto has_vendor = !ep.vendor_.empty() && ep.vendor_ != "-";

      if (has_vendor) {
        // Known vendors in bright cyan to stand out
        ep_text = ep_text | color(Color::Cyan);
      } else if (is_ipv6) {
        // IPv6 addresses in lighter colour
        ep_text = ep_text | color(Color::CyanLight);
      } else {
        // IPv4 addresses in standard colour
        ep_text = ep_text | color(Color::Green);
      }

      endpoint_elements.push_back(ep_text);
    }

    auto endpoint_pane = vbox(endpoint_elements) | ftxui::frame | flex;

    // Build packet list (bottom pane)
    auto packet_elements = std::vector<Element>{};
    packet_elements.reserve(packets.size() + 1);

    // Calculate dynamic column widths based on actual data
    auto max_src_width = 6uz;  // Minimum for "Source" header
    auto max_dst_width = 11uz; // Minimum for "Destination" header

    for (const auto &pkt : packets) {
      max_src_width = std::max(max_src_width, pkt.src_.length());
      max_dst_width = std::max(max_dst_width, pkt.dst_.length());
    }

    // Packet header with dynamic widths and separate transport/application
    // columns
    packet_elements.push_back(
        text(std::format("{:6} {:8} {:9} {:9} {:<{}} {:<{}} {:6}", "#", "Time",
                         "Transport", "App", "Source", max_src_width,
                         "Destination", max_dst_width, "Bytes")) |
        bold | color(Color::White));

    // Packet rows with dynamic widths and protocol colourisation
    for (const auto &pkt : packets) {
      auto time_str = std::format("{:.3f}", pkt.timestamp_);
      auto row = text(std::format("{:<6} {:>8} {:<9} {:<9} {:<{}} {:<{}} {:>6}",
                                  pkt.number_, time_str, pkt.transport_,
                                  pkt.application_, pkt.src_, max_src_width,
                                  pkt.dst_, max_dst_width, pkt.bytes_));

      // Detect IPv6 by checking if source contains multiple colons
      auto is_ipv6 = std::count(pkt.src_.begin(), pkt.src_.end(), ':') > 1;

      // Colourise by transport protocol and IP version
      if (is_ipv6) {
        // IPv6 packets in lighter colours
        if (pkt.transport_.starts_with("TCP"))
          row = row | color(Color::GreenLight);
        else if (pkt.transport_.starts_with("UDP"))
          row = row | color(Color::YellowLight);
        else
          row = row | color(Color::CyanLight);
      } else {
        // IPv4 packets in standard colours
        if (pkt.transport_.starts_with("TCP"))
          row = row | color(Color::Green);
        else if (pkt.transport_.starts_with("UDP"))
          row = row | color(Color::Yellow);
        else
          row = row | color(Color::White);
      }

      packet_elements.push_back(row);
    }

    auto packet_pane = vbox(packet_elements) | ftxui::frame | flex;

    // Title with mode indicator and spinner
    auto frame = spinner_frame_.load();
    auto spinner = std::string{SPINNER_FRAMES[frame]};
    spinner_frame_.store((frame + 1) % SPINNER_FRAMES.size());

    // Get interface name (live mode) or filename (replay mode)
    auto mode_str = std::string{};
    auto name = store_->get_interface_name();
    if (is_live) {
      mode_str = name.empty() ? "LIVE" : std::format("LIVE ({})", name);
    } else {
      mode_str = name.empty() ? "REPLAY" : std::format("REPLAY ({})", name);
    }

    // Format b/s with appropriate units (Kb/s, Mb/s, Gb/s)
    auto bps_str = std::string{};
    if (bps >= 1'000'000'000.0)
      bps_str = std::format("{:.2f} Gb/s", bps / 1'000'000'000.0);
    else if (bps >= 1'000'000.0)
      bps_str = std::format("{:.2f} Mb/s", bps / 1'000'000.0);
    else if (bps >= 1'000.0)
      bps_str = std::format("{:.2f} Kb/s", bps / 1'000.0);
    else
      bps_str = std::format("{:.0f} b/s", bps);

    // Determine current view name and pause indicator
    auto current_view = view_mode.load();
    auto view_name = current_view == 1   ? "PACKETS"
                     : current_view == 2 ? "HOSTNAMES"
                                         : "ENDPOINTS";

    // Use fixed-width formatting to reduce jumpiness
    // Consolidated header: title, help text, and view name on one line
    auto title_line = hbox({
        text(std::format("{} {:20} | {} | Packets: {:6} | {:6.1f} p/s | {:>11} "
                         "| DNS: {:3} | <>=view SPACE=pause q/ESC=quit",
                         spinner, mode_str, time_display, total_packets, pps,
                         bps_str, dns_queries)) |
            bold | color(Color::Cyan),
        filler(),
        text(std::format("{}{}", view_name, paused ? " [PAUSED]" : "")) | bold |
            color(paused ? Color::Red : Color::Yellow),
    });

    // Build hostname list (aggregated by hostname with packet counts)
    auto hostname_elements = std::vector<Element>{};

    // Aggregate endpoints by hostname
    auto hostname_map = std::map<std::string, size_t>{};
    for (const auto &ep : endpoints) {
      auto hostname = ep.hostname_.empty() || ep.hostname_ == ep.ip_
                          ? std::string{}
                          : ep.hostname_;
      if (!hostname.empty())
        hostname_map[hostname] += ep.packet_count_;
    }

    // Convert to vector and sort by packet count (descending)
    auto hostname_vec = std::vector<std::pair<std::string, size_t>>{
        hostname_map.begin(), hostname_map.end()};
    std::sort(hostname_vec.begin(), hostname_vec.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });

    // Add header
    hostname_elements.push_back(
        text(std::format("{:60} {:>10}", "Hostname", "Packets")) | bold |
        color(Color::White));

    // Add hostname rows with colour coding
    for (const auto &[hostname, count] : hostname_vec) {
      auto row =
          text(std::format("{:60} {:>10}", hostname.substr(0, 60), count));

      // Colour code by hostname type
      if (network_utils::is_local_hostname(hostname)) {
        // Local hostnames (*.local, *.lan, single-label) in cyan
        row = row | color(Color::Cyan);
      } else {
        // Remote/public hostnames in green
        row = row | color(Color::Green);
      }

      hostname_elements.push_back(row);
    }

    auto hostname_pane = vbox(hostname_elements) | ftxui::frame | flex;

    // Build base view
    auto base_view = Element{};
    if (current_view == 1) {
      // Packets view (full screen)
      base_view = vbox({title_line, separator(), packet_pane | flex});
    } else if (current_view == 2) {
      // Hostnames view (full screen)
      base_view = vbox({title_line, separator(), hostname_pane | flex});
    } else {
      // Endpoints view (full screen, default)
      base_view = vbox({title_line, separator(), endpoint_pane | flex});
    }

    // Add dramatic pause banner overlay when paused
    if (paused) {
      auto banner =
          vbox({
              filler(),
              hbox({filler(),
                    text("    P A U S E D    ") | bold | bgcolor(Color::Red) |
                        color(Color::White) | center,
                    filler()}),
              filler(),
          }) |
          flex;
      return dbox({base_view, banner});
    }

    return base_view;
  });

  // Capture component to handle keyboard shortcuts
  auto component_with_shortcuts = CatchEvent(
      component, [this, &screen, &view_mode, &is_paused](Event event) {
        // Left/Right arrows: switch between views
        if (event == Event::ArrowLeft) {
          auto current = view_mode.load();
          view_mode.store((current + 2) % 3); // Move backwards through views
          return true;
        }
        if (event == Event::ArrowRight) {
          auto current = view_mode.load();
          view_mode.store((current + 1) % 3); // Move forwards through views
          return true;
        }

        // Spacebar: toggle pause (freeze display for easier copying)
        if (event == Event::Character(' ')) {
          auto current = is_paused.load();
          is_paused.store(!current);
          return true;
        }

        // Quit shortcuts: q, Esc, Ctrl+C
        if (event == Event::Character('q') || event == Event::Escape ||
            (event.is_character() && event.character() == "c" &&
             event.input() == "\x03")) {
          screen.Exit();
          return true;
        }

        return false;
      });

  // Manual render loop - post events from main thread after each frame
  // This avoids threading bugs while still achieving auto-refresh
  auto loop = ftxui::Loop(&screen, component_with_shortcuts);

  while (!loop.HasQuitted()) {
    // Post event to queue for next iteration (safe - same thread)
    screen.Post(ftxui::Event::Custom);

    // Process the event we just posted (draws frame)
    loop.RunOnce();

    // Limit to ~2 FPS to reduce CPU usage
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  // Mark screen as inactive and clear reference to prevent refresh thread
  // access
  screen_active_.store(false);
  screen_.reset();

  set_status("Shutting down...");

  // Reset terminal to clean up any leftover escape codes
  std::print("\033[0m\033[?25h"); // Reset attributes and show cursor
}

} // namespace tui
