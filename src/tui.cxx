// Terminal UI implementation
#include "tui.hxx"
#include <algorithm>
#include <format>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <thread>

namespace tui {

std::string endpoint_stats::to_string() const {
  auto port_str = port > 0 ? std::format(":{}", port) : "";
  auto host_str =
      !hostname.empty() && hostname != ip ? std::format(" ({})", hostname) : "";
  auto vendor_str = !vendor.empty() ? std::format(" [{}]", vendor) : "";
  auto mac_str = !mac_address.empty() ? std::format(" MAC:{}", mac_address) : "";
  return std::format("{}{} [{}]{}{}{} - {} pkts", ip, port_str, protocol,
                     host_str, vendor_str, mac_str, packet_count);
}

// data_store implementation
void data_store::add_endpoint(const std::string &ip, uint16_t port,
                               const std::string &protocol,
                               const std::string &hostname,
                               const std::string &vendor,
                               const std::string &mac_address) {
  auto lock = std::lock_guard{mutex_};
  auto key = std::format("{}:{}:{}", ip, port, protocol);

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
  auto lock = std::lock_guard{mutex_};
  packets_.push_back(entry);
  if (packets_.size() > MAX_PACKETS)
    packets_.pop_front();
  total_packets_++;
}

std::vector<endpoint_stats> data_store::get_endpoints() const {
  auto lock = std::lock_guard{mutex_};
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
  auto lock = std::lock_guard{mutex_};
  auto result = std::vector<packet_entry>{};

  auto start = packets_.size() > count ? packets_.size() - count : 0;
  for (size_t i = start; i < packets_.size(); i++)
    result.push_back(packets_[i]);

  return result;
}

size_t data_store::get_total_packets() const {
  auto lock = std::lock_guard{mutex_};
  return total_packets_;
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
  if (!running_)
    return;

  running_ = false;
  if (render_thread_ && render_thread_->joinable())
    render_thread_->join();
}

bool renderer::is_running() const { return running_; }

void renderer::render_loop() {
  using namespace ftxui;

  auto screen = ScreenInteractive::Fullscreen();

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
    auto status_text = paused_ ? "PAUSED" : std::format("Total: {}", total);
    packet_elements.push_back(text(std::format("Live Packets ({})", status_text)) |
                              bold | color(paused_ ? Color::Red : Color::Cyan));
    packet_elements.push_back(separator());

    for (const auto &pkt : packets) {
      auto pkt_line = text(std::format("[{:6d}] {} {} → {} ({} bytes)",
                                       pkt.number, pkt.protocol, pkt.src,
                                       pkt.dst, pkt.bytes));

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

    // Status bar with shortcuts hint
    auto status_bar =
        hbox({text("Shortcuts: ") | dim, text("q") | bold, text("/Esc=Quit ") | dim,
              text("p") | bold, text("=Pause ") | dim, text("h") | bold,
              text("/?=Help") | dim}) |
        bgcolor(Color::GrayDark);

    // Combine panes horizontally with status bar
    return vbox({hbox({endpoint_pane, separator(), packet_pane}) | border | flex,
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
    while (running_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (!paused_)
        screen.PostEvent(Event::Custom);
    }
  });

  screen.Loop(component_with_shortcuts);
  refresh_thread.join();
}

} // namespace tui
