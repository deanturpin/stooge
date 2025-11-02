// MAC address vendor lookup implementation
#include "oui.hxx"
#include <fstream>
#include <map>
#include <mutex>
#include <print>
#include <sstream>

namespace oui {

namespace {
// Cached OUI database
std::map<std::string, std::string> oui_db;
std::mutex oui_mutex;
bool loaded = false;

// Load OUI database from file
void load_database() {
  auto lock = std::lock_guard{oui_mutex};
  if (loaded)
    return;

  auto file = std::ifstream{"/usr/share/oui.txt"};
  if (!file.is_open()) {
    // Database file not found (don't print - TUI might be active)
    loaded = true;
    return;
  }

  auto line = std::string{};
  while (std::getline(file, line)) {
    // OUI format: "00-11-22   (hex)		Vendor Name"
    if (line.length() < 22 || line.find("(hex)") == std::string::npos)
      continue;

    // Extract OUI (first 8 chars, e.g., "00-11-22")
    auto oui = line.substr(0, 8);

    // Extract vendor name (after "(hex)" and tabs)
    auto hex_pos = line.find("(hex)");
    if (hex_pos == std::string::npos)
      continue;

    auto vendor_start = hex_pos + 5;
    while (vendor_start < line.length() &&
           (line[vendor_start] == ' ' || line[vendor_start] == '\t'))
      vendor_start++;

    if (vendor_start < line.length()) {
      auto vendor = line.substr(vendor_start);

      // Strip trailing whitespace (including \r from Windows line endings)
      while (!vendor.empty() &&
             (vendor.back() == ' ' || vendor.back() == '\t' ||
              vendor.back() == '\r' || vendor.back() == '\n'))
        vendor.pop_back();

      // Convert OUI to uppercase and remove dashes
      auto oui_key = std::string{};
      for (auto c : oui) {
        if (c != '-')
          oui_key += std::toupper(c);
      }
      oui_db[oui_key] = vendor;
    }
  }

  // Database loaded successfully (don't print - TUI might be active)
  loaded = true;
}
} // anonymous namespace

std::string lookup_vendor(const std::array<uint8_t, 6> &mac) {
  if (!loaded)
    load_database();

  // Build OUI key from first 3 bytes
  auto oui_key = std::format("{:02X}{:02X}{:02X}", mac[0], mac[1], mac[2]);

  auto lock = std::lock_guard{oui_mutex};
  if (auto it = oui_db.find(oui_key); it != oui_db.end())
    return it->second;

  return {};
}

std::string lookup_vendor(const std::string &mac_str) {
  // Parse MAC address string (supports "00:11:22:33:44:55" or
  // "00-11-22-33-44-55")
  auto mac = std::array<uint8_t, 6>{};
  auto ss = std::istringstream{mac_str};
  auto byte_str = std::string{};
  auto idx = 0;

  while (std::getline(ss, byte_str, mac_str.find(':') != std::string::npos ? ':' : '-') &&
         idx < 6) {
    mac[idx++] = std::stoi(byte_str, nullptr, 16);
  }

  if (idx != 6)
    return {};

  return lookup_vendor(mac);
}

} // namespace oui
