// MAC address vendor lookup implementation
#include "oui.hxx"
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>

namespace oui {

namespace {
// Constexpr MAC address and OUI validation helpers
constexpr bool is_valid_oui_length(std::string_view oui) {
  return oui.length() == 6; // "001122" format
}

constexpr bool is_hex_digit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
         (c >= 'a' && c <= 'f');
}

constexpr bool is_valid_oui_key(std::string_view oui) {
  if (!is_valid_oui_length(oui))
    return false;

  for (auto c : oui)
    if (!is_hex_digit(c))
      return false;

  return true;
}

constexpr bool is_valid_mac_array_size(size_t size) { return size == 6; }

// Compile-time unit tests for OUI and MAC validation
static_assert(is_valid_oui_length("001122"), "Valid OUI length");
static_assert(!is_valid_oui_length("00112"), "Invalid OUI length (too short)");
static_assert(!is_valid_oui_length("0011223"), "Invalid OUI length (too long)");
static_assert(is_hex_digit('0'), "0 is hex digit");
static_assert(is_hex_digit('9'), "9 is hex digit");
static_assert(is_hex_digit('A'), "A is hex digit");
static_assert(is_hex_digit('F'), "F is hex digit");
static_assert(is_hex_digit('a'), "a is hex digit");
static_assert(is_hex_digit('f'), "f is hex digit");
static_assert(!is_hex_digit('G'), "G is not hex digit");
static_assert(!is_hex_digit('Z'), "Z is not hex digit");
static_assert(!is_hex_digit(' '), "Space is not hex digit");
static_assert(is_valid_oui_key("001122"), "Valid OUI key format");
static_assert(is_valid_oui_key("AABBCC"), "Valid uppercase OUI key");
static_assert(is_valid_oui_key("aabbcc"), "Valid lowercase OUI key");
static_assert(!is_valid_oui_key("00112G"), "Invalid hex character G");
static_assert(!is_valid_oui_key("00112"), "Invalid OUI key (too short)");
static_assert(is_valid_mac_array_size(6), "MAC address must be 6 bytes");
static_assert(!is_valid_mac_array_size(5), "5 bytes is not a valid MAC");
static_assert(!is_valid_mac_array_size(7), "7 bytes is not a valid MAC");

// Cached OUI database
std::map<std::string, std::string> oui_db;
std::mutex oui_mutex;
bool loaded = false;

// Load OUI database from file
void load_database() {
  auto lock = std::lock_guard{oui_mutex};
  if (loaded)
    return;

  auto file = std::ifstream{"/usr/share/ieee-data/oui.txt"};
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

std::string lookup_vendor(std::string_view mac_str) {
  // Parse MAC address string (supports "00:11:22:33:44:55" or
  // "00-11-22-33-44-55")
  auto mac = std::array<uint8_t, 6>{};
  auto ss = std::istringstream{std::string{mac_str}};
  auto byte_str = std::string{};
  auto idx = 0;

  while (
      std::getline(ss, byte_str,
                   mac_str.find(':') != std::string_view::npos ? ':' : '-') &&
      idx < 6) {
    mac[idx++] = std::stoi(byte_str, nullptr, 16);
  }

  if (idx != 6)
    return {};

  return lookup_vendor(mac);
}

} // namespace oui
