// Network utility functions for IP address and hostname classification
#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace network_utils {

namespace detail {
// Constexpr ASCII digit check
constexpr bool is_digit(char c) { return c >= '0' && c <= '9'; }

// Parse an IPv4 octet from string (constexpr helper)
constexpr int parse_octet(std::string_view str, size_t &pos) {
  auto result = 0;
  while (pos < str.length() && is_digit(str[pos])) {
    result = result * 10 + (str[pos] - '0');
    pos++;
  }
  return result;
}

// Count dots in a string (constexpr helper)
constexpr size_t count_dots(std::string_view str) {
  auto count = 0uz;
  for (auto c : str)
    if (c == '.')
      count++;
  return count;
}

// Check if string ends with suffix (constexpr helper)
constexpr bool ends_with(std::string_view str, std::string_view suffix) {
  if (suffix.length() > str.length())
    return false;
  return str.substr(str.length() - suffix.length()) == suffix;
}

// Constexpr ASCII lowercase conversion
constexpr char to_lower_ascii(char c) {
  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

// Case-insensitive string comparison (constexpr helper, ASCII only)
constexpr bool iequals(std::string_view a, std::string_view b) {
  if (a.length() != b.length())
    return false;
  for (auto i = 0uz; i < a.length(); i++)
    if (to_lower_ascii(a[i]) != to_lower_ascii(b[i]))
      return false;
  return true;
}
} // namespace detail

// Check if an IPv4 address (as 4 octets) is in a private range
constexpr bool is_private_ipv4(const std::array<uint8_t, 4> &octets) {
  // 10.0.0.0/8 (Class A private)
  if (octets[0] == 10)
    return true;

  // 172.16.0.0/12 (Class B private)
  if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
    return true;

  // 192.168.0.0/16 (Class C private)
  if (octets[0] == 192 && octets[1] == 168)
    return true;

  // 127.0.0.0/8 (Loopback)
  if (octets[0] == 127)
    return true;

  // 169.254.0.0/16 (Link-local/APIPA)
  if (octets[0] == 169 && octets[1] == 254)
    return true;

  return false;
}

// Check if an IPv4 address is in a private range (RFC 1918)
// Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
// Also includes: 127.0.0.0/8 (loopback), 169.254.0.0/16 (link-local)
constexpr bool is_private_ipv4(std::string_view ip) {
  // Parse octets from dotted-decimal notation
  if (detail::count_dots(ip) != 3)
    return false;

  auto octets = std::array<uint8_t, 4>{};
  auto pos = 0uz;

  for (auto i = 0uz; i < 4; i++) {
    auto octet = detail::parse_octet(ip, pos);
    if (octet < 0 || octet > 255)
      return false;
    octets[i] = static_cast<uint8_t>(octet);
    if (i < 3) {
      if (pos >= ip.length() || ip[pos] != '.')
        return false;
      pos++; // Skip dot
    }
  }

  return is_private_ipv4(octets);
}

// Check if a hostname appears to be local/internal
// Returns true for:
// - .local domains (mDNS/Bonjour)
// - .lan domains
// - Single-label hostnames (no dots)
// - localhost variations
constexpr bool is_local_hostname(std::string_view hostname) {
  if (hostname.empty())
    return false;

  // localhost and variations
  if (detail::iequals(hostname, "localhost"))
    return true;
  if (detail::ends_with(hostname, ".localhost"))
    return true;

  // .local domain (mDNS/Bonjour)
  if (detail::ends_with(hostname, ".local"))
    return true;

  // .lan domain
  if (detail::ends_with(hostname, ".lan"))
    return true;

  // Single-label hostname (no dots) - typically local
  if (detail::count_dots(hostname) == 0)
    return true;

  return false;
}

} // namespace network_utils
