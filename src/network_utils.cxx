// Network utility function implementations
#include "network_utils.hxx"
#include <algorithm>
#include <cctype>

namespace network_utils {

namespace {
// Parse an IPv4 octet from string (constexpr helper)
constexpr int parse_octet(std::string_view str, size_t &pos) {
  auto result = 0;
  while (pos < str.length() && std::isdigit(str[pos])) {
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

// Case-insensitive string comparison (constexpr helper)
constexpr bool iequals(std::string_view a, std::string_view b) {
  if (a.length() != b.length())
    return false;
  for (auto i = 0uz; i < a.length(); i++)
    if (std::tolower(a[i]) != std::tolower(b[i]))
      return false;
  return true;
}
} // anonymous namespace

constexpr bool is_private_ipv4(std::string_view ip) {
  // Parse octets from dotted-decimal notation
  if (count_dots(ip) != 3)
    return false;

  auto octets = std::array<uint8_t, 4>{};
  auto pos = 0uz;

  for (auto i = 0uz; i < 4; i++) {
    auto octet = parse_octet(ip, pos);
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

constexpr bool is_local_hostname(std::string_view hostname) {
  if (hostname.empty())
    return false;

  // localhost and variations
  if (iequals(hostname, "localhost"))
    return true;
  if (ends_with(hostname, ".localhost"))
    return true;

  // .local domain (mDNS/Bonjour)
  if (ends_with(hostname, ".local"))
    return true;

  // .lan domain
  if (ends_with(hostname, ".lan"))
    return true;

  // Single-label hostname (no dots) - typically local
  if (count_dots(hostname) == 0)
    return true;

  return false;
}

// Compile-time unit tests for private IP detection
static_assert(is_private_ipv4("10.0.0.1"), "10.0.0.1 is private");
static_assert(is_private_ipv4("10.255.255.255"), "10.255.255.255 is private");
static_assert(is_private_ipv4("172.16.0.1"), "172.16.0.1 is private");
static_assert(is_private_ipv4("172.31.255.255"), "172.31.255.255 is private");
static_assert(is_private_ipv4("192.168.0.1"), "192.168.0.1 is private");
static_assert(is_private_ipv4("192.168.255.255"), "192.168.255.255 is private");
static_assert(is_private_ipv4("127.0.0.1"), "127.0.0.1 is loopback");
static_assert(is_private_ipv4("127.255.255.255"),
              "127.255.255.255 is loopback");
static_assert(is_private_ipv4("169.254.1.1"), "169.254.1.1 is link-local");
static_assert(!is_private_ipv4("8.8.8.8"), "8.8.8.8 is public");
static_assert(!is_private_ipv4("1.1.1.1"), "1.1.1.1 is public");
static_assert(!is_private_ipv4("172.15.255.255"), "172.15.x.x is public");
static_assert(!is_private_ipv4("172.32.0.0"), "172.32.x.x is public");
static_assert(!is_private_ipv4("192.167.1.1"), "192.167.x.x is public");
static_assert(!is_private_ipv4("11.0.0.1"), "11.x.x.x is public");

// Compile-time unit tests for octet array version
static_assert(is_private_ipv4(std::array<uint8_t, 4>{10, 0, 0, 1}),
              "10.0.0.1 is private");
static_assert(is_private_ipv4(std::array<uint8_t, 4>{172, 16, 0, 1}),
              "172.16.0.1 is private");
static_assert(is_private_ipv4(std::array<uint8_t, 4>{192, 168, 1, 1}),
              "192.168.1.1 is private");
static_assert(!is_private_ipv4(std::array<uint8_t, 4>{8, 8, 8, 8}),
              "8.8.8.8 is public");

// Compile-time unit tests for hostname classification
static_assert(is_local_hostname("localhost"), "localhost is local");
static_assert(is_local_hostname("foo.localhost"), "foo.localhost is local");
static_assert(is_local_hostname("myhost.local"), "myhost.local is local");
static_assert(is_local_hostname("router.lan"), "router.lan is local");
static_assert(is_local_hostname("mycomputer"),
              "Single-label hostname is local");
static_assert(!is_local_hostname("google.com"), "google.com is not local");
static_assert(!is_local_hostname("api.example.org"),
              "api.example.org is not local");
static_assert(!is_local_hostname(""), "Empty string is not local");

} // namespace network_utils
