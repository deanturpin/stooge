// Network utility functions for IP address and hostname classification
#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace network_utils {

// Check if an IPv4 address is in a private range (RFC 1918)
// Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
// Also includes: 127.0.0.0/8 (loopback), 169.254.0.0/16 (link-local)
constexpr bool is_private_ipv4(std::string_view ip);

// Check if an IPv4 address (as 4 octets) is in a private range
constexpr bool is_private_ipv4(const std::array<uint8_t, 4> &octets);

// Check if a hostname appears to be local/internal
// Returns true for:
// - .local domains (mDNS/Bonjour)
// - .lan domains
// - Single-label hostnames (no dots)
// - localhost variations
constexpr bool is_local_hostname(std::string_view hostname);

} // namespace network_utils
