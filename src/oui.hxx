// MAC address vendor lookup using IEEE OUI database
#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace oui {

// Look up vendor name from MAC address
// Returns vendor name or empty string if not found
std::string lookup_vendor(const std::array<uint8_t, 6> &mac);

// Look up vendor name from MAC address string (e.g., "00:11:22:33:44:55")
std::string lookup_vendor(const std::string &mac_str);

} // namespace oui
