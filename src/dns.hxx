// DNS reverse lookup with caching
#pragma once

#include <string>

namespace dns {
// Perform reverse DNS lookup for an IP address
// Returns hostname if found, empty string if lookup fails
// Results are cached for performance
std::string reverse_lookup(const std::string &ip);
} // namespace dns
