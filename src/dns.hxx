// DNS reverse lookup with caching and async resolution
#pragma once

#include <string>

namespace dns {
// Perform reverse DNS lookup for an IP address
// Returns hostname if found, empty string if lookup fails or not yet resolved
// Automatically starts background resolution on first lookup
std::string reverse_lookup(const std::string &ip);

// Wait for all background DNS lookups to complete
void wait_for_resolution();
} // namespace dns
