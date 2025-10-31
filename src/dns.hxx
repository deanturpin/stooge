#pragma once

#include <map>
#include <string>

namespace dns {
std::string reverse_lookup(const std::string &ip);
std::map<std::string, std::string> get_cache();
} // namespace dns
