// Dissector runtime - loads and executes Wireshark-compatible Lua dissectors
#pragma once

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace dissector {

// Dissected protocol information returned from dissector
struct result {
  std::string protocol_;
  std::string info_; // Summary line for display
};

// Runtime for executing protocol dissectors
class runtime {
private:
  lua_State *L_ = nullptr;

public:
  runtime();
  ~runtime();

  // Load a dissector script from file
  bool load(std::string_view filepath);

  // Execute dissector on packet payload
  // Returns protocol info if dissector succeeds, nullopt otherwise
  std::optional<result> dissect(const uint8_t *payload, size_t length,
                                uint16_t src_port, uint16_t dst_port,
                                std::string_view protocol);
};

} // namespace dissector
