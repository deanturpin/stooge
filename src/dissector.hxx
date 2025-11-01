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
#include <vector>

namespace dissector {

// Dissected protocol information returned from dissector
struct result {
  std::string protocol;
  std::string info; // Summary line for display
};

// Runtime for executing protocol dissectors
class runtime {
private:
  lua_State *L = nullptr;

public:
  runtime();
  ~runtime();

  // Load a dissector script from file
  bool load(const std::string &filepath);

  // Execute dissector on packet payload
  // Returns protocol info if dissector succeeds, nullopt otherwise
  std::optional<result> dissect(const uint8_t *payload, size_t length,
                                uint16_t src_port, uint16_t dst_port,
                                const std::string &protocol);
};

} // namespace dissector
