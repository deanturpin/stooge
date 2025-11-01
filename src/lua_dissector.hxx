// Lua dissector runtime - loads and executes Wireshark-compatible Lua
// dissectors
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

namespace lua_dissector {

// Dissected protocol information returned from Lua dissector
struct DissectorResult {
  std::string protocol;
  std::string info; // Summary line for display
};

// Lua runtime for executing protocol dissectors
class Runtime {
private:
  lua_State *L = nullptr;

public:
  Runtime();
  ~Runtime();

  // Load a Lua dissector script from file
  bool load_dissector(const std::string &filepath);

  // Execute dissector on packet payload
  // Returns protocol info if dissector succeeds, nullopt otherwise
  std::optional<DissectorResult> dissect(const uint8_t *payload, size_t length,
                                         uint16_t src_port, uint16_t dst_port,
                                         const std::string &protocol);
};

} // namespace lua_dissector
