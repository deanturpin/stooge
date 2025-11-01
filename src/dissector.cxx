// Dissector runtime implementation
#include "dissector.hxx"
#include <print>

namespace dissector {

// Stub implementations of Wireshark Lua API functions that dissectors expect
// These provide minimal functionality to make dissectors loadable

// Proto() constructor stub - creates protocol object
static int lua_proto_new(lua_State *L) {
  // Get protocol name and description
  auto name = std::string{};
  auto desc = std::string{};

  if (lua_gettop(L) >= 1)
    name = luaL_checkstring(L, 1);
  if (lua_gettop(L) >= 2)
    desc = luaL_checkstring(L, 2);

  // Create a table to represent the protocol object
  lua_newtable(L);

  // Store protocol name and description
  lua_pushstring(L, name.c_str());
  lua_setfield(L, -2, "name");

  lua_pushstring(L, desc.c_str());
  lua_setfield(L, -2, "description");

  // Create empty fields table
  lua_newtable(L);
  lua_setfield(L, -2, "fields");

  return 1; // Return the protocol table
}

// ProtoField stubs - these just return dummy values since we're not building a
// full GUI
static int lua_protofield_string(lua_State *L) {
  lua_pushstring(L, "field");
  return 1;
}

static int lua_protofield_uint16(lua_State *L) {
  lua_pushstring(L, "field");
  return 1;
}

static int lua_protofield_uint8(lua_State *L) {
  lua_pushstring(L, "field");
  return 1;
}

// DissectorTable.get() stub
static int lua_dissectortable_get(lua_State *L) {
  // Create a dummy dissector table object
  lua_newtable(L);

  // Add :add() method that does nothing
  lua_pushstring(L, "add");
  lua_pushcfunction(L, [](lua_State *L) -> int {
    return 0; // Do nothing
  });
  lua_settable(L, -3);

  return 1;
}

// Register stub Wireshark API
static void register_wireshark_api(lua_State *L) {
  // Register Proto constructor
  lua_pushcfunction(L, lua_proto_new);
  lua_setglobal(L, "Proto");

  // Register ProtoField table
  lua_newtable(L);
  lua_pushcfunction(L, lua_protofield_string);
  lua_setfield(L, -2, "string");
  lua_pushcfunction(L, lua_protofield_uint16);
  lua_setfield(L, -2, "uint16");
  lua_pushcfunction(L, lua_protofield_uint8);
  lua_setfield(L, -2, "uint8");
  lua_setglobal(L, "ProtoField");

  // Register DissectorTable
  lua_newtable(L);
  lua_pushcfunction(L, lua_dissectortable_get);
  lua_setfield(L, -2, "get");
  lua_setglobal(L, "DissectorTable");

  // Register base table for ProtoField types
  lua_newtable(L);
  lua_pushnumber(L, 0);
  lua_setfield(L, -2, "DEC");
  lua_pushnumber(L, 1);
  lua_setfield(L, -2, "HEX");
  lua_setglobal(L, "base");
}

runtime::runtime() {
  L = luaL_newstate();
  if (!L) {
    std::print("Failed to create Lua state\n");
    return;
  }

  // Open standard libraries
  luaL_openlibs(L);

  // Register Wireshark API stubs
  register_wireshark_api(L);
}

runtime::~runtime() {
  if (L)
    lua_close(L);
}

bool runtime::load(const std::string &filepath) {
  if (!L)
    return false;

  // Load and execute the Lua dissector script
  if (luaL_dofile(L, filepath.c_str()) != LUA_OK) {
    auto error = std::string{lua_tostring(L, -1)};
    std::print("Error loading dissector {}: {}\n", filepath, error);
    lua_pop(L, 1);
    return false;
  }

  return true;
}

std::optional<result> runtime::dissect(const uint8_t *payload, size_t length,
                                       uint16_t src_port, uint16_t dst_port,
                                       const std::string &protocol) {
  // For now, just return empty result
  // Full implementation would call dissector.dissector() function
  // and extract protocol info from the tree
  return std::nullopt;
}

} // namespace dissector
