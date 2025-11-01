// Dissector runtime implementation
#include "dissector.hxx"
#include <cstring>
#include <print>

namespace dissector {

// Buffer wrapper for Lua - holds packet data
struct buffer_wrapper {
  const uint8_t *data;
  size_t length;
};

// Packet info captured by dissector
struct pinfo_data {
  std::string protocol;
  std::string info;
};

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

// Buffer metatable methods
static int buffer_len(lua_State *L) {
  auto buf = static_cast<buffer_wrapper *>(lua_touserdata(L, 1));
  lua_pushinteger(L, buf->length);
  return 1;
}

static int buffer_call(lua_State *L) {
  auto buf = static_cast<buffer_wrapper *>(lua_touserdata(L, 1));
  // buffer() returns entire buffer, buffer(offset, length) returns substring
  // For simplicity, just return a new buffer userdata
  auto newbuf =
      static_cast<buffer_wrapper *>(lua_newuserdata(L, sizeof(buffer_wrapper)));
  newbuf->data = buf->data;
  newbuf->length = buf->length;

  // Add metatable with __tostring method
  lua_newtable(L);
  lua_pushcfunction(L, [](lua_State *L) -> int {
    auto b = static_cast<buffer_wrapper *>(lua_touserdata(L, 1));
    lua_pushlstring(L, reinterpret_cast<const char *>(b->data), b->length);
    return 1;
  });
  lua_setfield(L, -2, "string");
  lua_setmetatable(L, -2);

  return 1;
}

std::optional<result> runtime::dissect(const uint8_t *payload, size_t length,
                                       uint16_t src_port, uint16_t dst_port,
                                       const std::string &protocol) {
  if (!L || length == 0)
    return std::nullopt;

  // Try HTTP dissector for port 80, 8080, 443
  auto proto_name = std::string{};
  if (protocol == "TCP" && (dst_port == 80 || dst_port == 8080 ||
                            src_port == 80 || src_port == 8080))
    proto_name = "http_custom";
  else if (protocol == "UDP" && (dst_port == 53 || src_port == 53))
    proto_name = "dns_custom";
  else
    return std::nullopt;

  // Get the protocol object
  lua_getglobal(L, proto_name.c_str());
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    return std::nullopt;
  }

  // Get the dissector function
  lua_getfield(L, -1, "dissector");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 2);
    return std::nullopt;
  }

  // Create buffer userdata
  auto buf =
      static_cast<buffer_wrapper *>(lua_newuserdata(L, sizeof(buffer_wrapper)));
  buf->data = payload;
  buf->length = length;

  // Set buffer metatable
  lua_newtable(L);
  lua_pushcfunction(L, buffer_len);
  lua_setfield(L, -2, "len");
  lua_pushcfunction(L, buffer_call);
  lua_setfield(L, -2, "__call");
  lua_setmetatable(L, -2);

  // Create pinfo table
  lua_newtable(L);
  lua_newtable(L); // pinfo.cols
  lua_setfield(L, -2, "cols");

  // Create tree table (dummy)
  lua_newtable(L);
  lua_pushcfunction(L, [](lua_State *L) -> int {
    // tree:add() just returns another tree
    lua_newtable(L);
    return 1;
  });
  lua_setfield(L, -2, "add");

  // Call dissector function: dissector(buffer, pinfo, tree)
  if (lua_pcall(L, 3, 0, 0) != LUA_OK) {
    auto error = std::string{lua_tostring(L, -1)};
    std::print("Dissector error: {}\n", error);
    lua_pop(L, 2); // Pop error and proto
    return std::nullopt;
  }

  lua_pop(L, 1); // Pop proto

  // For now, return simple result
  auto res = result{};
  res.protocol = proto_name;
  res.info = "Dissected";
  return res;
}

} // namespace dissector
