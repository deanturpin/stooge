// Dissector runtime implementation
#include "dissector.hxx"
#include <print>

extern "C" {
#include <lauxlib.h>
#include <lualib.h>
}

namespace dissector {

// Buffer wrapper for Lua - holds packet data
struct buffer_wrapper {
  const uint8_t *data_;
  size_t length_;
};

// Packet info captured by dissector
struct pinfo_data {
  std::string protocol_;
  std::string info_;
};

// Stub implementations of Wireshark Lua API functions that dissectors expect
// These provide minimal functionality to make dissectors loadable
//
// Note: All Lua C API functions must return int to indicate how many values
// were pushed onto the Lua stack. They cannot be void even if they do nothing.

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

// ProtoField stubs - return placeholder values for GUI field definitions
// The return value indicates 1 item pushed to Lua stack
static int lua_protofield_string(lua_State *L) {
  lua_pushstring(L, "field");
  return 1; // Tells Lua we pushed 1 value
}

static int lua_protofield_uint16(lua_State *L) {
  lua_pushstring(L, "field");
  return 1; // Tells Lua we pushed 1 value
}

static int lua_protofield_uint8(lua_State *L) {
  lua_pushstring(L, "field");
  return 1; // Tells Lua we pushed 1 value
}

// DissectorTable.get() stub
static int lua_dissectortable_get(lua_State *L) {
  // Create a dummy dissector table object
  lua_newtable(L);

  // Add :add() method that does nothing
  lua_pushstring(L, "add");
  lua_pushcfunction(L, [](lua_State *L) -> int {
    return 0; // Return 0 = pushed nothing to stack
  });
  lua_settable(L, -3);

  return 1; // Return the dissector table
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
  L_ = luaL_newstate();
  if (L_ == nullptr) {
    std::print("Failed to create Lua state\n");
    return;
  }

  // Open standard libraries
  luaL_openlibs(L_);

  // Register bit32 stubs (Lua 5.4 removed bit32, provide minimal
  // implementation)
  lua_newtable(L_);
  lua_pushcfunction(L_, [](lua_State *L) -> int {
    auto val = luaL_checkinteger(L, 1);
    auto shift = luaL_checkinteger(L, 2);
    lua_pushinteger(L, val >> shift);
    return 1; // Pushed result to stack
  });
  lua_setfield(L_, -2, "rshift");
  lua_pushcfunction(L_, [](lua_State *L) -> int {
    auto val1 = luaL_checkinteger(L, 1);
    auto val2 = luaL_checkinteger(L, 2);
    lua_pushinteger(L, val1 & val2);
    return 1; // Pushed result to stack
  });
  lua_setfield(L_, -2, "band");
  lua_setglobal(L_, "bit32");

  // Register Wireshark API stubs
  register_wireshark_api(L_);
}

runtime::~runtime() {
  if (L_ != nullptr)
    lua_close(L_);
}

bool runtime::load(std::string_view filepath) {
  if (L_ == nullptr)
    return false;

  // Load and execute the Lua dissector script
  if (luaL_dofile(L_, std::string{filepath}.c_str()) != LUA_OK) {
    auto error = std::string{lua_tostring(L_, -1)};
    std::print("Error loading dissector {}: {}\n", filepath, error);
    lua_pop(L_, 1);
    return false;
  }

  return true;
}

// Buffer metatable methods - all must return int for Lua C API
static int buffer_len(lua_State *L) {
  auto buf = static_cast<buffer_wrapper *>(lua_touserdata(L, 1));
  lua_pushinteger(L, buf->length_);
  return 1; // Pushed length to stack
}

// Buffer slice uint() method
static int buffer_uint(lua_State *L) {
  auto buf = static_cast<buffer_wrapper *>(lua_touserdata(L, 1));
  if (buf->length_ == 1uz) {
    lua_pushinteger(L, buf->data_[0]);
  } else if (buf->length_ == 2uz) {
    uint16_t val = (buf->data_[0] << 8) | buf->data_[1]; // Big-endian
    lua_pushinteger(L, val);
  } else if (buf->length_ == 4uz) {
    uint32_t val = (buf->data_[0] << 24) | (buf->data_[1] << 16) |
                   (buf->data_[2] << 8) | buf->data_[3];
    lua_pushinteger(L, val);
  } else {
    return luaL_error(L, "uint() only supports 1, 2, or 4 byte buffers");
  }
  return 1; // Pushed uint value to stack
}

// Buffer slice string() method
static int buffer_string(lua_State *L) {
  auto buf = static_cast<buffer_wrapper *>(lua_touserdata(L, 1));
  lua_pushlstring(L, reinterpret_cast<const char *>(buf->data_), buf->length_);
  return 1; // Pushed string to stack
}

static int buffer_call(lua_State *L) {
  auto buf = static_cast<buffer_wrapper *>(lua_touserdata(L, 1));

  // Get offset and length parameters
  auto offset = 0;
  auto length = buf->length_;
  if (lua_gettop(L) >= 2) {
    offset = luaL_checkinteger(L, 2);
  }
  if (lua_gettop(L) >= 3) {
    length = luaL_checkinteger(L, 3);
  }

  // Bounds check
  if (offset < 0 || offset >= static_cast<int>(buf->length_)) {
    return luaL_error(L, "buffer offset out of range");
  }
  if (offset + length > buf->length_) {
    length = buf->length_ - offset;
  }

  // Create new buffer slice
  auto newbuf =
      static_cast<buffer_wrapper *>(lua_newuserdata(L, sizeof(buffer_wrapper)));
  newbuf->data_ = buf->data_ + offset;
  newbuf->length_ = length;

  // Set metatable with methods
  lua_newtable(L); // metatable
  lua_newtable(L); // methods table
  lua_pushcfunction(L, buffer_len);
  lua_setfield(L, -2, "len");
  lua_pushcfunction(L, buffer_uint);
  lua_setfield(L, -2, "uint");
  lua_pushcfunction(L, buffer_string);
  lua_setfield(L, -2, "string");
  lua_setfield(L, -2, "__index");
  lua_setmetatable(L, -2);

  return 1; // Pushed new buffer slice to stack
}

std::optional<result> runtime::dissect(const uint8_t *payload, size_t length,
                                       uint16_t src_port, uint16_t dst_port,
                                       std::string_view protocol) {
  if (L_ == nullptr)
    return std::nullopt;

  if (length == 0uz)
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
  lua_getglobal(L_, proto_name.c_str());
  if (!lua_istable(L_, -1)) {
    lua_pop(L_, 1);
    return std::nullopt;
  }

  // Get the dissector function
  lua_getfield(L_, -1, "dissector");
  if (!lua_isfunction(L_, -1)) {
    lua_pop(L_, 2);
    return std::nullopt;
  }

  // Create buffer userdata
  auto buf = static_cast<buffer_wrapper *>(
      lua_newuserdata(L_, sizeof(buffer_wrapper)));
  buf->data_ = payload;
  buf->length_ = length;

  // Set buffer metatable
  lua_newtable(L_); // metatable

  // Create methods table for __index
  lua_newtable(L_); // methods table
  lua_pushcfunction(L_, buffer_len);
  lua_setfield(L_, -2, "len");
  lua_setfield(L_, -2, "__index"); // metatable.__index = methods

  lua_pushcfunction(L_, buffer_call);
  lua_setfield(L_, -2, "__call");

  lua_setmetatable(L_, -2);

  // Create pinfo table with cols.info tracking
  lua_newtable(L_); // pinfo table
  lua_newtable(L_); // pinfo.cols table

  // Create cols metatable to track info field assignments
  lua_newtable(L_); // cols metatable
  lua_pushcfunction(L_, [](lua_State *L) -> int {
    // __newindex: called when cols.info = value
    // Stack: table, key, value
    if (lua_type(L, 2) == LUA_TSTRING) {
      auto key = std::string{lua_tostring(L, 2)};
      if (key == "info" && lua_type(L, 3) == LUA_TSTRING) {
        // Store the info value in the registry for later retrieval
        lua_pushvalue(L, 3); // Push value
        lua_setfield(L, LUA_REGISTRYINDEX, "dissector_info");
      }
    }
    // Store in table normally
    lua_rawset(L, 1);
    return 0; // Pushed nothing to stack
  });
  lua_setfield(L_, -2, "__newindex");
  lua_setmetatable(L_, -2); // Set metatable on cols

  lua_setfield(L_, -2, "cols"); // pinfo.cols = cols table

  // Create tree table (dummy) with method support
  lua_newtable(L_); // tree table

  // Create metatable with __index for methods
  lua_newtable(L_); // metatable
  lua_newtable(L_); // methods table
  lua_pushcfunction(L_, [](lua_State *L) -> int {
    // tree:add() - returns a new tree with same metatable
    lua_newtable(L);        // new tree
    lua_getmetatable(L, 1); // Copy metatable from self
    lua_setmetatable(L, -2);
    return 1; // Pushed new tree to stack
  });
  lua_setfield(L_, -2, "add");
  lua_setfield(L_, -2, "__index"); // metatable.__index = methods table
  lua_setmetatable(L_, -2);        // Set metatable on tree

  // Call dissector function: dissector(buffer, pinfo, tree)
  if (lua_pcall(L_, 3, 0, 0) != LUA_OK) {
    lua_pop(L_, 2); // Pop error and proto
    return std::nullopt;
  }

  lua_pop(L_, 1); // Pop proto

  // Extract info from registry
  auto res = result{};
  // Strip "_custom" suffix from protocol name for cleaner display
  res.protocol_ = proto_name == "dns_custom"    ? "DNS"
                  : proto_name == "http_custom" ? "HTTP"
                                                : proto_name;
  lua_getfield(L_, LUA_REGISTRYINDEX, "dissector_info");
  if (lua_isstring(L_, -1))
    res.info_ = lua_tostring(L_, -1);
  else
    res.info_ = "Dissected";
  lua_pop(L_, 1); // Pop info value

  // Clear registry entry for next dissection
  lua_pushnil(L_);
  lua_setfield(L_, LUA_REGISTRYINDEX, "dissector_info");

  return res;
}

} // namespace dissector
