# CMake configuration for stooge - network traffic replayer
cmake_minimum_required(VERSION 3.20)
project(stooge)

# Use C++23 for std::print, std::format, and modern features
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find libpcap for PCAP file parsing
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Find Lua for dissector script execution
pkg_check_modules(LUA REQUIRED lua5.4)

# Build executable
add_executable(stooge src/main.cxx src/dns.cxx src/dissector.cxx)
target_link_libraries(stooge ${PCAP_LIBRARIES} ${LUA_LIBRARIES})
target_include_directories(stooge PRIVATE ${PCAP_INCLUDE_DIRS} ${LUA_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/src)
