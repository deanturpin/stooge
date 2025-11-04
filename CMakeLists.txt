# CMake configuration for stooge - network traffic replayer
cmake_minimum_required(VERSION 3.30)
project(stooge)

# Use C++26 for latest language features
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build with debug symbols
set(CMAKE_BUILD_TYPE Debug)

# Find libpcap for PCAP file parsing
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Find Lua for dissector script execution
pkg_check_modules(LUA REQUIRED lua5.4)

# Find FTXUI for terminal UI
find_package(ftxui REQUIRED)

# Build executable
add_executable(stooge src/main.cxx src/dns.cxx src/dissector.cxx src/tui.cxx src/oui.cxx)
target_link_libraries(stooge ${PCAP_LIBRARIES} ${LUA_LIBRARIES}
    ftxui::screen ftxui::dom ftxui::component)
target_include_directories(stooge PRIVATE ${PCAP_INCLUDE_DIRS} ${LUA_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/src)

# Enable testing
enable_testing()

# Find Catch2
find_package(Catch2 3 REQUIRED)

# Build test executable
add_executable(stooge_tests tests/test_dns.cxx src/dns.cxx src/tui.cxx)
target_link_libraries(stooge_tests PRIVATE Catch2::Catch2WithMain
    ftxui::screen ftxui::dom ftxui::component)
target_include_directories(stooge_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Register tests with CTest
include(CTest)
add_test(NAME stooge_tests COMMAND stooge_tests)
