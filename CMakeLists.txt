cmake_minimum_required(VERSION 3.20)
project(stooge)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(stooge src/main.cxx src/dns.cxx)
target_link_libraries(stooge ${PCAP_LIBRARIES})
target_include_directories(stooge PRIVATE ${PCAP_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/src)
