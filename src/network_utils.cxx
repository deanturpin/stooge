// Network utility function compile-time tests
#include "network_utils.hxx"

namespace network_utils {

// Compile-time unit tests for private IP detection
static_assert(is_private_ipv4("10.0.0.1"), "10.0.0.1 is private");
static_assert(is_private_ipv4("10.255.255.255"), "10.255.255.255 is private");
static_assert(is_private_ipv4("172.16.0.1"), "172.16.0.1 is private");
static_assert(is_private_ipv4("172.31.255.255"), "172.31.255.255 is private");
static_assert(is_private_ipv4("192.168.0.1"), "192.168.0.1 is private");
static_assert(is_private_ipv4("192.168.255.255"), "192.168.255.255 is private");
static_assert(is_private_ipv4("127.0.0.1"), "127.0.0.1 is loopback");
static_assert(is_private_ipv4("127.255.255.255"),
              "127.255.255.255 is loopback");
static_assert(is_private_ipv4("169.254.1.1"), "169.254.1.1 is link-local");
static_assert(!is_private_ipv4("8.8.8.8"), "8.8.8.8 is public");
static_assert(!is_private_ipv4("1.1.1.1"), "1.1.1.1 is public");
static_assert(!is_private_ipv4("172.15.255.255"), "172.15.x.x is public");
static_assert(!is_private_ipv4("172.32.0.0"), "172.32.x.x is public");
static_assert(!is_private_ipv4("192.167.1.1"), "192.167.x.x is public");
static_assert(!is_private_ipv4("11.0.0.1"), "11.x.x.x is public");

// Compile-time unit tests for octet array version
static_assert(is_private_ipv4(std::array<uint8_t, 4>{10, 0, 0, 1}),
              "10.0.0.1 is private");
static_assert(is_private_ipv4(std::array<uint8_t, 4>{172, 16, 0, 1}),
              "172.16.0.1 is private");
static_assert(is_private_ipv4(std::array<uint8_t, 4>{192, 168, 1, 1}),
              "192.168.1.1 is private");
static_assert(!is_private_ipv4(std::array<uint8_t, 4>{8, 8, 8, 8}),
              "8.8.8.8 is public");

// Compile-time unit tests for hostname classification
static_assert(is_local_hostname("localhost"), "localhost is local");
static_assert(is_local_hostname("foo.localhost"), "foo.localhost is local");
static_assert(is_local_hostname("myhost.local"), "myhost.local is local");
static_assert(is_local_hostname("router.lan"), "router.lan is local");
static_assert(is_local_hostname("mycomputer"),
              "Single-label hostname is local");
static_assert(!is_local_hostname("google.com"), "google.com is not local");
static_assert(!is_local_hostname("api.example.org"),
              "api.example.org is not local");
static_assert(!is_local_hostname(""), "Empty string is not local");

} // namespace network_utils
