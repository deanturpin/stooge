// Unit tests for DNS resolution functionality
#include "dns.hxx"
#include "tui.hxx"
#include <catch2/catch_test_macros.hpp>
#include <memory>

TEST_CASE("traffic_monitor manages endpoints correctly", "[tui]") {
  auto store = std::make_shared<tui::traffic_monitor>();

  SECTION("initially has no endpoints") {
    auto endpoints = store->get_endpoints();
    REQUIRE(endpoints.empty());
    REQUIRE(store->get_total_packets() == 0uz);
  }

  SECTION("can add and retrieve endpoints") {
    store->add_endpoint("192.168.1.1", 80, "TCP", "example.com", "Vendor",
                        "00:11:22:33:44:55");
    auto endpoints = store->get_endpoints();
    REQUIRE(endpoints.size() == 1uz);
    REQUIRE(endpoints[0].ip_ == "192.168.1.1");
    REQUIRE(endpoints[0].port_ == 80);
    REQUIRE(endpoints[0].protocol_ == "TCP");
    REQUIRE(endpoints[0].hostname_ == "example.com");
    REQUIRE(endpoints[0].vendor_ == "Vendor");
    REQUIRE(endpoints[0].mac_address_ == "00:11:22:33:44:55");
    REQUIRE(endpoints[0].packet_count_ == 1uz);
  }

  SECTION("increments packet count for duplicate endpoints") {
    store->add_endpoint("192.168.1.1", 80, "TCP", "example.com");
    store->add_endpoint("192.168.1.1", 80, "TCP", "example.com");
    auto endpoints = store->get_endpoints();
    REQUIRE(endpoints.size() == 1uz);
    REQUIRE(endpoints[0].packet_count_ == 2uz);
  }

  SECTION("distinguishes endpoints by port and protocol") {
    store->add_endpoint("192.168.1.1", 80, "TCP", "");
    store->add_endpoint("192.168.1.1", 443, "TCP", "");
    store->add_endpoint("192.168.1.1", 53, "UDP", "");
    auto endpoints = store->get_endpoints();
    REQUIRE(endpoints.size() == 3uz);
  }

  SECTION("updates hostname for existing IP") {
    store->add_endpoint("192.168.1.1", 80, "TCP", "");
    store->update_hostname("192.168.1.1", "resolved.example.com");
    auto endpoints = store->get_endpoints();
    REQUIRE(endpoints[0].hostname_ == "resolved.example.com");
  }

  SECTION("identifies unresolved IPs") {
    store->add_endpoint("192.168.1.1", 80, "TCP", "example.com");
    store->add_endpoint("192.168.1.2", 80, "TCP", "");
    auto unresolved = store->get_unresolved_ips();
    REQUIRE(unresolved.size() == 1uz);
    REQUIRE(unresolved[0] == "192.168.1.2");
  }
}

TEST_CASE("traffic_monitor manages packets correctly", "[tui]") {
  auto store = std::make_shared<tui::traffic_monitor>();

  SECTION("can add and retrieve packets") {
    auto pkt = tui::packet_entry{};
    pkt.number_ = 1uz;
    pkt.timestamp_ = 0.0;
    pkt.transport_ = "TCP";
    pkt.application_ = "HTTP";
    pkt.src_ = "192.168.1.1:80";
    pkt.dst_ = "192.168.1.2:443";
    pkt.bytes_ = 1500uz;
    pkt.dissection_ = "HTTP GET /";

    store->add_packet(pkt);
    REQUIRE(store->get_total_packets() == 1uz);

    auto packets = store->get_recent_packets(10uz);
    REQUIRE(packets.size() == 1uz);
    REQUIRE(packets[0].number_ == 1uz);
    REQUIRE(packets[0].transport_ == "TCP");
    REQUIRE(packets[0].application_ == "HTTP");
    REQUIRE(packets[0].dissection_ == "HTTP GET /");
  }

  SECTION("limits packet history to MAX_PACKETS") {
    // Add more than MAX_PACKETS (1000)
    for (auto i = 0uz; i < 1100uz; i++) {
      auto pkt = tui::packet_entry{};
      pkt.number_ = i;
      store->add_packet(pkt);
    }

    auto packets = store->get_recent_packets(2000uz);
    REQUIRE(packets.size() <= 1000uz); // Should be capped at MAX_PACKETS
    REQUIRE(store->get_total_packets() == 1100uz); // But counter keeps counting
  }
}

TEST_CASE("traffic_monitor manages capture mode correctly", "[tui]") {
  auto store = std::make_shared<tui::traffic_monitor>();

  SECTION("defaults to replay mode") { REQUIRE_FALSE(store->is_live()); }

  SECTION("can set live capture mode") {
    store->set_capture_mode(true);
    REQUIRE(store->is_live());
  }

  SECTION("tracks packet time") {
    store->set_capture_time(3661.5); // 1 hour, 1 minute, 1.5 seconds
    auto time_str = store->get_time_display();
    REQUIRE(time_str == "01:01:01"); // Should format as HH:MM:SS
  }
}

TEST_CASE("endpoint_stats formats correctly", "[tui]") {
  auto ep = tui::endpoint_stats{};
  ep.ip_ = "192.168.1.1";
  ep.port_ = 80;
  ep.protocol_ = "TCP";
  ep.hostname_ = "example.com";
  ep.vendor_ = "Apple";
  ep.mac_address_ = "00:11:22:33:44:55";
  ep.packet_count_ = 42uz;

  auto str = ep.to_string();
  REQUIRE_FALSE(str.empty());
  // String should contain IP, port, protocol, hostname, vendor
  REQUIRE(str.find("192.168.1.1") != std::string::npos);
  REQUIRE(str.find("TCP") != std::string::npos);
  REQUIRE(str.find("example.com") != std::string::npos);
}
