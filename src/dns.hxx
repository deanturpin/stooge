// DNS reverse lookup with async resolution
#pragma once

#include <memory>
#include <string>
#include <string_view>

namespace tui {
class data_store;
}

namespace dns {
// Start DNS resolution thread that works on endpoint map
void start_resolver(std::shared_ptr<tui::data_store> store);

// Stop DNS resolution thread
void stop_resolver();
} // namespace dns
