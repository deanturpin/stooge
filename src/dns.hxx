// DNS reverse lookup with async resolution
#pragma once

#include <memory>

namespace tui {
class traffic_monitor;
}

namespace dns {
// Start DNS resolution thread that works on endpoint map
void start_resolver(std::shared_ptr<tui::traffic_monitor> store);

// Stop DNS resolution thread
void stop_resolver();

// Notify DNS thread that new endpoints have been added
void notify_new_work();
} // namespace dns
