/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: network/monitor/net_monitor.cpp
 */

#include "network/monitor/net_monitor.h"

namespace nullbot {
namespace network {

struct NetMonitor::Impl {
    bool running = false;
};

NetMonitor::NetMonitor()  : impl_(std::make_unique<Impl>()) {}
NetMonitor::~NetMonitor() { Stop(); }

bool NetMonitor::Start()       { impl_->running = true;  return true; }
void NetMonitor::Stop()        { impl_->running = false; }
bool NetMonitor::IsRunning() const { return impl_->running; }

} // namespace network
} // namespace nullbot
