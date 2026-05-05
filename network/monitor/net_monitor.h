/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: network/monitor/net_monitor.h
 *
 * Passive network traffic monitor. Feeds observed connections and DNS queries
 * into the C2 detector for real-time botnet activity detection.
 */
#pragma once

#include <memory>

namespace nullbot {
namespace network {

class NetMonitor {
public:
    NetMonitor();
    ~NetMonitor();

    NetMonitor(const NetMonitor&)            = delete;
    NetMonitor& operator=(const NetMonitor&) = delete;

    bool Start();
    void Stop();
    bool IsRunning() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace network
} // namespace nullbot
