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

class C2Detector;

class NetMonitor {
public:
    NetMonitor();
    ~NetMonitor();

    NetMonitor(const NetMonitor&)            = delete;
    NetMonitor& operator=(const NetMonitor&) = delete;

    // Background thread: enumerate active TCP connections every interval_ms and
    // feed each one into detector.InspectConnection().
    void StartPolling(C2Detector& detector, int interval_ms);
    void StopPolling();

    bool IsRunning() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace network
} // namespace nullbot
