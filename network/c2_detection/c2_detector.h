#pragma once

/*
 * NullBot — C2 Communication Detection Module
 * File: network/c2_detection/c2_detector.h
 *
 * Detects Command & Control communications from botnet agents by analyzing:
 * - DNS queries against known malicious domain feeds
 * - IP connections against reputation blacklists
 * - Beaconing patterns (regular interval callbacks)
 * - Fast-flux DNS patterns
 * - Direct IP connections without domain (no-SNI HTTPS)
 */

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <chrono>

namespace nullbot {
namespace network {

// ─── C2 alert severity ────────────────────────────────────────────────────────

enum class C2AlertLevel {
    INFO     = 0,
    WARNING  = 1,
    HIGH     = 2,
    CRITICAL = 3
};

// ─── Detected C2 event ────────────────────────────────────────────────────────

struct C2Alert {
    C2AlertLevel   level;
    std::string    process_name;
    DWORD          pid;
    std::string    indicator;         // Domain, IP, or pattern description
    std::string    detection_method;  // "DNS_BLACKLIST" | "IP_REPUTATION" | "BEACONING" | "DGA" | "FASTFLUX"
    std::string    description;
    FILETIME       timestamp;
    bool           blocked;           // Whether the connection was blocked
};

using C2AlertCallback = std::function<void(const C2Alert& alert)>;

// ─── Beaconing tracker ────────────────────────────────────────────────────────
// Tracks connection intervals per (pid, destination) to detect beaconing

struct BeaconTracker {
    struct ConnectionRecord {
        std::chrono::steady_clock::time_point last_seen;
        std::vector<double> intervals_ms;  // Time between connections in ms
        DWORD  connection_count = 0;
    };

    // Key: "PID:destination_ip:port"
    std::unordered_map<std::string, ConnectionRecord> records;

    void RecordConnection(DWORD pid, const std::string& dest_ip, USHORT port);
    bool IsBeaconing(DWORD pid, const std::string& dest_ip, USHORT port) const;

    // A connection is beaconing if:
    // - 5+ connections recorded
    // - Interval standard deviation < 15% of mean (very regular)
    static constexpr int    MIN_CONNECTIONS_TO_DETECT = 5;
    static constexpr double MAX_JITTER_RATIO          = 0.15;
};

// ─── C2 Detector ──────────────────────────────────────────────────────────────

class C2Detector {
public:
    C2Detector();
    ~C2Detector();

    // Load blacklists from local DB (updated by signature updater)
    bool LoadBlacklists(const std::string& data_path);

    // Start monitoring (hooks DNS + monitors network connections)
    bool StartMonitoring(C2AlertCallback on_alert);
    void StopMonitoring();

    // Manual check — called by network monitor with captured packet/connection info
    void InspectDNSQuery(DWORD pid, const std::string& process_name, const std::string& domain);
    void InspectConnection(DWORD pid, const std::string& process_name,
                           const std::string& dest_ip, USHORT dest_port,
                           const std::string& sni_hostname = "");

    // Update blacklists dynamically (called after feed update)
    void UpdateDomainBlacklist(const std::unordered_set<std::string>& domains);
    void UpdateIPBlacklist(const std::unordered_set<std::string>& ips);

    // Stats
    size_t GetBlockedCount()   const;
    size_t GetDetectedCount()  const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    // ── Detection methods ─────────────────────────────────────────────────────

    bool IsDomainBlacklisted(const std::string& domain) const;
    bool IsIPBlacklisted(const std::string& ip)         const;
    bool IsSuspiciousDomain(const std::string& domain)  const;  // Fast-flux, new domain, etc.
    bool IsDirectIPConnection(const std::string& sni, const std::string& ip) const;

    void CheckBeaconing(DWORD pid, const std::string& process_name,
                        const std::string& dest_ip, USHORT port);

    void EmitAlert(C2Alert alert);

    // ── Blacklist data ────────────────────────────────────────────────────────
    std::unordered_set<std::string> domain_blacklist_;
    std::unordered_set<std::string> ip_blacklist_;
    BeaconTracker                   beacon_tracker_;

    C2AlertCallback                 alert_callback_;
    std::atomic<bool>               monitoring_{false};
    std::atomic<size_t>             blocked_count_{0};
    std::atomic<size_t>             detected_count_{0};
    mutable std::mutex              blacklist_mutex_;
};

// ─── Known C2 port patterns ───────────────────────────────────────────────────
// Non-standard ports commonly used by botnet C2 to evade firewalls

inline const std::vector<USHORT> SUSPICIOUS_C2_PORTS = {
    6667, 6668, 6669,   // IRC (classic botnet protocol)
    1080,               // SOCKS proxy
    4444,               // Metasploit default
    5555,               // Common botnet
    8080, 8443,         // Alternative HTTP/HTTPS
    31337,              // Classic "elite" hacker port
    12345, 54321,       // Common RAT ports
};

} // namespace network
} // namespace nullbot
