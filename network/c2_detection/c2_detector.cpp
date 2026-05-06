/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: network/c2_detection/c2_detector.cpp
 */

#include "network/c2_detection/c2_detector.h"
#include "network/c2_detection/beacon_math.h"

#include <sqlite3.h>
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>

namespace nullbot {
namespace network {

// ─── Impl ─────────────────────────────────────────────────────────────────────

struct C2Detector::Impl {
    std::mutex beacon_mutex;
    std::mutex callback_mutex;
};

// ─── BeaconTracker ────────────────────────────────────────────────────────────

void BeaconTracker::RecordConnection(DWORD pid,
                                     const std::string& dest_ip,
                                     USHORT port) {
    const std::string key = std::to_string(pid) + ":" + dest_ip + ":" +
                            std::to_string(port);
    auto now = std::chrono::steady_clock::now();
    auto& rec = records[key];

    if (rec.connection_count > 0) {
        double interval_ms =
            std::chrono::duration<double, std::milli>(now - rec.last_seen).count();
        rec.intervals_ms.push_back(interval_ms);
    }
    rec.last_seen = now;
    ++rec.connection_count;
}

bool BeaconTracker::IsBeaconing(DWORD pid,
                                const std::string& dest_ip,
                                USHORT port) const {
    const std::string key = std::to_string(pid) + ":" + dest_ip + ":" +
                            std::to_string(port);
    auto it = records.find(key);
    if (it == records.end()) return false;

    const auto& iv = it->second.intervals_ms;
    if (static_cast<int>(iv.size()) < MIN_CONNECTIONS_TO_DETECT) return false;

    const double mean = beacon_math::Mean(iv);
    if (mean == 0.0) return false;

    const double stddev = beacon_math::StdDev(iv, mean);
    return beacon_math::CoeffVariation(stddev, mean) < MAX_JITTER_RATIO;
}

// ─── C2Detector ───────────────────────────────────────────────────────────────

C2Detector::C2Detector()  : impl_(std::make_unique<Impl>()) {}
C2Detector::~C2Detector() = default;

// ─── LoadBlacklists ───────────────────────────────────────────────────────────

bool C2Detector::LoadBlacklists(const std::string& data_path) {
    std::string db_path = data_path;
    if (!db_path.empty() && db_path.back() != '\\' && db_path.back() != '/')
        db_path += '\\';
    db_path += "signatures.db";

    sqlite3* raw_db = nullptr;
    if (sqlite3_open_v2(db_path.c_str(), &raw_db, SQLITE_OPEN_READONLY, nullptr)
            != SQLITE_OK) {
        if (raw_db) sqlite3_close(raw_db);
        std::cout << "[C2Detector] Could not open blacklist DB: " << db_path << "\n";
        return false;
    }

    std::unordered_set<std::string> domains;
    std::unordered_set<std::string> ips;

    auto load_text_column = [&](const char* sql,
                                std::unordered_set<std::string>& out) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(raw_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* val =
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (val && *val) out.emplace(val);
        }
        sqlite3_finalize(stmt);
    };

    load_text_column("SELECT domain FROM domain_blacklist;", domains);
    load_text_column("SELECT ip      FROM ip_blacklist;",    ips);

    sqlite3_close(raw_db);

    size_t n_domains = 0;
    size_t n_ips     = 0;
    {
        std::lock_guard<std::mutex> lock(blacklist_mutex_);
        domain_blacklist_ = std::move(domains);
        ip_blacklist_     = std::move(ips);
        n_domains = domain_blacklist_.size();
        n_ips     = ip_blacklist_.size();
    }

    std::cout << "[C2Detector] Loaded " << n_domains
              << " domains, " << n_ips << " IPs\n";
    return true;
}

// ─── StartMonitoring / StopMonitoring ─────────────────────────────────────────

bool C2Detector::StartMonitoring(C2AlertCallback on_alert) {
    {
        std::lock_guard<std::mutex> lock(impl_->callback_mutex);
        alert_callback_ = std::move(on_alert);
    }
    monitoring_ = true;
    return true;
}

void C2Detector::StopMonitoring() {
    monitoring_ = false;
}

// ─── UpdateBlacklists ─────────────────────────────────────────────────────────

void C2Detector::UpdateDomainBlacklist(
        const std::unordered_set<std::string>& domains) {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    domain_blacklist_ = domains;
}

void C2Detector::UpdateIPBlacklist(
        const std::unordered_set<std::string>& ips) {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    ip_blacklist_ = ips;
}

// ─── Stats ────────────────────────────────────────────────────────────────────

size_t    C2Detector::GetBlockedCount()  const { return blocked_count_.load(); }
size_t    C2Detector::GetDetectedCount() const { return detected_count_.load(); }

// ─── InspectDNSQuery ──────────────────────────────────────────────────────────

void C2Detector::InspectDNSQuery(DWORD pid,
                                  const std::string& process_name,
                                  const std::string& domain) {
    // Normalize: lowercase and strip trailing dot
    std::string normalized = domain;
    for (char& c : normalized)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (!normalized.empty() && normalized.back() == '.') normalized.pop_back();

    if (IsDomainBlacklisted(normalized)) {
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        EmitAlert({
            C2AlertLevel::CRITICAL,
            process_name,
            pid,
            normalized,
            "DNS_BLACKLIST",
            "Domain matched known C2 blacklist",
            ft,
            false
        });
        return;
    }

    // TODO: integrate DGADetector here
}

// ─── InspectConnection ────────────────────────────────────────────────────────

void C2Detector::InspectConnection(DWORD pid,
                                    const std::string& process_name,
                                    const std::string& dest_ip,
                                    USHORT dest_port,
                                    const std::string& sni_hostname) {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);

    if (IsIPBlacklisted(dest_ip)) {
        EmitAlert({
            C2AlertLevel::CRITICAL,
            process_name,
            pid,
            dest_ip,
            "IP_REPUTATION",
            "IP matched known C2 blacklist (port " + std::to_string(dest_port) + ")",
            ft,
            false
        });
    }

    for (USHORT p : SUSPICIOUS_C2_PORTS) {
        if (dest_port == p) {
            EmitAlert({
                C2AlertLevel::WARNING,
                process_name,
                pid,
                dest_ip + ":" + std::to_string(dest_port),
                "SUSPICIOUS_PORT",
                "Connection to known C2 port " + std::to_string(dest_port),
                ft,
                false
            });
            break;
        }
    }

    // HTTPS directly to an IP with no SNI — classic C2 TLS evasion
    if (sni_hostname.empty() && dest_port == 443) {
        EmitAlert({
            C2AlertLevel::WARNING,
            process_name,
            pid,
            dest_ip,
            "DIRECT_IP_HTTPS",
            "HTTPS connection to bare IP without SNI",
            ft,
            false
        });
    }

    CheckBeaconing(pid, process_name, dest_ip, dest_port);
}

// ─── CheckBeaconing ───────────────────────────────────────────────────────────

void C2Detector::CheckBeaconing(DWORD pid,
                                  const std::string& process_name,
                                  const std::string& dest_ip,
                                  USHORT port) {
    double mean_ms  = 0.0;
    bool   beaconing = false;

    {
        std::lock_guard<std::mutex> lock(impl_->beacon_mutex);
        beacon_tracker_.RecordConnection(pid, dest_ip, port);

        const std::string key = std::to_string(pid) + ":" + dest_ip + ":" +
                                std::to_string(port);
        auto it = beacon_tracker_.records.find(key);
        if (it != beacon_tracker_.records.end()) {
            const auto& iv = it->second.intervals_ms;
            if (static_cast<int>(iv.size()) >=
                    BeaconTracker::MIN_CONNECTIONS_TO_DETECT) {
                mean_ms  = beacon_math::Mean(iv);
                beaconing = beacon_tracker_.IsBeaconing(pid, dest_ip, port);
            }
        }
    }

    if (beaconing) {
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        EmitAlert({
            C2AlertLevel::HIGH,
            process_name,
            pid,
            dest_ip + ":" + std::to_string(port),
            "BEACONING",
            "Regular callback pattern detected, mean interval " +
                std::to_string(static_cast<int>(mean_ms)) + "ms",
            ft,
            false
        });
    }
}

// ─── EmitAlert ────────────────────────────────────────────────────────────────

void C2Detector::EmitAlert(C2Alert alert) {
    ++detected_count_;
    std::lock_guard<std::mutex> lock(impl_->callback_mutex);
    if (alert_callback_) alert_callback_(alert);
}

// ─── Private helpers ──────────────────────────────────────────────────────────

bool C2Detector::IsDomainBlacklisted(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    return domain_blacklist_.count(domain) > 0;
}

bool C2Detector::IsIPBlacklisted(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    return ip_blacklist_.count(ip) > 0;
}

bool C2Detector::IsSuspiciousDomain(const std::string&) const {
    return false; // reserved for fast-flux heuristic
}

bool C2Detector::IsDirectIPConnection(const std::string& sni,
                                       const std::string&) const {
    return sni.empty();
}

} // namespace network
} // namespace nullbot
