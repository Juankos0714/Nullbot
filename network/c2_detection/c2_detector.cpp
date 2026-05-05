/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: network/c2_detection/c2_detector.cpp
 */

#include "network/c2_detection/c2_detector.h"

namespace nullbot {
namespace network {

// ─── BeaconTracker ────────────────────────────────────────────────────────────

void BeaconTracker::RecordConnection(DWORD, const std::string&, USHORT) {}

bool BeaconTracker::IsBeaconing(DWORD, const std::string&, USHORT) const {
    return false;
}

// ─── C2Detector::Impl ─────────────────────────────────────────────────────────

struct C2Detector::Impl {};

// ─── C2Detector ───────────────────────────────────────────────────────────────

C2Detector::C2Detector()  : impl_(std::make_unique<Impl>()) {}
C2Detector::~C2Detector() = default;

bool C2Detector::LoadBlacklists(const std::string&)       { return true; }
bool C2Detector::StartMonitoring(C2AlertCallback callback) {
    alert_callback_ = std::move(callback);
    monitoring_     = true;
    return true;
}
void C2Detector::StopMonitoring() { monitoring_ = false; }

void C2Detector::InspectDNSQuery(DWORD, const std::string&, const std::string&) {}
void C2Detector::InspectConnection(DWORD, const std::string&,
                                   const std::string&, USHORT,
                                   const std::string&) {}

void C2Detector::UpdateDomainBlacklist(const std::unordered_set<std::string>& domains) {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    domain_blacklist_ = domains;
}

void C2Detector::UpdateIPBlacklist(const std::unordered_set<std::string>& ips) {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    ip_blacklist_ = ips;
}

size_t C2Detector::GetBlockedCount()  const { return blocked_count_.load(); }
size_t C2Detector::GetDetectedCount() const { return detected_count_.load(); }

bool C2Detector::IsDomainBlacklisted(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    return domain_blacklist_.count(domain) > 0;
}

bool C2Detector::IsIPBlacklisted(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    return ip_blacklist_.count(ip) > 0;
}

bool C2Detector::IsSuspiciousDomain(const std::string&) const  { return false; }
bool C2Detector::IsDirectIPConnection(const std::string& sni,
                                      const std::string&) const { return sni.empty(); }

void C2Detector::CheckBeaconing(DWORD, const std::string&,
                                 const std::string&, USHORT) {}
void C2Detector::EmitAlert(C2Alert alert) {
    ++detected_count_;
    if (alert_callback_) alert_callback_(alert);
}

} // namespace network
} // namespace nullbot
