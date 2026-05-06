/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/unit/test_c2_detector.cpp
 */

#include "tests/test_runner.h"
#include "network/c2_detection/c2_detector.h"
#include "network/c2_detection/beacon_math.h"

#include <sqlite3.h>
#include <windows.h>

#include <chrono>
#include <cmath>
#include <string>
#include <vector>

// ─── beacon_math pure-function tests ─────────────────────────────────────────

TEST_CASE(BeaconMath_Mean_ReturnsCorrectValue) {
    std::vector<double> v = {100.0, 200.0, 300.0};
    REQUIRE(std::abs(nullbot::network::beacon_math::Mean(v) - 200.0) < 1e-9);
}

TEST_CASE(BeaconMath_Mean_ReturnsZero_ForEmptyVector) {
    REQUIRE(nullbot::network::beacon_math::Mean({}) == 0.0);
}

TEST_CASE(BeaconMath_StdDev_ReturnsZero_ForConstantIntervals) {
    std::vector<double> v = {500.0, 500.0, 500.0, 500.0, 500.0};
    double mean = nullbot::network::beacon_math::Mean(v);
    REQUIRE(nullbot::network::beacon_math::StdDev(v, mean) == 0.0);
}

TEST_CASE(BeaconMath_StdDev_ReturnsCorrectValue) {
    // Population stddev of {2,4,4,4,5,5,7,9} = 2.0
    std::vector<double> v = {2, 4, 4, 4, 5, 5, 7, 9};
    double mean = nullbot::network::beacon_math::Mean(v);
    REQUIRE(std::abs(mean - 5.0) < 1e-9);
    REQUIRE(std::abs(nullbot::network::beacon_math::StdDev(v, mean) - 2.0) < 1e-9);
}

// ─── BeaconTracker structural tests ──────────────────────────────────────────

// Directly populate records so tests are deterministic (no real-time dependency)
static nullbot::network::BeaconTracker MakeTracker(
        const std::vector<double>& intervals) {
    nullbot::network::BeaconTracker tracker;
    auto& rec = tracker.records["42:10.0.0.1:4444"];
    rec.connection_count = static_cast<DWORD>(intervals.size() + 1);
    rec.intervals_ms     = intervals;
    rec.last_seen        = std::chrono::steady_clock::now();
    return tracker;
}

TEST_CASE(BeaconTracker_IsBeaconing_ReturnsFalse_WithFewIntervals) {
    // 3 intervals < MIN_CONNECTIONS_TO_DETECT (5) → no verdict yet
    auto tracker = MakeTracker({1000.0, 1000.0, 1000.0});
    REQUIRE(!tracker.IsBeaconing(42, "10.0.0.1", 4444));
}

TEST_CASE(BeaconTracker_IsBeaconing_ReturnsTrue_ForPerfectlyRegularIntervals) {
    // stddev = 0, mean = 1000ms → CV = 0.0 < 0.15 → beaconing
    auto tracker = MakeTracker({1000.0, 1000.0, 1000.0, 1000.0, 1000.0});
    REQUIRE(tracker.IsBeaconing(42, "10.0.0.1", 4444));
}

TEST_CASE(BeaconTracker_IsBeaconing_ReturnsTrue_ForLowJitter) {
    // 5% jitter: stddev/mean ≈ 0.05 < 0.15 → beaconing
    auto tracker = MakeTracker({950.0, 1000.0, 1050.0, 980.0, 1020.0});
    REQUIRE(tracker.IsBeaconing(42, "10.0.0.1", 4444));
}

TEST_CASE(BeaconTracker_IsBeaconing_ReturnsFalse_ForHighlyIrregularIntervals) {
    // Wildly varying intervals: CV >> 0.15 → not beaconing
    auto tracker = MakeTracker({100.0, 5000.0, 200.0, 8000.0, 50.0});
    REQUIRE(!tracker.IsBeaconing(42, "10.0.0.1", 4444));
}

TEST_CASE(BeaconTracker_IsBeaconing_HandlesZeroMean_WithoutCrash) {
    // All zero intervals — mean == 0 must not divide by zero
    auto tracker = MakeTracker({0.0, 0.0, 0.0, 0.0, 0.0});
    REQUIRE(!tracker.IsBeaconing(42, "10.0.0.1", 4444));
}

// ─── C2Detector blacklist tests ───────────────────────────────────────────────

namespace {

struct AlertCapture {
    std::vector<nullbot::network::C2Alert> alerts;
    std::mutex mtx;

    void Record(const nullbot::network::C2Alert& a) {
        std::lock_guard<std::mutex> lock(mtx);
        alerts.push_back(a);
    }

    bool HasMethod(const std::string& method) const {
        for (const auto& a : alerts)
            if (a.detection_method == method) return true;
        return false;
    }
};

// Creates a minimal signatures.db at dir_path\signatures.db
static bool CreateTestDB(const std::string& dir_path,
                          const std::string& domain,
                          const std::string& ip) {
    std::string db_path = dir_path + "\\signatures.db";

    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }

    const std::string sql =
        "CREATE TABLE domain_blacklist (domain TEXT NOT NULL);"
        "INSERT INTO domain_blacklist VALUES ('" + domain + "');"
        "CREATE TABLE ip_blacklist (ip TEXT NOT NULL);"
        "INSERT INTO ip_blacklist VALUES ('" + ip + "');";

    char* errmsg = nullptr;
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);
    sqlite3_close(db);
    return true;
}

static std::string WstrToUtf8Narrow(const std::wstring& ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n) - 1u, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

static std::string TempTestDir() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring dir = tmp;
    if (!dir.empty() && dir.back() == L'\\') dir.pop_back();
    dir += L"\\nullbot_c2test";
    CreateDirectoryW(dir.c_str(), nullptr);
    return WstrToUtf8Narrow(dir);
}

static void CleanTestDir(const std::string& dir) {
    std::string db = dir + "\\signatures.db";
    DeleteFileA(db.c_str());
    std::wstring wdir(dir.begin(), dir.end());
    RemoveDirectoryW(wdir.c_str());
}

} // namespace

TEST_CASE(LoadBlacklists_LoadsDomainsAndIPs_FromSQLiteDB) {
    std::string dir = TempTestDir();
    REQUIRE(CreateTestDB(dir, "evil-c2.xyz", "198.51.100.1"));

    nullbot::network::C2Detector detector;
    REQUIRE(detector.LoadBlacklists(dir));

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    detector.InspectDNSQuery(1, "test.exe", "evil-c2.xyz");
    REQUIRE(cap.HasMethod("DNS_BLACKLIST"));

    cap.alerts.clear();
    detector.InspectConnection(1, "test.exe", "198.51.100.1", 80);
    REQUIRE(cap.HasMethod("IP_REPUTATION"));

    CleanTestDir(dir);
}

TEST_CASE(InspectDNSQuery_EmitsAlert_ForBlacklistedDomain) {
    nullbot::network::C2Detector detector;
    detector.UpdateDomainBlacklist({"evil.example.com", "c2-server.xyz"});

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    detector.InspectDNSQuery(1234, "malware.exe", "evil.example.com");
    REQUIRE(cap.HasMethod("DNS_BLACKLIST"));
    REQUIRE(cap.alerts[0].level == nullbot::network::C2AlertLevel::CRITICAL);
    REQUIRE(cap.alerts[0].indicator == "evil.example.com");
}

TEST_CASE(InspectDNSQuery_NoAlert_ForGoogleCom) {
    nullbot::network::C2Detector detector;
    detector.UpdateDomainBlacklist({"evil.example.com"});

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    detector.InspectDNSQuery(1, "chrome.exe", "google.com");
    REQUIRE(cap.alerts.empty());
}

TEST_CASE(InspectDNSQuery_NormalizesUppercase) {
    nullbot::network::C2Detector detector;
    detector.UpdateDomainBlacklist({"evil.example.com"});

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    // Query arrives in mixed case — must still match
    detector.InspectDNSQuery(1, "test.exe", "EVIL.EXAMPLE.COM");
    REQUIRE(cap.HasMethod("DNS_BLACKLIST"));
}

TEST_CASE(InspectConnection_EmitsAlert_ForBlacklistedIP) {
    nullbot::network::C2Detector detector;
    detector.UpdateIPBlacklist({"203.0.113.42"});

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    detector.InspectConnection(5678, "trojan.exe", "203.0.113.42", 443);
    REQUIRE(cap.HasMethod("IP_REPUTATION"));
    REQUIRE(cap.alerts[0].level == nullbot::network::C2AlertLevel::CRITICAL);
}

TEST_CASE(InspectConnection_EmitsAlert_ForDirectIPHTTPS) {
    nullbot::network::C2Detector detector;

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    // Port 443, no SNI → DIRECT_IP_HTTPS
    detector.InspectConnection(1, "svc.exe", "8.8.8.8", 443, "");
    REQUIRE(cap.HasMethod("DIRECT_IP_HTTPS"));
}
