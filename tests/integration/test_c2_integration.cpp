/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/integration/test_c2_integration.cpp
 *
 * End-to-end integration tests for C2 detection over real time.
 * The beaconing test takes ~2 seconds (10 connections x 200ms sleep).
 */

#include "tests/test_runner.h"
#include "network/c2_detection/c2_detector.h"
#include "third_party/sqlite3/sqlite3.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ─── Fixture helpers ──────────────────────────────────────────────────────────

namespace {

struct AlertCapture {
    std::vector<nullbot::network::C2Alert> alerts;
    mutable std::mutex mtx;

    void Record(const nullbot::network::C2Alert& a) {
        std::lock_guard<std::mutex> lock(mtx);
        alerts.push_back(a);
    }

    bool HasMethod(const std::string& m) const {
        std::lock_guard<std::mutex> lock(mtx);
        for (const auto& a : alerts)
            if (a.detection_method == m) return true;
        return false;
    }

    size_t Count() const {
        std::lock_guard<std::mutex> lock(mtx);
        return alerts.size();
    }
};

static std::string TempDir() {
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    std::string dir = tmp;
    if (!dir.empty() && dir.back() == '\\') dir.pop_back();
    dir += "\\nullbot_c2int_test";
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir;
}

static void CleanDir(const std::string& dir) {
    DeleteFileA((dir + "\\signatures.db").c_str());
    RemoveDirectoryA(dir.c_str());
}

static bool CreateTestDB(const std::string& dir,
                          const std::string& domain,
                          const std::string& ip) {
    std::string path = dir + "\\signatures.db";
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    std::string sql =
        "CREATE TABLE domain_blacklist (domain TEXT NOT NULL);"
        "INSERT INTO domain_blacklist VALUES ('" + domain + "');"
        "CREATE TABLE ip_blacklist (ip TEXT NOT NULL);"
        "INSERT INTO ip_blacklist VALUES ('" + ip + "');";
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
    return true;
}

} // namespace

// ─── Test 1: Blacklisted domain emits DNS_BLACKLIST alert ─────────────────────

TEST_CASE(C2Integration_BlacklistedDomain_EmitsAlert) {
    std::string dir = TempDir();
    REQUIRE(CreateTestDB(dir, "c2-inttest.xyz", "10.0.0.1"));

    nullbot::network::C2Detector detector;
    REQUIRE(detector.LoadBlacklists(dir));

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    detector.InspectDNSQuery(100, "malware.exe", "c2-inttest.xyz");

    REQUIRE(cap.HasMethod("DNS_BLACKLIST"));
    REQUIRE(cap.Count() >= 1);

    CleanDir(dir);
}

// ─── Test 2: Benign domain produces no alert ──────────────────────────────────

TEST_CASE(C2Integration_BenignDomain_NoAlert) {
    nullbot::network::C2Detector detector;
    detector.UpdateDomainBlacklist({"evil-c2-inttest.xyz"});

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    detector.InspectDNSQuery(1, "chrome.exe", "github.com");

    REQUIRE(!cap.HasMethod("DNS_BLACKLIST"));
}

// ─── Test 3: Regular connections trigger BEACONING alert ─────────────────────
//
// 10 connections with ~200ms sleep → mean ~200ms, stddev < 30ms → CV < 0.15.
// MIN_CONNECTIONS_TO_DETECT = 5, so beaconing is checked from connection 6 onward.

TEST_CASE(C2Integration_RegularConnections_TriggerBeaconing) {
    nullbot::network::C2Detector detector;

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    // Use a non-443 port to avoid DIRECT_IP_HTTPS noise in the alert stream
    for (int i = 0; i < 10; ++i) {
        detector.InspectConnection(1234, "test.exe", "1.2.3.4", 8080);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    REQUIRE(cap.HasMethod("BEACONING"));
}

// ─── Test 4: Blacklisted IP emits IP_REPUTATION alert ────────────────────────

TEST_CASE(C2Integration_BlacklistedIP_EmitsAlert) {
    std::string dir = TempDir();
    REQUIRE(CreateTestDB(dir, "no-such-domain.xyz", "198.51.100.99"));

    nullbot::network::C2Detector detector;
    REQUIRE(detector.LoadBlacklists(dir));

    AlertCapture cap;
    detector.StartMonitoring([&](const nullbot::network::C2Alert& a) {
        cap.Record(a);
    });

    detector.InspectConnection(42, "svc.exe", "198.51.100.99", 80);

    REQUIRE(cap.HasMethod("IP_REPUTATION"));

    CleanDir(dir);
}
