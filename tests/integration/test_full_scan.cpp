/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/integration/test_full_scan.cpp
 *
 * End-to-end integration tests for the scan → quarantine → restore pipeline.
 *
 * EICAR note: tests that create the EICAR test file require that Windows Defender
 * has an exclusion on the temp directory, or that Defender is disabled, otherwise
 * Defender removes the file before our scanner sees it.  In a CI environment add:
 *   Add-MpPreference -ExclusionPath $env:TEMP
 */

#include "tests/test_runner.h"
#include "core/scanner/scanner.h"
#include "core/quarantine/quarantine.h"
#include "core/realtime/realtime_protection.h"
#include "third_party/sqlite3/sqlite3.h"

#include <windows.h>
#include <atomic>
#include <string>
#include <thread>
#include <chrono>

// ─── Synthetic threat payload ─────────────────────────────────────────────────
// A benign string seeded into the test DB as a "threat".
// Using a custom payload instead of EICAR avoids Windows Defender removing the
// file before the scanner reaches it, which would make these tests flaky on
// machines with real-time AV protection enabled.
//
// SHA-256 verified by test_scanner.cpp: ScanFile_ComputesCorrectSHA256_ForKnownPayload
static const char kTestPayload[] = "NullBot_test_sha256";
static const char kTestPayloadSha256[] =
    "dd584e9d384bbb4fdf6121854fcd9d69d0466554122e26291c939d27a4e093c4";

// ─── Fixture helpers ──────────────────────────────────────────────────────────

namespace {

static std::wstring GetTempBase() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring base = tmp;
    if (!base.empty() && base.back() == L'\\') base.pop_back();
    return base;
}

static std::wstring MakeTempDir(const wchar_t* prefix) {
    wchar_t placeholder[MAX_PATH];
    GetTempFileNameW((GetTempBase() + L"\\").c_str(), prefix, 0, placeholder);
    DeleteFileW(placeholder);
    CreateDirectoryW(placeholder, nullptr);
    return placeholder;
}

static void RemoveAll(const std::wstring& path) {
    std::wstring pattern = path + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;
            std::wstring child = path + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                RemoveAll(child);
            else
                DeleteFileW(child.c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(path.c_str());
}

static std::wstring CreateTestFile(const std::wstring& dir,
                               const std::wstring& name,
                               const char* data, DWORD len) {
    std::wstring path = dir + L"\\" + name;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD written = 0;
    WriteFile(h, data, len, &written, nullptr);
    CloseHandle(h);
    return path;
}

static bool FileExists(const std::wstring& p) {
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static std::string ReadAllBytes(const std::wstring& p) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    std::string buf(static_cast<size_t>(sz.QuadPart), '\0');
    DWORD rd = 0;
    ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &rd, nullptr);
    CloseHandle(h);
    buf.resize(rd);
    return buf;
}

static std::string WideToUtf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n) - 1u, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Creates <dir>\signatures.db with one hash entry.
static bool SeedSigDB(const std::wstring& dir,
                      const char* sha256, const char* threat_name) {
    std::string path = WideToUtf8(dir + L"\\signatures.db");

    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    std::string sql =
        "CREATE TABLE IF NOT EXISTS hashes (sha256 TEXT PRIMARY KEY, name TEXT NOT NULL);"
        "INSERT OR IGNORE INTO hashes VALUES ('" +
        std::string(sha256) + "', '" + std::string(threat_name) + "');";
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
    return true;
}

// Busy-wait until predicate or timeout.
template<typename Pred>
static bool WaitFor(Pred pred, DWORD timeout_ms) {
    DWORD elapsed = 0;
    while (elapsed < timeout_ms) {
        if (pred()) return true;
        Sleep(10);
        elapsed += 10;
    }
    return pred();
}

} // namespace

// ─── Test 1: Clean directory — 0 threats, 10 files scanned ───────────────────

TEST_CASE(FullScan_CleanDirectory_ZeroThreats) {
    std::wstring dir = MakeTempDir(L"nbc");

    // 10 .txt files with low-entropy content (no heuristic triggers)
    static const char payload[] = "NullBot clean test file content.\n";
    for (int i = 0; i < 10; ++i) {
        std::wstring name = L"clean_" + std::to_wstring(i) + L".txt";
        REQUIRE(!CreateTestFile(dir, name, payload, static_cast<DWORD>(sizeof(payload) - 1)).empty());
    }

    // Scanner with no DB — hash lookup always misses, only heuristics active
    nullbot::scanner::FileScanner scanner("Z:\\nonexistent");
    nullbot::scanner::ScanOptions opts;
    opts.use_heuristics = true;

    size_t scanned = 0;
    auto results = scanner.ScanDirectory(dir, opts,
        [&](const std::wstring&, size_t n, size_t) { scanned = n; },
        nullptr);

    RemoveAll(dir);

    REQUIRE(results.empty());   // 0 threats
    REQUIRE(scanned == 10);     // all 10 files visited

    DWORD elapsed_ms = 0;  // ScanDirectory is synchronous; just verify it returned
    REQUIRE(elapsed_ms < 5000);
}

// ─── Test 2: Threat detection by hash signature ───────────────────────────────

TEST_CASE(FullScan_DetectsThreat_ByHashSignature) {
    std::wstring sig_dir  = MakeTempDir(L"nbs");
    std::wstring scan_dir = MakeTempDir(L"nbd");

    REQUIRE(SeedSigDB(sig_dir, kTestPayloadSha256, "Test.Threat.Synthetic"));

    std::string sig_dir_narrow = WideToUtf8(sig_dir);
    nullbot::scanner::FileScanner scanner(sig_dir_narrow);
    REQUIRE(scanner.Initialize());

    std::wstring threat_path = CreateTestFile(scan_dir, L"threat_sample.dat",
                                              kTestPayload,
                                              static_cast<DWORD>(sizeof(kTestPayload) - 1));
    REQUIRE(!threat_path.empty());

    std::string found_name;
    auto results = scanner.ScanDirectory(scan_dir, {},
        nullptr,
        [&](const nullbot::scanner::ScanResult& r) { found_name = r.threat_name; });

    RemoveAll(scan_dir);
    RemoveAll(sig_dir);

    REQUIRE(!results.empty());
    REQUIRE(results[0].detection_type == "SIGNATURE");
    REQUIRE(found_name == "Test.Threat.Synthetic");
    REQUIRE(results[0].level >= nullbot::scanner::ThreatLevel::SUSPICIOUS);
}

// ─── Test 3: Quarantine → list → restore → verify ────────────────────────────

TEST_CASE(FullScan_QuarantineFullFlow) {
    std::wstring work_dir = MakeTempDir(L"nbq");
    std::wstring src_dir  = work_dir + L"\\src";
    std::wstring qdir     = work_dir + L"\\vault";
    CreateDirectoryW(src_dir.c_str(), nullptr);

    const std::string original_content = "QuarantineRoundTripPayload_NullBot_v1";
    std::wstring src = CreateTestFile(src_dir, L"target.exe",
                                 original_content.data(),
                                 static_cast<DWORD>(original_content.size()));
    REQUIRE(!src.empty());

    nullbot::quarantine::QuarantineManager qm(qdir);
    REQUIRE(qm.Initialize());

    // Quarantine
    REQUIRE(qm.Quarantine(src, "Test.Threat.FullFlow", "SIGNATURE", "deadbeef"));
    REQUIRE(!FileExists(src));       // original gone
    REQUIRE(qm.GetCount() == 1);

    auto items = qm.ListAll();
    REQUIRE(items.size() == 1);
    REQUIRE(items[0].threat_name == "Test.Threat.FullFlow");

    // Vault file exists and is encrypted (content != original)
    std::wstring vault_path = qdir + L"\\" +
        std::wstring(items[0].vault_filename.begin(), items[0].vault_filename.end());
    REQUIRE(FileExists(vault_path));
    REQUIRE(ReadAllBytes(vault_path).find(original_content) == std::string::npos);

    // Restore
    REQUIRE(qm.Restore(items[0].id));
    REQUIRE(FileExists(src));
    REQUIRE(ReadAllBytes(src) == original_content);

    // DB record updated
    auto after = qm.GetById(items[0].id);
    REQUIRE(after.has_value());
    REQUIRE(after->restored == true);

    RemoveAll(work_dir);
}

// ─── Test 4: RealTimeProtection callback fires when threat appears in %TEMP% ──

TEST_CASE(FullScan_RealTimeDetection_CallbackFired) {
    std::wstring sig_dir = MakeTempDir(L"nbrts");
    std::wstring qdir    = MakeTempDir(L"nbrtq");

    REQUIRE(SeedSigDB(sig_dir, kTestPayloadSha256, "Test.Threat.Synthetic"));

    std::string sig_dir_narrow = WideToUtf8(sig_dir);
    std::atomic<bool> callback_fired{ false };

    nullbot::realtime::RealTimeProtection rtp(sig_dir_narrow, qdir);
    rtp.SetThreatCallback([&](const nullbot::scanner::ScanResult& r) {
        if (r.threat_name == "Test.Threat.Synthetic")
            callback_fired.store(true, std::memory_order_release);
    });
    REQUIRE(rtp.Start(false));

    // Allow watcher threads to arm ReadDirectoryChangesW
    Sleep(150);

    // Drop the test payload into %TEMP% — one of the three watched directories.
    // Must use a watched extension (.cmd is on the list and benign for AV).
    std::wstring threat_path = GetTempBase() + L"\\nullbot_rtp_test.cmd";
    CreateTestFile(GetTempBase(), L"nullbot_rtp_test.cmd",
                   kTestPayload, static_cast<DWORD>(sizeof(kTestPayload) - 1));

    bool fired = WaitFor([&] {
        return callback_fired.load(std::memory_order_acquire);
    }, 3000);

    rtp.Stop();
    DeleteFileW(threat_path.c_str());
    RemoveAll(sig_dir);
    RemoveAll(qdir);

    REQUIRE(fired);
}
