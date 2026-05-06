/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/realtime/realtime_protection.cpp
 */

#include "core/realtime/realtime_protection.h"

#include <shlobj.h>  // SHGetKnownFolderPath, FOLDERID_*

#pragma comment(lib, "shell32.lib")

namespace nullbot {
namespace realtime {

// ─── Constructor / Destructor ─────────────────────────────────────────────────

RealTimeProtection::RealTimeProtection(const std::string&  sig_db_path,
                                       const std::wstring& quarantine_dir)
    : sig_db_path_(sig_db_path)
    , quarantine_dir_(quarantine_dir)
{}

RealTimeProtection::~RealTimeProtection() {
    Stop();
}

// ─── Configuration ────────────────────────────────────────────────────────────

void RealTimeProtection::SetThreatCallback(ThreatAlertCallback cb) {
    std::lock_guard<std::mutex> lock(scan_mutex_);
    threat_cb_ = std::move(cb);
}

bool RealTimeProtection::IsRunning() const { return running_; }

// ─── Watched path expansion ───────────────────────────────────────────────────

std::vector<std::wstring> RealTimeProtection::BuildWatchedPaths() {
    std::vector<std::wstring> paths;

    // 1. %TEMP%
    wchar_t temp_buf[MAX_PATH] = {};
    if (GetTempPathW(MAX_PATH, temp_buf) > 0)
        paths.emplace_back(temp_buf);

    // 2. %APPDATA%
    PWSTR appdata = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
        paths.emplace_back(appdata);
        CoTaskMemFree(appdata);
    }

    // 3. Startup folder (%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup)
    PWSTR startup = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Startup, 0, nullptr, &startup))) {
        paths.emplace_back(startup);
        CoTaskMemFree(startup);
    }

    return paths;
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────

bool RealTimeProtection::Start(bool auto_quarantine) {
    if (running_) return true;

    auto_quarantine_ = auto_quarantine;

    // Initialize scanner — the DB may not exist yet; scanner returns CLEAN for unknown files.
    scanner_ = std::make_unique<scanner::FileScanner>(sig_db_path_);
    scanner_->Initialize();  // best-effort — failures mean no signature matching

    if (auto_quarantine_) {
        qm_ = std::make_unique<quarantine::QuarantineManager>(quarantine_dir_);
        qm_->Initialize();
    }

    auto watched_paths = BuildWatchedPaths();
    for (const auto& path : watched_paths) {
        auto watcher = std::make_unique<DirectoryWatcher>(
            path,
            [this](const std::wstring& fp) { OnFileEvent(fp); }
        );
        if (watcher->Start()) {
            watchers_.push_back(std::move(watcher));
        }
        // Silently skip directories that cannot be opened (missing, no access, etc.)
    }

    running_ = true;
    return true;
}

void RealTimeProtection::Stop() {
    if (!running_) return;
    // Stop all watchers first — their threads may be in OnFileEvent holding scan_mutex_.
    for (auto& w : watchers_) w->Stop();
    watchers_.clear();
    running_ = false;
}

// ─── Event handler ───────────────────────────────────────────────────────────

void RealTimeProtection::OnFileEvent(const std::wstring& file_path) {
    // Serialize scans: multiple watcher threads must not race on scanner_ or qm_.
    std::lock_guard<std::mutex> lock(scan_mutex_);

    scanner::ScanResult result = scanner_->ScanFile(file_path);

    if (result.level < scanner::ThreatLevel::SUSPICIOUS) return;

    // Auto-quarantine if requested and not already quarantined.
    if (auto_quarantine_ && qm_ && !result.quarantined) {
        if (qm_->Quarantine(file_path,
                            result.threat_name,
                            result.detection_type,
                            result.sha256)) {
            result.quarantined = true;
        }
    }

    if (threat_cb_) threat_cb_(result);
}

} // namespace realtime
} // namespace nullbot
