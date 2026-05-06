#pragma once

/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/realtime/realtime_protection.h
 *
 * Orchestrates real-time filesystem protection:
 *   - Monitors %TEMP%, %APPDATA%, and the Startup folder with DirectoryWatcher.
 *   - Scans new/modified files via FileScanner.
 *   - Optionally quarantines detected threats automatically.
 *   - Emits a callback for each threat so the UI can display notifications.
 *
 * Single owner; Start() / Stop() are not thread-safe with each other.
 */

#include <windows.h>

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "core/realtime/directory_watcher.h"
#include "core/scanner/scanner.h"
#include "core/quarantine/quarantine.h"

namespace nullbot {
namespace realtime {

class RealTimeProtection {
public:
    using ThreatAlertCallback =
        std::function<void(const scanner::ScanResult& result)>;

    // sig_db_path   — path to the signatures SQLite DB (passed to FileScanner)
    // quarantine_dir — vault directory for auto-quarantine
    RealTimeProtection(const std::string&  sig_db_path,
                       const std::wstring& quarantine_dir);
    ~RealTimeProtection();

    // Non-copyable — owns OS handles and live threads via DirectoryWatcher.
    RealTimeProtection(const RealTimeProtection&)            = delete;
    RealTimeProtection& operator=(const RealTimeProtection&) = delete;

    // Called on the watcher thread when a threat is detected.
    void SetThreatCallback(ThreatAlertCallback cb);

    // Initialize scanner + quarantine, expand watched paths, start watchers.
    // Returns false if the scanner fails to initialize.
    bool Start(bool auto_quarantine = false);

    // Stop all watchers and join their threads.
    void Stop();

    bool IsRunning() const;

private:
    // Invoked by each DirectoryWatcher callback on the watcher's thread.
    void OnFileEvent(const std::wstring& file_path);

    // Populate watch_paths_ by expanding environment variables.
    static std::vector<std::wstring> BuildWatchedPaths();

    std::string  sig_db_path_;
    std::wstring quarantine_dir_;

    ThreatAlertCallback threat_cb_;
    bool                auto_quarantine_ = false;
    bool                running_         = false;

    std::unique_ptr<scanner::FileScanner>          scanner_;
    std::unique_ptr<quarantine::QuarantineManager> qm_;
    std::vector<std::unique_ptr<DirectoryWatcher>> watchers_;

    // Serializes concurrent OnFileEvent calls (watcher threads may overlap).
    std::mutex scan_mutex_;
};

} // namespace realtime
} // namespace nullbot
