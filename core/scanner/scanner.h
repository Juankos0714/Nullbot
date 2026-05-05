#pragma once

/*
 * NullBot — Core Scanner Module
 * File: core/scanner/scanner.h
 *
 * Handles file scanning via hash signatures and YARA rules.
 * Thread-safe, designed for parallel scanning.
 */

#include <windows.h>
#include <memory>
#include <string>
#include <vector>
#include <functional>

// YARA is an optional dependency. When present, enables rule-based detection.
#ifdef NULLBOT_HAVE_YARA
#include <yara.h>
#endif

namespace nullbot {
namespace scanner {

// ─── Severity levels ──────────────────────────────────────────────────────────

enum class ThreatLevel {
    CLEAN     = 0,
    SUSPICIOUS = 1,
    MALICIOUS  = 2,
    CRITICAL   = 3
};

// ─── Scan result ──────────────────────────────────────────────────────────────

struct ScanResult {
    std::wstring    file_path;
    ThreatLevel     level;
    std::string     threat_name;    // e.g. "Botnet.Agent.Zeus"
    std::string     detection_type; // "SIGNATURE" | "YARA" | "HEURISTIC"
    std::string     sha256;
    bool            quarantined;
    FILETIME        scan_time;
};

// ─── Scan options ─────────────────────────────────────────────────────────────

struct ScanOptions {
    bool recursive          = true;
    bool scan_archives      = false;
    bool use_heuristics     = true;
    bool use_yara           = true;
    bool auto_quarantine    = false;
    int  max_threads        = 4;
    std::vector<std::wstring> excluded_paths;
};

// ─── Progress callback ────────────────────────────────────────────────────────

using ScanProgressCallback = std::function<void(
    const std::wstring& current_file,
    size_t files_scanned,
    size_t total_files
)>;

using ThreatFoundCallback = std::function<void(const ScanResult& result)>;

// ─── Scanner class ────────────────────────────────────────────────────────────

class FileScanner {
public:
    explicit FileScanner(const std::string& signatures_db_path);
    ~FileScanner();

    // Disable copy, allow move
    FileScanner(const FileScanner&) = delete;
    FileScanner& operator=(const FileScanner&) = delete;

    // Initialize YARA + load signature DB
    bool Initialize();

    // Single file scan
    ScanResult ScanFile(const std::wstring& file_path);

    // Directory scan (uses thread pool internally)
    std::vector<ScanResult> ScanDirectory(
        const std::wstring& directory_path,
        const ScanOptions& options = {},
        ScanProgressCallback on_progress = nullptr,
        ThreatFoundCallback  on_threat   = nullptr
    );

    // Reload signatures without restart
    bool ReloadSignatures();

    // Stats
    size_t GetSignatureCount() const;
    size_t GetYaraRuleCount()  const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    // Internal helpers
    std::string ComputeSHA256(const std::wstring& file_path);
    bool        MatchesHashDatabase(const std::string& sha256, std::string& out_name);
    bool        RunYaraScan(const std::wstring& file_path, std::string& out_rule);
    ThreatLevel EvaluateThreatLevel(const std::string& threat_name, const std::string& detection_type);

    // Entropy check (high entropy → packed/encrypted → suspicious)
    double      ComputeFileEntropy(const std::wstring& file_path);
    bool        IsHighEntropy(double entropy);

    static constexpr double ENTROPY_THRESHOLD = 7.2;
};

} // namespace scanner
} // namespace nullbot
