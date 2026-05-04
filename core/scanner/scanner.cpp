/*
 * NullBot — Core Scanner Implementation
 * File: core/scanner/scanner.cpp
 */

#include "scanner.h"
#include "../heuristic/pe_analyzer.h"
#include "../../signatures/sig_database.h"

#include <windows.h>
#include <wincrypt.h>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "crypt32.lib")

namespace nullbot {
namespace scanner {

// ─── Internal implementation ──────────────────────────────────────────────────

struct FileScanner::Impl {
    std::string          db_path;
    signatures::SigDB    sig_db;
    YR_RULES*            yara_rules = nullptr;
    std::mutex           yara_mutex;
    std::atomic<bool>    initialized{false};
};

// ─── Constructor / Destructor ─────────────────────────────────────────────────

FileScanner::FileScanner(const std::string& signatures_db_path)
    : impl_(std::make_unique<Impl>())
{
    impl_->db_path = signatures_db_path;
}

FileScanner::~FileScanner() {
    if (impl_->yara_rules) {
        yr_rules_destroy(impl_->yara_rules);
    }
    yr_finalize();
}

// ─── Initialization ───────────────────────────────────────────────────────────

bool FileScanner::Initialize() {
    // Initialize YARA library
    if (yr_initialize() != ERROR_SUCCESS) {
        return false;
    }

    // Load YARA rules from compiled rules file
    std::string rules_path = impl_->db_path + "\\compiled.yarc";
    if (yr_rules_load(rules_path.c_str(), &impl_->yara_rules) != ERROR_SUCCESS) {
        // Fallback: try to compile from source directory
        YR_COMPILER* compiler = nullptr;
        yr_compiler_create(&compiler);

        // TODO: iterate rules/*.yar and add each file
        // yr_compiler_add_file(compiler, fp, nullptr, filename);

        yr_compiler_destroy(compiler);
    }

    // Load hash signature database
    if (!impl_->sig_db.Load(impl_->db_path + "\\signatures.db")) {
        return false;
    }

    impl_->initialized = true;
    return true;
}

// ─── Single file scan ─────────────────────────────────────────────────────────

ScanResult FileScanner::ScanFile(const std::wstring& file_path) {
    ScanResult result;
    result.file_path = file_path;
    result.level     = ThreatLevel::CLEAN;
    result.quarantined = false;
    GetSystemTimeAsFileTime(&result.scan_time);

    // 1. Compute hash and check against database
    result.sha256 = ComputeSHA256(file_path);
    std::string threat_name;

    if (MatchesHashDatabase(result.sha256, threat_name)) {
        result.threat_name    = threat_name;
        result.detection_type = "SIGNATURE";
        result.level          = EvaluateThreatLevel(threat_name, "SIGNATURE");
        return result;
    }

    // 2. YARA scan
    std::string yara_rule;
    if (RunYaraScan(file_path, yara_rule)) {
        result.threat_name    = yara_rule;
        result.detection_type = "YARA";
        result.level          = EvaluateThreatLevel(yara_rule, "YARA");
        return result;
    }

    // 3. Heuristic: entropy check
    double entropy = ComputeFileEntropy(file_path);
    if (IsHighEntropy(entropy)) {
        result.threat_name    = "Heuristic.HighEntropy.Packed";
        result.detection_type = "HEURISTIC";
        result.level          = ThreatLevel::SUSPICIOUS;
    }

    // 4. Heuristic: PE analysis
    heuristic::PEAnalyzer pe(file_path);
    if (pe.IsExecutable()) {
        auto suspicious_imports = pe.GetSuspiciousImports();
        if (!suspicious_imports.empty()) {
            result.threat_name    = "Heuristic.PE.SuspiciousImports";
            result.detection_type = "HEURISTIC";
            result.level          = ThreatLevel::SUSPICIOUS;
        }

        if (pe.HasAntiDebugTechniques()) {
            result.level = ThreatLevel::MALICIOUS;
            result.threat_name = "Heuristic.PE.AntiDebug";
        }
    }

    return result;
}

// ─── Directory scan ───────────────────────────────────────────────────────────

std::vector<ScanResult> FileScanner::ScanDirectory(
    const std::wstring& directory_path,
    const ScanOptions& options,
    ScanProgressCallback on_progress,
    ThreatFoundCallback  on_threat)
{
    // 1. Enumerate all files first
    std::vector<std::wstring> files;
    std::queue<std::wstring>  dirs_to_scan;
    dirs_to_scan.push(directory_path);

    while (!dirs_to_scan.empty()) {
        std::wstring current_dir = dirs_to_scan.front();
        dirs_to_scan.pop();

        WIN32_FIND_DATAW find_data;
        HANDLE hFind = FindFirstFileW((current_dir + L"\\*").c_str(), &find_data);

        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            std::wstring name = find_data.cFileName;
            if (name == L"." || name == L"..") continue;

            std::wstring full_path = current_dir + L"\\" + name;

            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (options.recursive) {
                    // Check excluded paths
                    bool excluded = false;
                    for (const auto& ex : options.excluded_paths) {
                        if (full_path.find(ex) != std::wstring::npos) {
                            excluded = true;
                            break;
                        }
                    }
                    if (!excluded) dirs_to_scan.push(full_path);
                }
            } else {
                files.push_back(full_path);
            }
        } while (FindNextFileW(hFind, &find_data));

        FindClose(hFind);
    }

    // 2. Parallel scan using thread pool
    std::vector<ScanResult> results;
    std::mutex results_mutex;
    std::atomic<size_t> scanned_count{0};

    size_t total = files.size();
    size_t chunk_size = (total + options.max_threads - 1) / options.max_threads;

    std::vector<std::thread> threads;
    for (int t = 0; t < options.max_threads; ++t) {
        size_t start = t * chunk_size;
        size_t end   = min(start + chunk_size, total);
        if (start >= total) break;

        threads.emplace_back([&, start, end]() {
            for (size_t i = start; i < end; ++i) {
                ScanResult r = ScanFile(files[i]);

                size_t count = ++scanned_count;
                if (on_progress) on_progress(files[i], count, total);

                if (r.level >= ThreatLevel::SUSPICIOUS) {
                    if (on_threat) on_threat(r);
                    std::lock_guard<std::mutex> lock(results_mutex);
                    results.push_back(std::move(r));
                }
            }
        });
    }

    for (auto& t : threads) t.join();
    return results;
}

// ─── SHA-256 hash ─────────────────────────────────────────────────────────────

std::string FileScanner::ComputeSHA256(const std::wstring& file_path) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    HANDLE hFile = CreateFileW(
        file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) return "";

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return "";
    }

    BYTE buffer[8192];
    DWORD bytes_read;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, nullptr) && bytes_read > 0) {
        CryptHashData(hHash, buffer, bytes_read, 0);
    }

    BYTE hash[32];
    DWORD hash_len = sizeof(hash);
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0)) {
        std::ostringstream oss;
        for (DWORD i = 0; i < hash_len; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        result = oss.str();
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return result;
}

// ─── YARA scan ────────────────────────────────────────────────────────────────

bool FileScanner::RunYaraScan(const std::wstring& file_path, std::string& out_rule) {
    if (!impl_->yara_rules) return false;

    std::lock_guard<std::mutex> lock(impl_->yara_mutex);

    struct YaraScanContext {
        bool  matched = false;
        std::string rule_name;
    } ctx;

    // Convert path to narrow string for YARA
    std::string path_narrow(file_path.begin(), file_path.end());

    yr_rules_scan_file(
        impl_->yara_rules,
        path_narrow.c_str(),
        SCAN_FLAGS_FAST_MODE,
        [](YR_SCAN_CONTEXT* /*ctx*/, int msg, void* msg_data, void* user_data) -> int {
            if (msg == CALLBACK_MSG_RULE_MATCHING) {
                auto* rule = static_cast<YR_RULE*>(msg_data);
                auto* scan_ctx = static_cast<YaraScanContext*>(user_data);
                scan_ctx->matched   = true;
                scan_ctx->rule_name = rule->identifier;
                return CALLBACK_ABORT;
            }
            return CALLBACK_CONTINUE;
        },
        &ctx,
        0
    );

    if (ctx.matched) {
        out_rule = ctx.rule_name;
        return true;
    }
    return false;
}

// ─── Entropy ──────────────────────────────────────────────────────────────────

double FileScanner::ComputeFileEntropy(const std::wstring& file_path) {
    HANDLE hFile = CreateFileW(
        file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) return 0.0;

    DWORD freq[256] = {};
    BYTE  buf[4096];
    DWORD bytes_read;
    ULONGLONG total = 0;

    while (ReadFile(hFile, buf, sizeof(buf), &bytes_read, nullptr) && bytes_read > 0) {
        for (DWORD i = 0; i < bytes_read; ++i) freq[buf[i]]++;
        total += bytes_read;
    }
    CloseHandle(hFile);

    if (total == 0) return 0.0;

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / total;
        entropy -= p * log2(p);
    }
    return entropy;
}

bool FileScanner::IsHighEntropy(double entropy) {
    return entropy >= ENTROPY_THRESHOLD;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

bool FileScanner::MatchesHashDatabase(const std::string& sha256, std::string& out_name) {
    return impl_->sig_db.LookupHash(sha256, out_name);
}

ThreatLevel FileScanner::EvaluateThreatLevel(
    const std::string& threat_name,
    const std::string& detection_type)
{
    if (detection_type == "SIGNATURE") return ThreatLevel::MALICIOUS;
    if (threat_name.find("Botnet")  != std::string::npos) return ThreatLevel::CRITICAL;
    if (threat_name.find("Rootkit") != std::string::npos) return ThreatLevel::CRITICAL;
    if (detection_type == "YARA")    return ThreatLevel::MALICIOUS;
    return ThreatLevel::SUSPICIOUS;
}

size_t FileScanner::GetSignatureCount() const { return impl_->sig_db.Count(); }

} // namespace scanner
} // namespace nullbot
