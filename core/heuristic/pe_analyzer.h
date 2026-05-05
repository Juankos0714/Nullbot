#pragma once
/*
 * NullBot — PE Heuristic Analyzer
 * File: core/heuristic/pe_analyzer.h
 *
 * Parses Windows PE headers to detect suspicious characteristics
 * commonly found in malware and botnet agents.
 */

#include <windows.h>
#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace nullbot {
namespace heuristic {

// ─── Suspicious import categories ─────────────────────────────────────────────

struct SuspiciousImport {
    std::string dll_name;
    std::string function_name;
    std::string reason;
};

// ─── Per-section entropy result ───────────────────────────────────────────────

struct SectionEntropyResult {
    std::string section_name;
    double      entropy;
    bool        is_suspicious;
};

// ─── PE analysis result ───────────────────────────────────────────────────────

struct PEInfo {
    bool is_pe              = false;
    bool is_64bit           = false;
    bool is_dll             = false;
    bool is_packed          = false;
    bool has_valid_sections = true;

    std::string entry_point_section;
    DWORD       section_count   = 0;
    DWORD       import_count    = 0;
    double      text_entropy    = 0.0;

    std::vector<SuspiciousImport>    suspicious_imports;
    std::vector<std::string>         suspicious_sections;
};

// ─── PE Analyzer ──────────────────────────────────────────────────────────────

class PEAnalyzer {
public:
    explicit PEAnalyzer(const std::wstring& file_path);
    ~PEAnalyzer();

    bool IsExecutable() const;
    bool IsValid()      const;

    std::vector<SuspiciousImport>    GetSuspiciousImports();
    std::vector<SectionEntropyResult> GetSectionEntropies();
    std::vector<std::string>         GetSuspiciousSections();

    bool        HasAntiDebugTechniques();
    bool        HasProcessHollowingPattern();
    bool        HasKeyloggerPattern();
    std::string IsPackerSignature();

    PEInfo Analyze();

private:
    std::wstring  file_path_;
    HANDLE        hFile_  = INVALID_HANDLE_VALUE;
    HANDLE        hMap_   = nullptr;
    LPVOID        base_   = nullptr;
    bool          loaded_ = false;

    IMAGE_DOS_HEADER*    dos_header_    = nullptr;
    IMAGE_NT_HEADERS*    nt_headers_    = nullptr;
    IMAGE_SECTION_HEADER* sections_     = nullptr;
    WORD                  section_count_ = 0;

    bool Load();
    void Unload();
    void   ParseImports(std::vector<SuspiciousImport>& out);
    LPVOID RvaToVa(DWORD rva);

    static const std::vector<std::pair<std::string, std::string>> SUSPICIOUS_APIS;
    static const std::array<std::string_view, 12>                 STANDARD_SECTION_NAMES;
};

// ─── Known suspicious APIs ────────────────────────────────────────────────────

inline const std::vector<std::pair<std::string, std::string>> PEAnalyzer::SUSPICIOUS_APIS = {
    // Process injection / hollowing
    { "VirtualAllocEx",             "Remote memory allocation — process injection" },
    { "WriteProcessMemory",         "Remote memory write — process injection" },
    { "NtUnmapViewOfSection",       "Process hollowing — unmaps host process image" },
    { "ZwUnmapViewOfSection",       "Process hollowing — unmaps host process image (Zw variant)" },
    { "CreateRemoteThread",         "Thread creation in remote process — injection" },
    { "NtCreateThreadEx",           "Undocumented thread creation — stealth injection" },
    { "RtlCreateUserThread",        "Undocumented thread creation — stealth injection" },
    { "QueueUserAPC",               "APC injection technique" },

    // Keylogger / hook
    { "SetWindowsHookEx",           "Global hook — keylogger / injection" },
    { "GetAsyncKeyState",           "Key state polling — keylogger indicator" },
    { "GetKeyState",                "Key state polling — keylogger indicator" },

    // Anti-debug / evasion
    { "IsDebuggerPresent",          "Anti-debug check" },
    { "CheckRemoteDebuggerPresent", "Anti-debug check" },
    { "NtQueryInformationProcess",  "Anti-debug / process hiding" },
    { "NtSetInformationThread",     "Anti-debug: thread hiding from debugger" },
    { "OutputDebugStringA",         "Anti-debug timing check" },
    { "ZwQuerySystemInformation",   "Rootkit / process hiding" },

    // Persistence
    { "RegSetValueEx",              "Registry modification — possible persistence" },
    { "SHGetSpecialFolderPath",     "Locating system folders — possible self-copy" },

    // Network / C2
    { "WSAStartup",                 "Network initialization" },
    { "connect",                    "Direct socket connection" },
    { "InternetOpenUrl",            "HTTP request — possible C2 beacon" },
    { "HttpSendRequest",            "HTTP request — possible C2 beacon" },
    { "WinHttpConnect",             "HTTP request — possible C2 beacon" },
    { "URLDownloadToFile",          "File download — dropper behavior" },

    // Memory manipulation
    { "VirtualProtect",             "Memory protection change — shellcode preparation" },
};

// ─── Standard PE section names ────────────────────────────────────────────────
// Sections NOT in this list are flagged by GetSuspiciousSections().

inline const std::array<std::string_view, 12> PEAnalyzer::STANDARD_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".bss", ".rsrc",
    ".reloc", ".pdata", ".edata", ".idata", ".tls",
    ".didat", "fothk"
};

} // namespace heuristic
} // namespace nullbot
