#pragma once

/*
 * NullBot — PE Heuristic Analyzer
 * File: core/heuristic/pe_analyzer.h
 *
 * Parses Windows PE headers to detect suspicious characteristics
 * commonly found in malware and botnet agents.
 */

#include <windows.h>
#include <string>
#include <vector>

namespace nullbot {
namespace heuristic {

// ─── Suspicious import categories ─────────────────────────────────────────────

struct SuspiciousImport {
    std::string dll_name;
    std::string function_name;
    std::string reason;  // Why this import is suspicious
};

// ─── PE analysis result ───────────────────────────────────────────────────────

struct PEInfo {
    bool is_pe             = false;
    bool is_64bit          = false;
    bool is_dll            = false;
    bool is_packed         = false;
    bool has_valid_sections = true;

    std::string entry_point_section;  // Unusual if not .text
    DWORD       section_count     = 0;
    DWORD       import_count      = 0;
    double      text_entropy      = 0.0;

    std::vector<SuspiciousImport> suspicious_imports;
    std::vector<std::string>      suspicious_sections;  // Sections with odd names/flags
};

// ─── PE Analyzer ──────────────────────────────────────────────────────────────

class PEAnalyzer {
public:
    explicit PEAnalyzer(const std::wstring& file_path);
    ~PEAnalyzer();

    bool IsExecutable() const;
    bool IsValid()      const;

    // Returns suspicious imports found (process injection, evasion, C2 comms)
    std::vector<SuspiciousImport> GetSuspiciousImports();

    // Returns true if anti-debug techniques are detected in imports/sections
    bool HasAntiDebugTechniques();

    // Returns true if typical process hollowing APIs are found together
    bool HasProcessHollowingPattern();

    // Returns true if typical keylogger APIs are present
    bool HasKeyloggerPattern();

    // Full analysis result
    PEInfo Analyze();

private:
    std::wstring  file_path_;
    HANDLE        hFile_  = INVALID_HANDLE_VALUE;
    HANDLE        hMap_   = nullptr;
    LPVOID        base_   = nullptr;
    bool          loaded_ = false;

    IMAGE_DOS_HEADER*    dos_header_  = nullptr;
    IMAGE_NT_HEADERS*    nt_headers_  = nullptr;
    IMAGE_SECTION_HEADER* sections_   = nullptr;
    WORD                  section_count_ = 0;

    bool Load();
    void Unload();

    void ParseImports(std::vector<SuspiciousImport>& out);
    LPVOID RvaToVa(DWORD rva);

    // Known suspicious imports — process injection, evasion, persistence
    static const std::vector<std::pair<std::string, std::string>> SUSPICIOUS_APIS;
};

// ─── Known suspicious API combinations ───────────────────────────────────────
// Format: { "FunctionName", "Reason" }

inline const std::vector<std::pair<std::string, std::string>> PEAnalyzer::SUSPICIOUS_APIS = {
    // Process injection
    { "VirtualAllocEx",         "Remote memory allocation — process injection" },
    { "WriteProcessMemory",     "Remote memory write — process injection" },
    { "NtUnmapViewOfSection",   "Process hollowing — unmaps host process image" },
    { "ZwUnmapViewOfSection",   "Process hollowing — unmaps host process image (Zw variant)" },
    { "CreateRemoteThread",     "Thread creation in remote process — injection" },
    { "NtCreateThreadEx",       "Undocumented thread creation — stealth injection" },
    { "RtlCreateUserThread",    "Undocumented thread creation — stealth injection" },
    { "QueueUserAPC",           "APC injection technique" },
    { "SetWindowsHookEx",       "Global hook — keylogger / injection" },

    // Anti-debug / evasion
    { "IsDebuggerPresent",      "Anti-debug check" },
    { "CheckRemoteDebuggerPresent", "Anti-debug check" },
    { "NtQueryInformationProcess",  "Anti-debug / process hiding" },
    { "NtSetInformationThread", "Thread hiding from debugger" },
    { "OutputDebugStringA",     "Anti-debug timing check" },
    { "ZwQuerySystemInformation","Rootkit / process hiding" },

    // Persistence
    { "RegSetValueEx",          "Registry modification — possible persistence" },
    { "SHGetSpecialFolderPath", "Locating system folders — possible self-copy" },

    // Network / C2
    { "WSAStartup",             "Network initialization" },
    { "connect",                "Direct socket connection" },
    { "InternetOpenUrl",        "HTTP request — possible C2 beacon" },
    { "HttpSendRequest",        "HTTP request — possible C2 beacon" },
    { "WinHttpConnect",         "HTTP request — possible C2 beacon" },
    { "URLDownloadToFile",      "File download — dropper behavior" },

    // Code injection
    { "LoadLibraryA",           "Dynamic library loading — possible shellcode" },
    { "GetProcAddress",         "Dynamic API resolution — common in shellcode" },
    { "VirtualProtect",         "Memory protection change — shellcode preparation" },
};

} // namespace heuristic
} // namespace nullbot
