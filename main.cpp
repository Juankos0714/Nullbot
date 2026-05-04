/*
 * NullBot — CLI Entry Point
 * File: main.cpp
 *
 * Command-line interface for scanning and monitoring.
 * The UI (WPF) is a separate project that uses this engine via named pipe IPC.
 *
 * Usage:
 *   nullbot_cli.exe --scan --path "C:\Users\..."
 *   nullbot_cli.exe --watch          (real-time protection)
 *   nullbot_cli.exe --update         (update signatures)
 *   nullbot_cli.exe --quarantine list
 */

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>

#include "core/scanner/scanner.h"
#include "core/quarantine/quarantine.h"
#include "network/c2_detection/c2_detector.h"

namespace fs = std::filesystem;
using namespace nullbot;

// ─── Globals ──────────────────────────────────────────────────────────────────

static const std::wstring DATA_DIR   = L"C:\\ProgramData\\NullBot";
static const std::wstring QUARANTINE = DATA_DIR + L"\\quarantine";
static const std::string  SIG_DB     = "C:\\ProgramData\\NullBot\\signatures";

// ─── Console helpers ──────────────────────────────────────────────────────────

void PrintBanner() {
    SetConsoleOutputCP(CP_UTF8);
    std::wcout << L"\n";
    std::wcout << L"  ███╗   ██╗██╗   ██╗██╗     ██╗     ██████╗  ██████╗ ████████╗\n";
    std::wcout << L"  ████╗  ██║██║   ██║██║     ██║     ██╔══██╗██╔═══██╗╚══██╔══╝\n";
    std::wcout << L"  ██╔██╗ ██║██║   ██║██║     ██║     ██████╔╝██║   ██║   ██║   \n";
    std::wcout << L"  ██║╚██╗██║██║   ██║██║     ██║     ██╔══██╗██║   ██║   ██║   \n";
    std::wcout << L"  ██║ ╚████║╚██████╔╝███████╗███████╗██████╔╝╚██████╔╝   ██║   \n";
    std::wcout << L"  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═════╝  ╚═════╝   ╚═╝   \n";
    std::wcout << L"\n  Open Source Anti-Botnet  |  v0.1.0-alpha  |  GPL-3.0\n\n";
}

void PrintHelp() {
    std::wcout <<
        L"Usage:\n"
        L"  nullbot_cli.exe --scan --path <dir>   Scan a directory\n"
        L"  nullbot_cli.exe --scan --quick        Scan common infection points\n"
        L"  nullbot_cli.exe --watch               Start real-time protection\n"
        L"  nullbot_cli.exe --update              Update threat signatures\n"
        L"  nullbot_cli.exe --quarantine list     List quarantined files\n"
        L"  nullbot_cli.exe --quarantine restore <id>  Restore a quarantined file\n"
        L"\nOptions:\n"
        L"  --no-heuristics    Disable heuristic analysis\n"
        L"  --auto-quarantine  Automatically quarantine detections\n"
        L"  --verbose          Show all scanned files\n\n";
}

void SetConsoleColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void PrintThreat(const scanner::ScanResult& r) {
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::wcout << L"  [THREAT] ";
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::wcout << r.file_path << L"\n";

    SetConsoleColor(FOREGROUND_RED);
    std::wcout << L"    Name:   " << std::wstring(r.threat_name.begin(), r.threat_name.end()) << L"\n";
    std::wcout << L"    Type:   " << std::wstring(r.detection_type.begin(), r.detection_type.end()) << L"\n";
    std::wcout << L"    SHA256: " << std::wstring(r.sha256.begin(), r.sha256.end()) << L"\n";
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// ─── Scan command ─────────────────────────────────────────────────────────────

int CmdScan(const std::vector<std::wstring>& args) {
    std::wstring scan_path;
    bool auto_quarantine = false;
    bool verbose         = false;
    bool no_heuristics   = false;

    // Parse args
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == L"--path" && i + 1 < args.size()) {
            scan_path = args[++i];
        } else if (args[i] == L"--quick") {
            scan_path = L"";  // Will use default high-risk dirs
        } else if (args[i] == L"--auto-quarantine") {
            auto_quarantine = true;
        } else if (args[i] == L"--verbose") {
            verbose = true;
        } else if (args[i] == L"--no-heuristics") {
            no_heuristics = true;
        }
    }

    // Default quick scan paths (common infection points)
    std::vector<std::wstring> scan_targets;
    if (scan_path.empty()) {
        WCHAR appdata[MAX_PATH], temp[MAX_PATH], startup[MAX_PATH];
        ExpandEnvironmentStringsW(L"%APPDATA%",  appdata,  MAX_PATH);
        ExpandEnvironmentStringsW(L"%TEMP%",     temp,     MAX_PATH);
        ExpandEnvironmentStringsW(L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                                  startup, MAX_PATH);

        scan_targets = { appdata, temp, startup };
        std::wcout << L"  Quick scan: checking " << scan_targets.size() << L" high-risk directories\n\n";
    } else {
        scan_targets = { scan_path };
    }

    // Initialize scanner
    scanner::FileScanner engine(SIG_DB);
    if (!engine.Initialize()) {
        std::wcerr << L"[ERROR] Failed to initialize scanner. Check signature database at: "
                   << std::wstring(SIG_DB.begin(), SIG_DB.end()) << L"\n";
        return 1;
    }

    std::wcout << L"  Loaded: " << engine.GetSignatureCount() << L" hash signatures, "
               << engine.GetYaraRuleCount() << L" YARA rules\n\n";

    quarantine::QuarantineManager qm(QUARANTINE);
    if (auto_quarantine) qm.Initialize();

    scanner::ScanOptions opts;
    opts.use_heuristics   = !no_heuristics;
    opts.auto_quarantine  = auto_quarantine;

    size_t total_threats = 0;
    auto start_time = GetTickCount64();

    for (const auto& target : scan_targets) {
        std::wcout << L"  Scanning: " << target << L"\n";

        auto results = engine.ScanDirectory(
            target, opts,
            [&](const std::wstring& file, size_t scanned, size_t total) {
                if (verbose) {
                    std::wcout << L"  [" << scanned << L"/" << total << L"] " << file << L"\r";
                } else {
                    std::wcout << L"  Progress: " << scanned << L"/" << total << L"\r";
                }
            },
            [&](const scanner::ScanResult& r) {
                std::wcout << L"\n";
                PrintThreat(r);
                total_threats++;

                if (auto_quarantine) {
                    qm.Quarantine(r.file_path, r.threat_name, r.detection_type, r.sha256);
                    std::wcout << L"    → Quarantined\n";
                }
            }
        );
    }

    ULONGLONG elapsed = (GetTickCount64() - start_time) / 1000;
    std::wcout << L"\n\n  ──────────────────────────────────\n";
    std::wcout << L"  Scan complete in " << elapsed << L"s\n";

    if (total_threats == 0) {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"  ✓ No threats found\n";
    } else {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"  ✗ " << total_threats << L" threat(s) detected\n";
        if (!auto_quarantine) {
            std::wcout << L"    Run with --auto-quarantine to remove them\n";
        }
    }
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    return total_threats > 0 ? 2 : 0;
}

// ─── Watch command (real-time protection) ────────────────────────────────────

int CmdWatch() {
    std::wcout << L"  Starting real-time protection...\n";
    std::wcout << L"  Press Ctrl+C to stop.\n\n";

    network::C2Detector c2;
    c2.LoadBlacklists(SIG_DB);
    c2.StartMonitoring([](const network::C2Alert& alert) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
            FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"\n  [C2 ALERT] ";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        std::wcout
            << std::wstring(alert.process_name.begin(), alert.process_name.end())
            << L" (PID " << alert.pid << L")\n"
            << L"    Indicator: " << std::wstring(alert.indicator.begin(), alert.indicator.end()) << L"\n"
            << L"    Method:    " << std::wstring(alert.detection_method.begin(), alert.detection_method.end()) << L"\n"
            << L"    Info:      " << std::wstring(alert.description.begin(), alert.description.end()) << L"\n";
    });

    // Block until Ctrl+C
    SetConsoleCtrlHandler([](DWORD) -> BOOL { return TRUE; }, TRUE);
    WaitForSingleObject(GetCurrentProcess(), INFINITE);
    return 0;
}

// ─── Quarantine command ───────────────────────────────────────────────────────

int CmdQuarantine(const std::vector<std::wstring>& args) {
    quarantine::QuarantineManager qm(QUARANTINE);
    if (!qm.Initialize()) {
        std::wcerr << L"[ERROR] Could not initialize quarantine.\n";
        return 1;
    }

    if (args.empty() || args[0] == L"list") {
        auto items = qm.ListAll();
        if (items.empty()) {
            std::wcout << L"  Quarantine is empty.\n";
            return 0;
        }

        std::wcout << L"  ID  | Threat Name                       | Date\n";
        std::wcout << L"  ────┼───────────────────────────────────┼──────────────────────\n";
        for (const auto& item : items) {
            std::wcout << L"  " << item.id << L"   | "
                       << std::wstring(item.threat_name.begin(), item.threat_name.end())
                       << L" | " << std::wstring(item.quarantine_date.begin(), item.quarantine_date.end())
                       << L"\n";
        }
        std::wcout << L"\n  Total: " << items.size() << L" item(s)\n";

    } else if (args[0] == L"restore" && args.size() >= 2) {
        int id = std::stoi(args[1]);
        if (qm.Restore(id)) {
            std::wcout << L"  ✓ File restored successfully.\n";
        } else {
            std::wcerr << L"  ✗ Restore failed. Check quarantine ID.\n";
            return 1;
        }
    }

    return 0;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

int wmain(int argc, wchar_t* argv[]) {
    PrintBanner();

    if (argc < 2) {
        PrintHelp();
        return 0;
    }

    std::vector<std::wstring> args(argv + 1, argv + argc);
    std::wstring cmd = args[0];

    if (cmd == L"--scan") {
        return CmdScan(std::vector<std::wstring>(args.begin() + 1, args.end()));
    } else if (cmd == L"--watch") {
        return CmdWatch();
    } else if (cmd == L"--quarantine") {
        return CmdQuarantine(std::vector<std::wstring>(args.begin() + 1, args.end()));
    } else if (cmd == L"--update") {
        std::wcout << L"  Run: python signatures/updater/update_feeds.py\n";
        return 0;
    } else if (cmd == L"--help" || cmd == L"-h") {
        PrintHelp();
        return 0;
    } else {
        std::wcerr << L"  Unknown command: " << cmd << L"\n";
        PrintHelp();
        return 1;
    }
}
