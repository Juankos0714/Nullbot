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
#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>

#include "core/scanner/scanner.h"
#include "core/quarantine/quarantine.h"
#include "core/realtime/realtime_protection.h"
#include "network/c2_detection/c2_detector.h"
#include "network/monitor/net_monitor.h"

namespace fs = std::filesystem;
using namespace nullbot;

// ─── Globals ──────────────────────────────────────────────────────────────────

static const std::wstring DATA_DIR   = L"C:\\ProgramData\\NullBot";
static const std::wstring QUARANTINE = DATA_DIR + L"\\quarantine";
static const std::string  SIG_DB     = "C:\\ProgramData\\NullBot\\signatures";

// True when stdout is a pipe (running from UI); false when interactive console.
static bool g_piped = false;

// ─── Console helpers ──────────────────────────────────────────────────────────

// Map detection_type string to a severity label understood by the UI parser.
static std::wstring MapSeverity(const std::string& detection_type) {
    std::string upper = detection_type;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    if (upper == "HEURISTIC") return L"MEDIUM";
    if (upper == "C2" || upper == "DGA" || upper == "BEHAVIORAL") return L"HIGH";
    return L"CRITICAL";
}

void PrintBanner() {
    if (g_piped) return;
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
    if (g_piped) return;
    std::wcout <<
        L"Usage:\n"
        L"  nullbot_cli.exe --scan --path <dir>   Scan a directory\n"
        L"  nullbot_cli.exe --scan --quick        Scan common infection points\n"
        L"  nullbot_cli.exe --watch               Start real-time protection\n"
        L"  nullbot_cli.exe --update              Update threat signatures\n"
        L"  nullbot_cli.exe --status              Show protection status\n"
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
        if (!g_piped) std::wcout << L"  Scanning: " << target << L"\n";

        auto results = engine.ScanDirectory(
            target, opts,
            [&](const std::wstring& file, size_t scanned, size_t total) {
                if (g_piped) {
                    std::wcout << L"PROGRESS: " << scanned << L"/" << total << L"\n";
                    if (verbose) std::wcout << L"FILE: " << file << L"\n";
                    std::wcout.flush();
                } else if (verbose) {
                    std::wcout << L"  [" << scanned << L"/" << total << L"] " << file << L"\r";
                } else {
                    std::wcout << L"  Progress: " << scanned << L"/" << total << L"\r";
                }
            },
            [&](const scanner::ScanResult& r) {
                total_threats++;

                if (g_piped) {
                    auto wname = std::wstring(r.threat_name.begin(), r.threat_name.end());
                    auto wtype = std::wstring(r.detection_type.begin(), r.detection_type.end());
                    auto whash = std::wstring(r.sha256.begin(), r.sha256.end());
                    std::wcout << L"THREAT: " << MapSeverity(r.detection_type)
                               << L"|" << wname
                               << L"|" << r.file_path
                               << L"|" << wtype
                               << L"|" << whash << L"\n";
                    std::wcout.flush();
                } else {
                    std::wcout << L"\n";
                    PrintThreat(r);
                }

                if (auto_quarantine) {
                    qm.Quarantine(r.file_path, r.threat_name, r.detection_type, r.sha256);
                    if (!g_piped) std::wcout << L"    → Quarantined\n";
                }
            }
        );
    }

    ULONGLONG elapsed = (GetTickCount64() - start_time) / 1000;
    if (!g_piped) {
        std::wcout << L"\n\n  ──────────────────────────────────\n";
        std::wcout << L"  Scan complete in " << elapsed << L"s\n";
        if (total_threats == 0) {
            SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::wcout << L"  No threats found\n";
        } else {
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::wcout << L"  " << total_threats << L" threat(s) detected\n";
            if (!auto_quarantine)
                std::wcout << L"    Run with --auto-quarantine to remove them\n";
        }
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    return total_threats > 0 ? 2 : 0;
}

// ─── Update command ───────────────────────────────────────────────────────────

int CmdUpdate(const std::vector<std::wstring>& args) {
    // Locate update_feeds.py relative to this executable (build/bin -> project root)
    wchar_t exe_buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe_buf, MAX_PATH);
    std::wstring exe_dir(exe_buf);
    auto slash = exe_dir.rfind(L'\\');
    if (slash != std::wstring::npos) exe_dir = exe_dir.substr(0, slash);

    std::wstring script = exe_dir + L"\\..\\..\\signatures\\updater\\update_feeds.py";

    std::wstring cmd = L"python \"" + script + L"\"";
    for (const auto& a : args) {
        cmd += L" ";
        cmd += a;
    }

    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE read_pipe = nullptr, write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
        std::wcerr << L"  [ERROR] Could not create pipe.\n";
        return 1;
    }
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{ sizeof(STARTUPINFOW) };
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = write_pipe;
    si.hStdError  = write_pipe;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr,
                             TRUE, 0, nullptr, nullptr, &si, &pi);
    CloseHandle(write_pipe);

    if (!ok) {
        CloseHandle(read_pipe);
        std::wcerr << L"  [ERROR] Could not launch Python. Ensure 'python' is in PATH.\n"
                   << L"  Manual: python signatures\\updater\\update_feeds.py\n";
        return 1;
    }

    char buf[4096];
    DWORD bytes_read = 0;
    while (ReadFile(read_pipe, buf, sizeof(buf) - 1, &bytes_read, nullptr)
           && bytes_read > 0) {
        buf[bytes_read] = '\0';
        std::cout << buf;
        std::cout.flush();
    }
    CloseHandle(read_pipe);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exit_code);
}

// ─── Status command ───────────────────────────────────────────────────────────

int CmdStatus() {
    std::wcout << L"  NullBot — Protection Status\n";
    std::wcout << L"  ───────────────────────────\n\n";

    // Signature database
    scanner::FileScanner engine(SIG_DB);
    bool sig_ok = engine.Initialize();
    std::wcout << L"  Signatures:    " << engine.GetSignatureCount() << L" hashes";
    if (engine.GetYaraRuleCount() > 0)
        std::wcout << L", " << engine.GetYaraRuleCount() << L" YARA rules";
    if (!sig_ok) std::wcout << L"  [DB not found]";
    std::wcout << L"\n";

    // Last update time from signatures.db file modification time
    std::wstring db_file = std::wstring(SIG_DB.begin(), SIG_DB.end()) + L"\\signatures.db";
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (GetFileAttributesExW(db_file.c_str(), GetFileExInfoStandard, &fad)) {
        SYSTEMTIME utc{}, local_st{};
        FileTimeToSystemTime(&fad.ftLastWriteTime, &utc);
        SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local_st);
        wchar_t ts[32];
        swprintf_s(ts, L"%04hu-%02hu-%02hu %02hu:%02hu",
                   local_st.wYear, local_st.wMonth, local_st.wDay,
                   local_st.wHour, local_st.wMinute);
        std::wcout << L"  Last updated:  " << ts << L"\n";
    } else {
        std::wcout << L"  Last updated:  never (run --update)\n";
    }

    // Quarantine
    quarantine::QuarantineManager qm(QUARANTINE);
    qm.Initialize();
    std::wcout << L"  Quarantine:    " << qm.GetCount() << L" file(s)";
    ULONGLONG total_bytes = qm.GetTotalSize();
    if (total_bytes > 0)
        std::wcout << L", " << (total_bytes / 1024) << L" KB";
    std::wcout << L"\n";

    // Real-time protection — the CLI does not own the watcher; indicate how to start
    std::wcout << L"  Real-time:     inactive (run '--watch' to activate)\n\n";
    return 0;
}

// ─── Watch command (real-time protection) ────────────────────────────────────

// Shared stop event — must be visible to the Ctrl+C handler (static linkage).
static HANDLE g_watch_stop_event = nullptr;

int CmdWatch() {
    g_watch_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_watch_stop_event) return 1;

    SetConsoleCtrlHandler([](DWORD) -> BOOL {
        if (g_watch_stop_event) SetEvent(g_watch_stop_event);
        return TRUE;
    }, TRUE);

    auto PrintC2Alert = [](const network::C2Alert& alert) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"\n  [C2 ALERT] ";
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::wcout
            << std::wstring(alert.process_name.begin(), alert.process_name.end())
            << L" (PID " << alert.pid << L")\n"
            << L"    Method:    "
            << std::wstring(alert.detection_method.begin(), alert.detection_method.end())
            << L"\n    Indicator: "
            << std::wstring(alert.indicator.begin(), alert.indicator.end()) << L"\n";
    };

    // C2 network detector
    network::C2Detector c2;
    c2.LoadBlacklists(SIG_DB);
    c2.StartMonitoring(PrintC2Alert);

    // Network connection poller
    network::NetMonitor net_mon;
    net_mon.StartPolling(c2, 5000);

    // Filesystem real-time protection (scanner + optional auto-quarantine)
    realtime::RealTimeProtection rtp(SIG_DB, QUARANTINE);
    rtp.SetThreatCallback([](const scanner::ScanResult& r) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"\n  [THREAT] ";
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::wcout << r.file_path << L"\n"
                   << L"    Name: "
                   << std::wstring(r.threat_name.begin(), r.threat_name.end()) << L"\n";
    });
    rtp.Start(false);

    std::wcout << L"  Watching %TEMP%, %APPDATA%, Startup folder\n";
    std::wcout << L"  Network polling: every 5 seconds\n";
    std::wcout << L"  Press Ctrl+C to stop.\n\n";

    WaitForSingleObject(g_watch_stop_event, INFINITE);

    net_mon.StopPolling();
    rtp.Stop();
    c2.StopMonitoring();
    CloseHandle(g_watch_stop_event);
    g_watch_stop_event = nullptr;

    std::wcout << L"\n  Real-time protection stopped.\n";
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
    // Detect whether stdout is a pipe (UI mode) or an interactive console.
    g_piped = !_isatty(_fileno(stdout));
    if (g_piped) {
        // Put stdout in UTF-8 text mode so wcout writes UTF-8 bytes to the pipe.
        _setmode(_fileno(stdout), _O_U8TEXT);
    } else {
        SetConsoleOutputCP(CP_UTF8);
    }

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
    } else if (cmd == L"--update") {
        return CmdUpdate(std::vector<std::wstring>(args.begin() + 1, args.end()));
    } else if (cmd == L"--status") {
        return CmdStatus();
    } else if (cmd == L"--quarantine") {
        return CmdQuarantine(std::vector<std::wstring>(args.begin() + 1, args.end()));
    } else if (cmd == L"--help" || cmd == L"-h") {
        PrintHelp();
        return 0;
    } else {
        std::wcerr << L"  Unknown command: " << cmd << L"\n";
        PrintHelp();
        return 1;
    }
}
