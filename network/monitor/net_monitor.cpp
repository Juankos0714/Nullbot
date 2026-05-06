/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: network/monitor/net_monitor.cpp
 */

// Winsock2 must precede windows.h to avoid winsock1 conflicts
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "network/monitor/net_monitor.h"
#include "network/c2_detection/c2_detector.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace nullbot {
namespace network {

// ─── File-scope helpers ───────────────────────────────────────────────────────

static std::string FormatIPv4(DWORD ip_net) {
    const auto* b = reinterpret_cast<const unsigned char*>(&ip_net);
    return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." +
           std::to_string(b[2]) + "." + std::to_string(b[3]);
}

static std::string ProcessName(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "unknown";

    wchar_t buf[MAX_PATH]{};
    DWORD   size = MAX_PATH;
    if (!QueryFullProcessImageNameW(h, 0, buf, &size)) {
        CloseHandle(h);
        return "unknown";
    }
    CloseHandle(h);

    std::wstring wp = buf;
    const size_t slash = wp.rfind(L'\\');
    if (slash != std::wstring::npos) wp = wp.substr(slash + 1);

    std::string name;
    name.reserve(wp.size());
    for (wchar_t c : wp)
        name += (c < 128) ? static_cast<char>(c) : '?';
    return name;
}

static void PollConnections(C2Detector& detector) {
    DWORD buf_size = 0;
    GetExtendedTcpTable(nullptr, &buf_size, FALSE, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0);
    if (buf_size == 0) return;

    std::vector<BYTE> buf(buf_size);
    if (GetExtendedTcpTable(buf.data(), &buf_size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return;

    const auto* table =
        reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
        if (row.dwRemoteAddr == 0)               continue;

        const DWORD  pid       = row.dwOwningPid;
        const std::string dest = FormatIPv4(row.dwRemoteAddr);
        const USHORT port      = ntohs(static_cast<USHORT>(row.dwRemotePort));

        detector.InspectConnection(pid, ProcessName(pid), dest, port);
    }
}

// ─── NetMonitor::Impl ─────────────────────────────────────────────────────────

struct NetMonitor::Impl {
    std::atomic<bool> stop_flag{false};
    std::atomic<bool> running{false};
    std::thread       poll_thread;
};

// ─── NetMonitor ───────────────────────────────────────────────────────────────

NetMonitor::NetMonitor()  : impl_(std::make_unique<Impl>()) {}
NetMonitor::~NetMonitor() { StopPolling(); }

void NetMonitor::StartPolling(C2Detector& detector, int interval_ms) {
    if (impl_->running.load()) return;

    impl_->stop_flag = false;
    impl_->running   = true;

    impl_->poll_thread = std::thread([this, &detector, interval_ms]() {
        while (!impl_->stop_flag.load()) {
            PollConnections(detector);
            std::this_thread::sleep_for(
                std::chrono::milliseconds(interval_ms));
        }
    });
}

void NetMonitor::StopPolling() {
    impl_->stop_flag = true;
    if (impl_->poll_thread.joinable())
        impl_->poll_thread.join();
    impl_->running = false;
}

bool NetMonitor::IsRunning() const {
    return impl_->running.load();
}

} // namespace network
} // namespace nullbot
