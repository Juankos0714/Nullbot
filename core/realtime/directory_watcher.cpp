/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/realtime/directory_watcher.cpp
 */

#include "core/realtime/directory_watcher.h"

#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

namespace nullbot {
namespace realtime {

// ─── Extension filter ─────────────────────────────────────────────────────────

bool DirectoryWatcher::IsWatchedExtension(const std::wstring& ext_lower) {
    static const std::wstring kWatched[] = {
        L".exe", L".dll", L".bat", L".ps1",
        L".vbs", L".js",  L".cmd", L".scr",
    };
    for (const auto& e : kWatched) {
        if (ext_lower == e) return true;
    }
    return false;
}

// ─── Constructor / Destructor ─────────────────────────────────────────────────

DirectoryWatcher::DirectoryWatcher(const std::wstring& path, FileCreatedCallback callback)
    : watch_path_(path), callback_(std::move(callback))
{}

DirectoryWatcher::~DirectoryWatcher() {
    Stop();
}

// ─── Start / Stop ─────────────────────────────────────────────────────────────

bool DirectoryWatcher::Start() {
    // Open with overlapped flag so ReadDirectoryChangesW is asynchronous.
    dir_handle_ = CreateFileW(
        watch_path_.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );
    if (dir_handle_ == INVALID_HANDLE_VALUE) return false;

    // Manual-reset event — WatchLoop will signal when done draining after stop.
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_event_) {
        CloseHandle(dir_handle_);
        dir_handle_ = INVALID_HANDLE_VALUE;
        return false;
    }

    watch_thread_ = std::thread(&DirectoryWatcher::WatchLoop, this);
    return true;
}

void DirectoryWatcher::Stop() {
    if (stop_event_) SetEvent(stop_event_);

    if (watch_thread_.joinable()) watch_thread_.join();

    if (stop_event_) {
        CloseHandle(stop_event_);
        stop_event_ = nullptr;
    }
    if (dir_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(dir_handle_);
        dir_handle_ = INVALID_HANDLE_VALUE;
    }
}

// ─── Watch loop ───────────────────────────────────────────────────────────────

void DirectoryWatcher::WatchLoop() {
    // Each pending ReadDirectoryChangesW call uses this OVERLAPPED.
    // The embedded hEvent is signaled when I/O completes.
    OVERLAPPED ov   = {};
    HANDLE io_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!io_event) return;
    ov.hEvent = io_event;

    constexpr DWORD kBufSize = 65536;
    std::vector<BYTE> buf(kBufSize);

    // WaitForMultipleObjects checks io_event first, then stop_event_.
    HANDLE handles[2] = { io_event, stop_event_ };

    while (true) {
        ResetEvent(io_event);

        BOOL ok = ReadDirectoryChangesW(
            dir_handle_,
            buf.data(),
            static_cast<DWORD>(buf.size()),
            FALSE,  // do not recurse into subdirectories
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
            nullptr,          // lpBytesReturned — must be nullptr for async
            &ov,
            nullptr           // no APC completion routine; use hEvent instead
        );
        if (!ok) break;

        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

        if (wait == WAIT_OBJECT_0 + 1) {
            // Stop signaled: cancel the pending I/O from this thread, then drain it.
            // CancelIo only cancels I/O issued by the current thread, which is correct.
            CancelIo(dir_handle_);
            DWORD drained = 0;
            GetOverlappedResult(dir_handle_, &ov, &drained, TRUE);
            break;
        }

        if (wait != WAIT_OBJECT_0) break;  // WAIT_FAILED or unexpected

        DWORD bytes_returned = 0;
        if (!GetOverlappedResult(dir_handle_, &ov, &bytes_returned, FALSE)) break;
        if (bytes_returned > 0) ParseNotifications(buf.data(), bytes_returned);
    }

    CloseHandle(io_event);
}

// ─── Notification parsing ─────────────────────────────────────────────────────

void DirectoryWatcher::ParseNotifications(const BYTE* buffer, DWORD buffer_len) {
    const auto* fni = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buffer);
    const BYTE* end = buffer + buffer_len;

    for (;;) {
        // Bounds check before dereferencing variable-length struct.
        if (reinterpret_cast<const BYTE*>(fni) + offsetof(FILE_NOTIFY_INFORMATION, FileName) > end)
            break;

        if (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_MODIFIED) {
            // FileName is NOT null-terminated; length is in bytes.
            std::wstring filename(fni->FileName, fni->FileNameLength / sizeof(WCHAR));

            size_t dot = filename.rfind(L'.');
            if (dot != std::wstring::npos) {
                std::wstring ext = filename.substr(dot);
                std::transform(ext.begin(), ext.end(), ext.begin(),
                               [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });

                if (IsWatchedExtension(ext)) {
                    callback_(watch_path_ + L"\\" + filename);
                }
            }
        }

        if (fni->NextEntryOffset == 0) break;
        fni = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(
            reinterpret_cast<const BYTE*>(fni) + fni->NextEntryOffset);
    }
}

} // namespace realtime
} // namespace nullbot
