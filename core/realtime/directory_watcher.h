#pragma once

/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/realtime/directory_watcher.h
 *
 * Monitors a single directory for file creation and modification events
 * and invokes a callback for files with watched extensions.
 * Uses ReadDirectoryChangesW with overlapped I/O on a dedicated thread.
 *
 * Thread-safety: Start()/Stop() are not thread-safe with each other;
 *   call them from a single owner thread. The callback fires on the
 *   watcher thread.
 */

#include <windows.h>

#include <functional>
#include <string>
#include <thread>

namespace nullbot {
namespace realtime {

class DirectoryWatcher {
public:
    using FileCreatedCallback = std::function<void(const std::wstring& file_path)>;

    DirectoryWatcher(const std::wstring& path, FileCreatedCallback callback);
    ~DirectoryWatcher();

    // Non-copyable, non-movable — owns OS handles and a live thread.
    DirectoryWatcher(const DirectoryWatcher&)            = delete;
    DirectoryWatcher& operator=(const DirectoryWatcher&) = delete;

    // Open the directory handle and start the watcher thread.
    // Returns false if the directory does not exist or cannot be opened.
    bool Start();

    // Signal the watcher thread to stop and block until it exits.
    // Safe to call even if Start() was never called or returned false.
    void Stop();

private:
    // Entry point for the watcher thread — issues and re-issues
    // ReadDirectoryChangesW in a loop until stop_event_ is signaled.
    void WatchLoop();

    // Parse a contiguous buffer of FILE_NOTIFY_INFORMATION records
    // and invoke callback_ for each entry that passes the extension filter.
    void ParseNotifications(const BYTE* buffer, DWORD buffer_len);

    // Returns true for extensions NullBot watches:
    // .exe .dll .bat .ps1 .vbs .js .cmd .scr
    static bool IsWatchedExtension(const std::wstring& ext_lower);

    std::wstring        watch_path_;
    FileCreatedCallback callback_;
    HANDLE              dir_handle_  = INVALID_HANDLE_VALUE;
    HANDLE              stop_event_  = nullptr;
    std::thread         watch_thread_;
};

} // namespace realtime
} // namespace nullbot
