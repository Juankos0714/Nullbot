/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/unit/test_directory_watcher.cpp
 *
 * Tests for DirectoryWatcher. Each test creates its own temporary directory
 * to avoid cross-test interference. No shared mutable state between tests.
 */

#include "tests/test_runner.h"
#include "core/realtime/directory_watcher.h"

#include <windows.h>

#include <atomic>
#include <string>

// ─── Helpers ──────────────────────────────────────────────────────────────────

namespace {

// Create a uniquely named temporary directory and return its path.
// The caller is responsible for cleanup (RemoveDirectoryW + DeleteFileW contents).
std::wstring MakeTempWatchDir(const wchar_t* prefix) {
    wchar_t base[MAX_PATH];
    GetTempPathW(MAX_PATH, base);

    wchar_t placeholder[MAX_PATH];
    GetTempFileNameW(base, prefix, 0, placeholder);
    DeleteFileW(placeholder);           // GetTempFileName creates a file; replace with dir
    CreateDirectoryW(placeholder, nullptr);
    return placeholder;
}

// Create an empty file at path. Returns true on success.
bool CreateEmptyFile(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

// Busy-wait until predicate is true or timeout_ms elapses.
// Polls every 10 ms. Returns true if predicate became true.
template<typename Pred>
bool WaitFor(Pred pred, DWORD timeout_ms) {
    DWORD elapsed = 0;
    while (elapsed < timeout_ms) {
        if (pred()) return true;
        Sleep(10);
        elapsed += 10;
    }
    return pred();  // one final check
}

} // namespace

// ─── Tests ────────────────────────────────────────────────────────────────────

TEST_CASE(DirectoryWatcher_Start_ReturnsTrueForExistingDir) {
    wchar_t temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);

    nullbot::realtime::DirectoryWatcher watcher(
        temp_dir,
        [](const std::wstring&) {}
    );

    REQUIRE(watcher.Start());
    watcher.Stop();
}

TEST_CASE(DirectoryWatcher_Start_ReturnsFalseForNonexistentDir) {
    nullbot::realtime::DirectoryWatcher watcher(
        L"C:\\NullBot_NonExistent_Dir_FFFFFFFF_Test\\",
        [](const std::wstring&) {}
    );
    REQUIRE_FALSE(watcher.Start());
}

TEST_CASE(DirectoryWatcher_Callback_InvokedForExeCreation) {
    std::wstring watch_dir = MakeTempWatchDir(L"nbx");

    std::atomic<bool> called{ false };

    nullbot::realtime::DirectoryWatcher watcher(
        watch_dir,
        [&](const std::wstring& /*path*/) {
            called.store(true, std::memory_order_release);
        }
    );

    REQUIRE(watcher.Start());

    // Allow the watcher thread to issue its first ReadDirectoryChangesW.
    Sleep(50);

    std::wstring exe_path = watch_dir + L"\\nullbot_test.exe";
    REQUIRE(CreateEmptyFile(exe_path));

    // Notification must arrive within 2 seconds (acceptance criterion: < 500 ms).
    bool arrived = WaitFor([&] {
        return called.load(std::memory_order_acquire);
    }, 2000);

    watcher.Stop();

    DeleteFileW(exe_path.c_str());
    RemoveDirectoryW(watch_dir.c_str());

    REQUIRE(arrived);
}

TEST_CASE(DirectoryWatcher_Stop_CompletesWithinOneSecond) {
    wchar_t temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);

    nullbot::realtime::DirectoryWatcher watcher(
        temp_dir,
        [](const std::wstring&) {}
    );
    REQUIRE(watcher.Start());

    DWORD t0      = GetTickCount();
    watcher.Stop();
    DWORD elapsed = GetTickCount() - t0;

    REQUIRE(elapsed < 1000);
}

TEST_CASE(DirectoryWatcher_Callback_NotInvokedForTxt) {
    std::wstring watch_dir = MakeTempWatchDir(L"nbt");

    std::atomic<bool> called{ false };

    nullbot::realtime::DirectoryWatcher watcher(
        watch_dir,
        [&](const std::wstring&) {
            called.store(true, std::memory_order_release);
        }
    );

    REQUIRE(watcher.Start());
    Sleep(50);  // let watcher thread arm ReadDirectoryChangesW

    std::wstring txt_path = watch_dir + L"\\nullbot_test.txt";
    REQUIRE(CreateEmptyFile(txt_path));

    // Wait 500 ms — a .txt creation must NOT trigger the callback.
    Sleep(500);

    watcher.Stop();

    DeleteFileW(txt_path.c_str());
    RemoveDirectoryW(watch_dir.c_str());

    REQUIRE_FALSE(called.load());
}
