/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/unit/test_scanner.cpp
 */

#include "tests/test_runner.h"
#include "core/scanner/scanner.h"

#include <windows.h>
#include <cstring>

namespace {

std::wstring MakeTempFile() {
    wchar_t dir[MAX_PATH], path[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"nbt", 0, path);
    return path;
}

std::wstring MakeTempDir() {
    wchar_t dir[MAX_PATH], tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"nbd", 0, tmp);
    DeleteFileW(tmp);
    CreateDirectoryW(tmp, nullptr);
    return tmp;
}

} // namespace

// ─── Tests ────────────────────────────────────────────────────────────────────

TEST_CASE(ScanFile_ReturnsClean_ForEmptyTextFile) {
    std::wstring path = MakeTempFile();

    nullbot::scanner::FileScanner scanner{"Z:\\nonexistent"};
    auto result = scanner.ScanFile(path);

    REQUIRE(result.level == nullbot::scanner::ThreatLevel::CLEAN);
    DeleteFileW(path.c_str());
}

TEST_CASE(ScanFile_ReturnsSuspicious_ForHighEntropyFile) {
    std::wstring path = MakeTempFile();

    // 512 bytes cycling 0-255 twice -> perfect entropy of 8.0 bits/byte
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    BYTE buf[512];
    for (int i = 0; i < 512; ++i) buf[i] = static_cast<BYTE>(i % 256);
    DWORD written;
    WriteFile(hFile, buf, sizeof(buf), &written, nullptr);
    CloseHandle(hFile);

    nullbot::scanner::FileScanner scanner{"Z:\\nonexistent"};
    auto result = scanner.ScanFile(path);

    REQUIRE(result.level == nullbot::scanner::ThreatLevel::SUSPICIOUS);
    DeleteFileW(path.c_str());
}

TEST_CASE(ScanFile_ComputesCorrectSHA256_ForKnownPayload) {
    std::wstring path = MakeTempFile();

    // "NullBot_test_sha256" -> SHA256: dd584e9d384bbb4fdf6121854fcd9d69d0466554122e26291c939d27a4e093c4
    const char payload[] = "NullBot_test_sha256";
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD written;
    WriteFile(hFile, payload, static_cast<DWORD>(strlen(payload)), &written, nullptr);
    CloseHandle(hFile);

    nullbot::scanner::FileScanner scanner{"Z:\\nonexistent"};
    auto result = scanner.ScanFile(path);

    REQUIRE(result.sha256 ==
            "dd584e9d384bbb4fdf6121854fcd9d69d0466554122e26291c939d27a4e093c4");
    DeleteFileW(path.c_str());
}

TEST_CASE(ScanDirectory_ReturnsEmpty_ForEmptyDirectory) {
    std::wstring dir = MakeTempDir();

    nullbot::scanner::FileScanner scanner{"Z:\\nonexistent"};
    auto results = scanner.ScanDirectory(dir);

    REQUIRE(results.empty());
    RemoveDirectoryW(dir.c_str());
}

TEST_CASE(ScanDirectory_DoesNotThrow_ForNonexistentPath) {
    nullbot::scanner::FileScanner scanner{"Z:\\nonexistent"};
    auto results = scanner.ScanDirectory(L"C:\\NonexistentPath\\DoesNotExist_NullBot\\");
    REQUIRE(results.empty());
}
