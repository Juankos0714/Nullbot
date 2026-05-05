/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/integration/test_quarantine.cpp
 */

#include "tests/test_runner.h"
#include "core/quarantine/quarantine.h"

#include <windows.h>
#include <string>
#include <vector>

namespace {

// ─── Fixture helpers ──────────────────────────────────────────────────────────

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring ws(static_cast<size_t>(n) - 1u, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), n);
    return ws;
}

static std::wstring TestDir() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring dir = tmp;
    if (!dir.empty() && dir.back() == L'\\') dir.pop_back();
    return dir + L"\\nullbot_test";
}

static std::wstring TestQuarantineDir() {
    return TestDir() + L"\\quarantine";
}

static void EnsureDir(const std::wstring& path) {
    CreateDirectoryW(path.c_str(), nullptr);
}

static void RemoveDir(const std::wstring& path) {
    std::wstring pattern = path + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;
            std::wstring child = path + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                RemoveDir(child);
            else
                DeleteFileW(child.c_str());
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    RemoveDirectoryW(path.c_str());
}

static std::wstring CreateTextFile(const std::wstring& dir,
                                   const std::wstring& name,
                                   const std::string&  content) {
    std::wstring path = dir + L"\\" + name;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD written = 0;
    WriteFile(h, content.data(), static_cast<DWORD>(content.size()), &written, nullptr);
    CloseHandle(h);
    return path;
}

static std::string ReadTextFile(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    std::string buf(static_cast<size_t>(sz.QuadPart), '\0');
    DWORD bytes_read = 0;
    ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &bytes_read, nullptr);
    CloseHandle(h);
    buf.resize(bytes_read);
    return buf;
}

static bool FileExists(const std::wstring& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

struct Fixture {
    std::wstring src_dir;
    std::wstring qdir;
    nullbot::quarantine::QuarantineManager mgr;

    Fixture()
        : src_dir(TestDir() + L"\\src")
        , qdir(TestQuarantineDir())
        , mgr(qdir)
    {
        RemoveDir(TestDir());
        EnsureDir(TestDir());
        EnsureDir(src_dir);
        mgr.Initialize();
    }

    ~Fixture() {
        RemoveDir(TestDir());
    }

    std::wstring VaultPath(const std::string& vault_filename) const {
        return qdir + L"\\" + Utf8ToWide(vault_filename);
    }
};

} // namespace

// ─── Test 1: Quarantine() creates vault file and removes original ─────────────

TEST_CASE(Quarantine_CreatesVaultAndDeletesOriginal) {
    Fixture f;
    std::wstring src = CreateTextFile(f.src_dir, L"malware.exe", "EVIL_PAYLOAD_DATA");
    REQUIRE(!src.empty());
    REQUIRE(FileExists(src));

    bool ok = f.mgr.Quarantine(src, "Test.Threat", "heuristic", "aabbccdd");
    REQUIRE(ok);
    REQUIRE(!FileExists(src));
    REQUIRE(f.mgr.GetCount() == 1);

    auto items = f.mgr.ListAll();
    REQUIRE(items.size() == 1);
    REQUIRE(FileExists(f.VaultPath(items[0].vault_filename)));
}

// ─── Test 2: Quarantined vault content is not plaintext ───────────────────────

TEST_CASE(Quarantine_VaultContentIsEncrypted) {
    Fixture f;
    const std::string payload = "PLAINTEXT_MARKER_12345";
    std::wstring src = CreateTextFile(f.src_dir, L"sample.exe", payload);
    REQUIRE(f.mgr.Quarantine(src, "Test", "hash", "aabb"));

    auto items = f.mgr.ListAll();
    REQUIRE(items.size() == 1);

    std::string vault_raw = ReadTextFile(f.VaultPath(items[0].vault_filename));
    REQUIRE(!vault_raw.empty());
    REQUIRE(vault_raw.find(payload) == std::string::npos);
}

// ─── Test 3: Restore() recovers exact original content ───────────────────────

TEST_CASE(Restore_RecoversPreciseOriginalContent) {
    Fixture f;
    const std::string payload = "ExactContentForRoundTrip_NullBot";
    std::wstring src = CreateTextFile(f.src_dir, L"victim.dat", payload);
    REQUIRE(f.mgr.Quarantine(src, "T", "h", "00"));

    auto items = f.mgr.ListAll();
    REQUIRE(items.size() == 1);

    REQUIRE(f.mgr.Restore(items[0].id));
    REQUIRE(FileExists(src));
    REQUIRE(ReadTextFile(src) == payload);
}

// ─── Test 4: Quarantine() with nonexistent file returns false ─────────────────

TEST_CASE(Quarantine_NonexistentFile_ReturnsFalse) {
    Fixture f;
    std::wstring ghost = f.src_dir + L"\\does_not_exist.exe";
    REQUIRE(!FileExists(ghost));

    REQUIRE(!f.mgr.Quarantine(ghost, "T", "h", "00"));
    REQUIRE(f.mgr.GetCount() == 0);
}

// ─── Test 5: Restore() with nonexistent ID returns false ─────────────────────

TEST_CASE(Restore_InvalidId_ReturnsFalse) {
    Fixture f;
    REQUIRE(!f.mgr.Restore(99999));
}

// ─── Test 6: ListAll() returns all inserted items ─────────────────────────────

TEST_CASE(ListAll_ReturnsAllInsertedItems) {
    Fixture f;
    for (int i = 0; i < 3; ++i) {
        std::wstring name = L"file" + std::to_wstring(i) + L".exe";
        std::wstring src  = CreateTextFile(f.src_dir, name, "payload" + std::to_string(i));
        REQUIRE(f.mgr.Quarantine(src, "T", "h", "00"));
    }

    REQUIRE(f.mgr.ListAll().size() == 3);
    REQUIRE(f.mgr.GetCount() == 3);
}

// ─── Test 7: Delete() removes vault file and SQLite entry ────────────────────

TEST_CASE(Delete_RemovesVaultFileAndDbEntry) {
    Fixture f;
    std::wstring src = CreateTextFile(f.src_dir, L"del_me.exe", "delete_test");
    REQUIRE(f.mgr.Quarantine(src, "T", "h", "00"));

    auto items = f.mgr.ListAll();
    REQUIRE(items.size() == 1);
    int id = items[0].id;
    std::wstring vault_path = f.VaultPath(items[0].vault_filename);
    REQUIRE(FileExists(vault_path));

    REQUIRE(f.mgr.Delete(id));
    REQUIRE(!FileExists(vault_path));
    REQUIRE(f.mgr.GetCount() == 0);
    REQUIRE(!f.mgr.GetById(id).has_value());
}
