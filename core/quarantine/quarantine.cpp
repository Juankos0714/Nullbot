/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/quarantine/quarantine.cpp
 */

#include "core/quarantine/quarantine.h"
#include "core/quarantine/vault_path.h"

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlwapi.h>

#include <sqlite3.h>

#include <ctime>
#include <memory>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace nullbot {
namespace quarantine {

// ─── RAII wrappers ────────────────────────────────────────────────────────────

struct CngAlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~CngAlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};

struct CngKeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~CngKeyHandle() { if (h) BCryptDestroyKey(h); }
};

struct StmtHandle {
    sqlite3_stmt* s = nullptr;
    ~StmtHandle() { if (s) sqlite3_finalize(s); }
};

struct SqliteHandle {
    sqlite3* db = nullptr;
    ~SqliteHandle() { if (db) sqlite3_close(db); }
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

static std::string IsoTimestamp() {
    time_t t = time(nullptr);
    char buf[32];
    struct tm tm_info{};
    gmtime_s(&tm_info, &t);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_info);
    return buf;
}

static std::string WstrToUtf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n) - 1u, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

static std::wstring Utf8ToWstr(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring ws(static_cast<size_t>(n) - 1u, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), n);
    return ws;
}

// SHA-256 of the input bytes using CryptoAPI (not CNG, consistent with scanner.cpp)
static bool Sha256Bytes(const BYTE* data, DWORD len, BYTE out[32]) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    bool ok = false;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;
    if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        if (CryptHashData(hash, data, len, 0)) {
            DWORD hashLen = 32;
            ok = !!CryptGetHashParam(hash, HP_HASHVAL, out, &hashLen, 0);
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return ok;
}

// ─── Constructor / Destructor ─────────────────────────────────────────────────

QuarantineManager::QuarantineManager(const std::wstring& quarantine_dir)
    : quarantine_dir_(quarantine_dir)
{
    const int required = WideCharToMultiByte(CP_UTF8, 0,
        quarantine_dir.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (required > 0) {
        db_path_.resize(static_cast<size_t>(required) - 1u);
        WideCharToMultiByte(CP_UTF8, 0,
            quarantine_dir.c_str(), -1, db_path_.data(), required, nullptr, nullptr);
    }
    db_path_ += "\\quarantine.db";
    ZeroMemory(encryption_key_, sizeof(encryption_key_));
    ZeroMemory(encryption_iv_,  sizeof(encryption_iv_));
}

QuarantineManager::~QuarantineManager() = default;

// ─── Initialize ───────────────────────────────────────────────────────────────

bool QuarantineManager::Initialize() {
    // Create quarantine directory if it doesn't exist
    CreateDirectoryW(quarantine_dir_.c_str(), nullptr);

    if (!DeriveEncryptionKey()) return false;

    // Open / create SQLite DB and create table
    SqliteHandle db;
    if (sqlite3_open(db_path_.c_str(), &db.db) != SQLITE_OK) return false;

    const char* ddl =
        "CREATE TABLE IF NOT EXISTS quarantine ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  vault_filename  TEXT    NOT NULL,"
        "  original_path   TEXT    NOT NULL,"
        "  sha256          TEXT    NOT NULL,"
        "  threat_name     TEXT    NOT NULL,"
        "  detection_type  TEXT    NOT NULL,"
        "  quarantine_date TEXT    NOT NULL,"
        "  file_size_bytes INTEGER NOT NULL,"
        "  restored        INTEGER NOT NULL DEFAULT 0"
        ");";

    char* errmsg = nullptr;
    int rc = sqlite3_exec(db.db, ddl, nullptr, nullptr, &errmsg);
    if (errmsg) sqlite3_free(errmsg);
    return rc == SQLITE_OK;
}

// ─── DeriveEncryptionKey ──────────────────────────────────────────────────────

bool QuarantineManager::DeriveEncryptionKey() {
    // Read MachineGuid from registry
    HKEY hKey = nullptr;
    std::wstring guid_str;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[64]{};
        DWORD buf_size = sizeof(buf);
        DWORD type = REG_SZ;
        if (RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                             reinterpret_cast<LPBYTE>(buf), &buf_size) == ERROR_SUCCESS) {
            guid_str = buf;
        }
        RegCloseKey(hKey);
    }

    // Fallback: use a fixed string so the vault is at least consistently keyed
    // per-process when the registry read fails (e.g., insufficient privileges).
    if (guid_str.empty()) guid_str = L"NullBot-Fallback-Key-00000000-0000";

    std::string guid_utf8 = WstrToUtf8(guid_str);

    // Key = SHA-256(GUID bytes)
    {
        std::string key_input = guid_utf8;
        BYTE hash[32]{};
        if (!Sha256Bytes(reinterpret_cast<const BYTE*>(key_input.data()),
                         static_cast<DWORD>(key_input.size()), hash))
            return false;
        memcpy(encryption_key_, hash, 32);
    }

    // IV = first 16 bytes of SHA-256(GUID + "NullBot_IV_v1")
    {
        std::string iv_input = guid_utf8 + "NullBot_IV_v1";
        BYTE hash[32]{};
        if (!Sha256Bytes(reinterpret_cast<const BYTE*>(iv_input.data()),
                         static_cast<DWORD>(iv_input.size()), hash))
            return false;
        memcpy(encryption_iv_, hash, 16);
    }

    return true;
}

// ─── EncryptFile ──────────────────────────────────────────────────────────────

bool QuarantineManager::EncryptFile(const std::wstring& src, const std::wstring& dst) {
    // Read source file
    HANDLE hSrc = CreateFileW(src.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hSrc == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size_li{};
    GetFileSizeEx(hSrc, &size_li);
    const DWORD plain_size = static_cast<DWORD>(size_li.QuadPart);

    std::vector<BYTE> plaintext(plain_size);
    DWORD read_bytes = 0;
    if (plain_size > 0) {
        if (!ReadFile(hSrc, plaintext.data(), plain_size, &read_bytes, nullptr) ||
            read_bytes != plain_size) {
            CloseHandle(hSrc);
            return false;
        }
    }
    CloseHandle(hSrc);

    // CNG AES-256-CBC setup
    CngAlgHandle alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return false;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)), 0)))
        return false;

    CngKeyHandle key;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &key.h,
        nullptr, 0,
        encryption_key_, 32, 0)))
        return false;

    // Determine output buffer size
    BYTE iv_copy[16];
    memcpy(iv_copy, encryption_iv_, 16);

    ULONG cipher_size = 0;
    BCryptEncrypt(key.h,
        plain_size > 0 ? plaintext.data() : nullptr, plain_size,
        nullptr, iv_copy, 16,
        nullptr, 0, &cipher_size, BCRYPT_BLOCK_PADDING);

    // Re-copy IV — BCryptEncrypt modifies the IV buffer
    memcpy(iv_copy, encryption_iv_, 16);

    std::vector<BYTE> ciphertext(cipher_size);
    ULONG actual = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(key.h,
        plain_size > 0 ? plaintext.data() : nullptr, plain_size,
        nullptr, iv_copy, 16,
        ciphertext.data(), cipher_size, &actual, BCRYPT_BLOCK_PADDING)))
        return false;

    // Write: IV (16 bytes) + ciphertext
    HANDLE hDst = CreateFileW(dst.c_str(), GENERIC_WRITE, 0,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDst == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    bool ok = (WriteFile(hDst, encryption_iv_, 16, &written, nullptr) && written == 16);
    if (ok) {
        ok = (WriteFile(hDst, ciphertext.data(), actual, &written, nullptr) &&
              written == actual);
    }
    CloseHandle(hDst);
    if (!ok) DeleteFileW(dst.c_str());
    return ok;
}

// ─── DecryptFile ──────────────────────────────────────────────────────────────

bool QuarantineManager::DecryptFile(const std::wstring& src, const std::wstring& dst) {
    HANDLE hSrc = CreateFileW(src.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hSrc == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size_li{};
    GetFileSizeEx(hSrc, &size_li);
    const DWORD total_size = static_cast<DWORD>(size_li.QuadPart);

    if (total_size < 16) { CloseHandle(hSrc); return false; }

    BYTE iv[16]{};
    DWORD read_bytes = 0;
    if (!ReadFile(hSrc, iv, 16, &read_bytes, nullptr) || read_bytes != 16) {
        CloseHandle(hSrc);
        return false;
    }

    const DWORD cipher_size = total_size - 16;
    std::vector<BYTE> ciphertext(cipher_size);
    if (cipher_size > 0) {
        if (!ReadFile(hSrc, ciphertext.data(), cipher_size, &read_bytes, nullptr) ||
            read_bytes != cipher_size) {
            CloseHandle(hSrc);
            return false;
        }
    }
    CloseHandle(hSrc);

    CngAlgHandle alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return false;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)), 0)))
        return false;

    CngKeyHandle key;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &key.h,
        nullptr, 0,
        encryption_key_, 32, 0)))
        return false;

    ULONG plain_size = 0;
    BCryptDecrypt(key.h,
        cipher_size > 0 ? ciphertext.data() : nullptr, cipher_size,
        nullptr, iv, 16,
        nullptr, 0, &plain_size, BCRYPT_BLOCK_PADDING);

    std::vector<BYTE> plaintext(plain_size);
    ULONG actual = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(key.h,
        cipher_size > 0 ? ciphertext.data() : nullptr, cipher_size,
        nullptr, iv, 16,
        plaintext.data(), plain_size, &actual, BCRYPT_BLOCK_PADDING)))
        return false;

    HANDLE hDst = CreateFileW(dst.c_str(), GENERIC_WRITE, 0,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDst == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    bool ok = true;
    if (actual > 0) {
        ok = (WriteFile(hDst, plaintext.data(), actual, &written, nullptr) &&
              written == actual);
    }
    CloseHandle(hDst);
    if (!ok) DeleteFileW(dst.c_str());
    return ok;
}

// ─── GenerateVaultPath ────────────────────────────────────────────────────────

std::wstring QuarantineManager::GenerateVaultPath() {
    return quarantine_dir_ + L"\\" + GenerateVaultFilename();
}

// ─── Quarantine ───────────────────────────────────────────────────────────────

bool QuarantineManager::Quarantine(
    const std::wstring& file_path,
    const std::string&  threat_name,
    const std::string&  detection_type,
    const std::string&  sha256)
{
    // Verify source exists
    if (GetFileAttributesW(file_path.c_str()) == INVALID_FILE_ATTRIBUTES) return false;

    // Get file size before encryption
    WIN32_FILE_ATTRIBUTE_DATA fa{};
    GetFileAttributesExW(file_path.c_str(), GetFileExInfoStandard, &fa);
    ULONGLONG file_size = (static_cast<ULONGLONG>(fa.nFileSizeHigh) << 32) | fa.nFileSizeLow;

    std::wstring vault_path = GenerateVaultPath();
    std::wstring vault_filename_only = vault_path;
    const size_t slash = vault_filename_only.rfind(L'\\');
    if (slash != std::wstring::npos) vault_filename_only = vault_filename_only.substr(slash + 1);

    if (!EncryptFile(file_path, vault_path)) return false;

    // Only delete original after successful encryption
    if (!DeleteFileW(file_path.c_str())) {
        DeleteFileW(vault_path.c_str()); // rollback
        return false;
    }

    QuarantinedFile entry{};
    entry.id              = 0; // assigned by SQLite AUTOINCREMENT
    entry.vault_filename  = WstrToUtf8(vault_filename_only);
    entry.original_path   = file_path;
    entry.sha256          = sha256;
    entry.threat_name     = threat_name;
    entry.detection_type  = detection_type;
    entry.quarantine_date = IsoTimestamp();
    entry.file_size_bytes = file_size;
    entry.restored        = false;

    if (!DB_Insert(entry)) {
        // Rollback: vault file is orphaned but source is already gone — best effort
        DeleteFileW(vault_path.c_str());
        return false;
    }
    return true;
}

// ─── Restore ─────────────────────────────────────────────────────────────────

bool QuarantineManager::Restore(int quarantine_id) {
    QuarantinedFile entry{};
    if (!DB_GetById(quarantine_id, entry)) return false;
    if (entry.restored) return false;

    // Refuse to overwrite an existing file at original path
    if (GetFileAttributesW(entry.original_path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return false;

    std::wstring vault_path = quarantine_dir_ + L"\\" + Utf8ToWstr(entry.vault_filename);

    if (!DecryptFile(vault_path, entry.original_path)) return false;

    if (!DB_SetRestored(quarantine_id, true)) {
        // Rollback — remove the decrypted file we just wrote
        DeleteFileW(entry.original_path.c_str());
        return false;
    }
    return true;
}

// ─── Delete ───────────────────────────────────────────────────────────────────

bool QuarantineManager::Delete(int quarantine_id) {
    QuarantinedFile entry{};
    if (!DB_GetById(quarantine_id, entry)) return false;

    std::wstring vault_path = quarantine_dir_ + L"\\" + Utf8ToWstr(entry.vault_filename);
    DeleteFileW(vault_path.c_str()); // best-effort; DB entry is authoritative

    return DB_Delete(quarantine_id);
}

// ─── ListAll / GetById / Stats ────────────────────────────────────────────────

std::vector<QuarantinedFile> QuarantineManager::ListAll() const {
    return DB_GetAll();
}

std::optional<QuarantinedFile> QuarantineManager::GetById(int id) const {
    QuarantinedFile entry{};
    if (!DB_GetById(id, entry)) return std::nullopt;
    return entry;
}

size_t QuarantineManager::GetCount() const {
    return DB_GetAll().size();
}

ULONGLONG QuarantineManager::GetTotalSize() const {
    ULONGLONG total = 0;
    for (const auto& f : DB_GetAll()) total += f.file_size_bytes;
    return total;
}

// ─── SQLite helpers ───────────────────────────────────────────────────────────

static QuarantinedFile RowToEntry(sqlite3_stmt* s) {
    QuarantinedFile e{};
    e.id              = sqlite3_column_int(s, 0);
    auto col_text = [&](int col) -> std::string {
        const char* t = reinterpret_cast<const char*>(sqlite3_column_text(s, col));
        return t ? t : "";
    };
    e.vault_filename  = col_text(1);
    e.original_path   = Utf8ToWstr(col_text(2));
    e.sha256          = col_text(3);
    e.threat_name     = col_text(4);
    e.detection_type  = col_text(5);
    e.quarantine_date = col_text(6);
    e.file_size_bytes = static_cast<ULONGLONG>(sqlite3_column_int64(s, 7));
    e.restored        = sqlite3_column_int(s, 8) != 0;
    return e;
}

bool QuarantineManager::DB_Insert(const QuarantinedFile& entry) {
    SqliteHandle db;
    if (sqlite3_open(db_path_.c_str(), &db.db) != SQLITE_OK) return false;

    const char* sql =
        "INSERT INTO quarantine "
        "(vault_filename, original_path, sha256, threat_name, detection_type, "
        " quarantine_date, file_size_bytes, restored) "
        "VALUES (?,?,?,?,?,?,?,0);";

    StmtHandle stmt;
    if (sqlite3_prepare_v2(db.db, sql, -1, &stmt.s, nullptr) != SQLITE_OK) return false;

    std::string orig_utf8 = WstrToUtf8(entry.original_path);
    sqlite3_bind_text(stmt.s, 1, entry.vault_filename.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.s, 2, orig_utf8.c_str(),             -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.s, 3, entry.sha256.c_str(),          -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.s, 4, entry.threat_name.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.s, 5, entry.detection_type.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.s, 6, entry.quarantine_date.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.s, 7, static_cast<sqlite3_int64>(entry.file_size_bytes));

    return sqlite3_step(stmt.s) == SQLITE_DONE;
}

bool QuarantineManager::DB_SetRestored(int id, bool restored) {
    SqliteHandle db;
    if (sqlite3_open(db_path_.c_str(), &db.db) != SQLITE_OK) return false;

    const char* sql = "UPDATE quarantine SET restored=? WHERE id=?;";
    StmtHandle stmt;
    if (sqlite3_prepare_v2(db.db, sql, -1, &stmt.s, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt.s, 1, restored ? 1 : 0);
    sqlite3_bind_int(stmt.s, 2, id);
    return sqlite3_step(stmt.s) == SQLITE_DONE;
}

bool QuarantineManager::DB_Delete(int id) {
    SqliteHandle db;
    if (sqlite3_open(db_path_.c_str(), &db.db) != SQLITE_OK) return false;

    const char* sql = "DELETE FROM quarantine WHERE id=?;";
    StmtHandle stmt;
    if (sqlite3_prepare_v2(db.db, sql, -1, &stmt.s, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt.s, 1, id);
    return sqlite3_step(stmt.s) == SQLITE_DONE;
}

bool QuarantineManager::DB_GetById(int id, QuarantinedFile& out) const {
    SqliteHandle db;
    if (sqlite3_open(db_path_.c_str(), &db.db) != SQLITE_OK) return false;

    const char* sql =
        "SELECT id, vault_filename, original_path, sha256, threat_name, "
        "detection_type, quarantine_date, file_size_bytes, restored "
        "FROM quarantine WHERE id=?;";

    StmtHandle stmt;
    if (sqlite3_prepare_v2(db.db, sql, -1, &stmt.s, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt.s, 1, id);
    if (sqlite3_step(stmt.s) != SQLITE_ROW) return false;

    out = RowToEntry(stmt.s);
    return true;
}

std::vector<QuarantinedFile> QuarantineManager::DB_GetAll() const {
    SqliteHandle db;
    if (sqlite3_open(db_path_.c_str(), &db.db) != SQLITE_OK) return {};

    const char* sql =
        "SELECT id, vault_filename, original_path, sha256, threat_name, "
        "detection_type, quarantine_date, file_size_bytes, restored "
        "FROM quarantine ORDER BY id;";

    StmtHandle stmt;
    if (sqlite3_prepare_v2(db.db, sql, -1, &stmt.s, nullptr) != SQLITE_OK) return {};

    std::vector<QuarantinedFile> results;
    while (sqlite3_step(stmt.s) == SQLITE_ROW)
        results.push_back(RowToEntry(stmt.s));
    return results;
}

} // namespace quarantine
} // namespace nullbot
