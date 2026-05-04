#pragma once

/*
 * NullBot — Quarantine Manager
 * File: core/quarantine/quarantine.h
 *
 * Moves detected threats to an encrypted quarantine vault.
 * - AES-256 encryption via Windows CNG (no external deps)
 * - Metadata stored in SQLite DB
 * - Restore capability with original path
 */

#include <windows.h>
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace nullbot {
namespace quarantine {

// ─── Quarantined item ─────────────────────────────────────────────────────────

struct QuarantinedFile {
    int         id;
    std::string vault_filename;       // Random filename in quarantine dir
    std::wstring original_path;
    std::string sha256;
    std::string threat_name;
    std::string detection_type;
    std::string quarantine_date;      // ISO 8601
    ULONGLONG   file_size_bytes;
    bool        restored;
};

// ─── Quarantine Manager ───────────────────────────────────────────────────────

class QuarantineManager {
public:
    explicit QuarantineManager(const std::wstring& quarantine_dir);
    ~QuarantineManager();

    bool Initialize();

    // Move file to quarantine vault (encrypted)
    bool Quarantine(
        const std::wstring& file_path,
        const std::string&  threat_name,
        const std::string&  detection_type,
        const std::string&  sha256
    );

    // Restore file to original path
    bool Restore(int quarantine_id);

    // Permanently delete a quarantined file
    bool Delete(int quarantine_id);

    // List quarantined files
    std::vector<QuarantinedFile> ListAll() const;

    // Get single item
    std::optional<QuarantinedFile> GetById(int id) const;

    // Stats
    size_t   GetCount()      const;
    ULONGLONG GetTotalSize() const;

private:
    std::wstring quarantine_dir_;
    std::string  db_path_;

    // AES-256 key derived from machine GUID (stable per machine)
    BYTE encryption_key_[32];
    BYTE encryption_iv_[16];

    bool DeriveEncryptionKey();
    bool EncryptFile(const std::wstring& src, const std::wstring& dst);
    bool DecryptFile(const std::wstring& src, const std::wstring& dst);

    std::wstring GenerateVaultPath();

    // SQLite operations
    bool  DB_Insert(const QuarantinedFile& entry);
    bool  DB_SetRestored(int id, bool restored);
    bool  DB_Delete(int id);
    bool  DB_GetById(int id, QuarantinedFile& out) const;
    std::vector<QuarantinedFile> DB_GetAll() const;
};

} // namespace quarantine
} // namespace nullbot
