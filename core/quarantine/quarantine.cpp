/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: core/quarantine/quarantine.cpp
 */

#include "core/quarantine/quarantine.h"

namespace nullbot {
namespace quarantine {

QuarantineManager::QuarantineManager(const std::wstring& quarantine_dir)
    : quarantine_dir_(quarantine_dir)
{
    const int required = WideCharToMultiByte(CP_UTF8, 0,
                                              quarantine_dir.c_str(), -1,
                                              nullptr, 0, nullptr, nullptr);
    if (required > 0) {
        db_path_.resize(static_cast<size_t>(required) - 1u);
        WideCharToMultiByte(CP_UTF8, 0,
                             quarantine_dir.c_str(), -1,
                             db_path_.data(), required, nullptr, nullptr);
    }
    db_path_ += "\\quarantine.db";
    ZeroMemory(encryption_key_, sizeof(encryption_key_));
    ZeroMemory(encryption_iv_,  sizeof(encryption_iv_));
}

QuarantineManager::~QuarantineManager() = default;

bool QuarantineManager::Initialize()                                 { return DeriveEncryptionKey(); }
bool QuarantineManager::Quarantine(const std::wstring&,
                                   const std::string&,
                                   const std::string&,
                                   const std::string&)               { return false; }
bool QuarantineManager::Restore(int)                                 { return false; }
bool QuarantineManager::Delete(int)                                  { return false; }
std::vector<QuarantinedFile> QuarantineManager::ListAll() const      { return {}; }
std::optional<QuarantinedFile> QuarantineManager::GetById(int) const { return std::nullopt; }
size_t    QuarantineManager::GetCount()     const                    { return 0; }
ULONGLONG QuarantineManager::GetTotalSize() const                    { return 0; }

bool         QuarantineManager::DeriveEncryptionKey()                      { return true; }
bool         QuarantineManager::EncryptFile(const std::wstring&,
                                            const std::wstring&)           { return false; }
bool         QuarantineManager::DecryptFile(const std::wstring&,
                                            const std::wstring&)           { return false; }
std::wstring QuarantineManager::GenerateVaultPath()                        { return {}; }

bool QuarantineManager::DB_Insert(const QuarantinedFile&)                  { return false; }
bool QuarantineManager::DB_SetRestored(int, bool)                          { return false; }
bool QuarantineManager::DB_Delete(int)                                     { return false; }
bool QuarantineManager::DB_GetById(int, QuarantinedFile&) const            { return false; }
std::vector<QuarantinedFile> QuarantineManager::DB_GetAll() const          { return {}; }

} // namespace quarantine
} // namespace nullbot
