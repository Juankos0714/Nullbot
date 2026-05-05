/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: signatures/sig_database.h
 *
 * Hash-based signature database backed by SQLite.
 * The underlying table schema is: hashes(sha256 TEXT PK, name TEXT NOT NULL)
 */
#pragma once

#include <cstddef>
#include <memory>
#include <string>

namespace nullbot {
namespace signatures {

class SigDB {
public:
    SigDB();
    ~SigDB();

    SigDB(const SigDB&)            = delete;
    SigDB& operator=(const SigDB&) = delete;

    bool   Load(const std::string& db_path);
    bool   LookupHash(const std::string& sha256, std::string& out_name) const;
    size_t Count() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace signatures
} // namespace nullbot
