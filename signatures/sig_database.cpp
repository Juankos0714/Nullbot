/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: signatures/sig_database.cpp
 */

#include "signatures/sig_database.h"
#include "third_party/sqlite3/sqlite3.h"

namespace nullbot {
namespace signatures {

struct SigDB::Impl {
    sqlite3* db           = nullptr;
    size_t   cached_count = 0;
};

SigDB::SigDB() : impl_(std::make_unique<Impl>()) {}

SigDB::~SigDB() {
    if (impl_->db) {
        sqlite3_close(impl_->db);
    }
}

bool SigDB::Load(const std::string& db_path) {
    if (impl_->db) {
        sqlite3_close(impl_->db);
        impl_->db = nullptr;
        impl_->cached_count = 0;
    }

    if (sqlite3_open_v2(db_path.c_str(), &impl_->db,
                        SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        impl_->db = nullptr;
        return false;
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT COUNT(*) FROM hashes;";
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(impl_->db);
        impl_->db = nullptr;
        return false;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        impl_->cached_count =
            static_cast<size_t>(sqlite3_column_int64(stmt, 0));
    }
    sqlite3_finalize(stmt);
    return true;
}

bool SigDB::LookupHash(const std::string& sha256, std::string& out_name) const {
    if (!impl_->db) return false;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT name FROM hashes WHERE sha256 = ? LIMIT 1;";
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, sha256.c_str(), -1, SQLITE_STATIC);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const auto* raw =
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (raw) {
            out_name = raw;
            found    = true;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

size_t SigDB::Count() const {
    return impl_->cached_count;
}

} // namespace signatures
} // namespace nullbot
