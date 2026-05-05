/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: tests/unit/test_sig_database.cpp
 */

#include "tests/test_runner.h"
#include "signatures/sig_database.h"
#include "third_party/sqlite3/sqlite3.h"

#include <windows.h>
#include <string>

static std::string MakeTempDbPath() {
    char temp[MAX_PATH];
    GetTempPathA(MAX_PATH, temp);
    return std::string(temp) + "nullbot_sigdb_test.db";
}

static void SeedDatabase(const std::string& path, bool insert_row) {
    sqlite3* db = nullptr;
    sqlite3_open(path.c_str(), &db);
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS hashes "
        "(sha256 TEXT PRIMARY KEY, name TEXT NOT NULL);",
        nullptr, nullptr, nullptr);
    if (insert_row) {
        sqlite3_exec(db,
            "INSERT OR IGNORE INTO hashes VALUES ("
            "'abcdef1234567890abcdef1234567890"
            "abcdef1234567890abcdef1234567890',"
            "'Botnet.Test.Zeus');",
            nullptr, nullptr, nullptr);
    }
    sqlite3_close(db);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

TEST_CASE(Load_ReturnsFalse_OnInvalidPath) {
    nullbot::signatures::SigDB db;
    REQUIRE_FALSE(db.Load("Z:\\nonexistent\\path\\signatures.db"));
}

TEST_CASE(LookupHash_ReturnsFalse_WhenHashNotInDatabase) {
    const std::string path = MakeTempDbPath();
    SeedDatabase(path, false);

    nullbot::signatures::SigDB db;
    REQUIRE(db.Load(path));

    std::string name;
    REQUIRE_FALSE(db.LookupHash(
        "0000000000000000000000000000000000000000000000000000000000000000",
        name));

    DeleteFileA(path.c_str());
}

TEST_CASE(LookupHash_ReturnsTrueAndCorrectName_ForKnownHash) {
    const std::string path = MakeTempDbPath();
    SeedDatabase(path, true);

    nullbot::signatures::SigDB db;
    REQUIRE(db.Load(path));

    std::string name;
    const bool found = db.LookupHash(
        "abcdef1234567890abcdef1234567890"
        "abcdef1234567890abcdef1234567890",
        name);

    REQUIRE(found);
    REQUIRE(name == "Botnet.Test.Zeus");

    DeleteFileA(path.c_str());
}
