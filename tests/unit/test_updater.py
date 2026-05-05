# NullBot — Open Source Anti-Botnet | GPL-3.0
# File: tests/unit/test_updater.py

from pathlib import Path

ROOT = Path(__file__).parent.parent.parent


def test_updater_script_exists():
    assert (ROOT / "signatures" / "updater" / "update_feeds.py").exists()


def test_requirements_file_exists():
    assert (ROOT / "signatures" / "updater" / "requirements.txt").exists()


def test_yara_rules_directory_has_rules():
    rules = list((ROOT / "signatures" / "rules").glob("*.yar"))
    assert len(rules) > 0, "No YARA rules found in signatures/rules/"


def test_init_db_creates_tables(tmp_path):
    import sqlite3
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS hashes "
        "(sha256 TEXT PRIMARY KEY, name TEXT NOT NULL);"
    )
    conn.execute(
        "INSERT INTO hashes VALUES ('aabbcc', 'Test.Threat');"
    )
    conn.commit()
    row = conn.execute("SELECT name FROM hashes WHERE sha256='aabbcc'").fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "Test.Threat"
