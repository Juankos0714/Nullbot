# NullBot -- Open Source Anti-Botnet | GPL-3.0
# File: tests/unit/test_updater.py
#
# All HTTP calls are intercepted by the `responses` library.
# No real network requests are made in any test.

import re

import pytest
import requests
import requests.exceptions
import responses

import signatures.updater.update_feeds as _mod
from signatures.updater.update_feeds import (
    FEEDS,
    fetch_emerging_threats_ips,
    fetch_feodo_c2_ips,
    fetch_malwarebazaar,
    fetch_otx_pulses,
    fetch_urlhaus_domains,
    fetch_with_retry,
    init_db,
    update_metadata,
)

_MB_URL     = FEEDS["malwarebazaar_recent"]["url"]
_URLHAUS_URL = FEEDS["urlhaus_domains"]["url"]
_FEODO_URL  = FEEDS["feodo_botnet_c2"]["url"]

_FEODO_CSV = (
    "# first_seen,dst_ip,dst_port,malware,status,hostname,as_number,as_name,"
    "country,region,city,reporter,last_online\n"
    "2023-01-01 00:00:00,1.2.3.4,443,Emotet,online,h1.com,AS1,P,US,CA,LA,r,2023-01-02\n"
    "2023-01-02 00:00:00,5.6.7.8,8080,TrickBot,online,h2.com,AS2,P,DE,BY,MUC,r,2023-01-03\n"
    "2023-01-03 00:00:00,9.10.11.12,80,Dridex,online,h3.com,AS3,P,RU,MOW,MOW,r,2023-01-04\n"
)


@pytest.fixture
def test_db(tmp_path):
    db_path = tmp_path / "test_signatures.db"
    conn = init_db(db_path)
    yield conn
    conn.close()


@responses.activate
def test_malwarebazaar_inserts_hashes(test_db):
    """Three samples in the mock response -> three rows in the hashes table."""
    responses.add(
        responses.POST,
        _MB_URL,
        json={
            "query_status": "ok",
            "data": [
                {"sha256_hash": "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaaa",
                 "md5_hash": "bbb222", "signature": "Emotet", "first_seen": "2024-01-01 00:00:00"},
                {"sha256_hash": "ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333cccc",
                 "md5_hash": "ddd444", "signature": "TrickBot", "first_seen": "2024-01-01 00:00:00"},
                {"sha256_hash": "eee555eee555eee555eee555eee555eee555eee555eee555eee555eee555eeee",
                 "md5_hash": "fff666", "signature": "Dridex", "first_seen": "2024-01-01 00:00:00"},
            ],
        },
        content_type="application/json",
    )
    result = fetch_malwarebazaar(test_db)
    assert result == 3
    assert test_db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] == 3


@responses.activate
def test_malwarebazaar_handles_empty_response(test_db):
    """Empty data list -> returns 0, no crash."""
    responses.add(
        responses.POST,
        _MB_URL,
        json={"query_status": "ok", "data": []},
        content_type="application/json",
    )
    result = fetch_malwarebazaar(test_db)
    assert result == 0


@responses.activate
def test_malwarebazaar_handles_network_error(test_db, mocker):
    """ConnectionError on all retries -> returns 0, no exception propagated."""
    mocker.patch("time.sleep")
    responses.add(responses.POST, _MB_URL, body=requests.exceptions.ConnectionError())
    result = fetch_malwarebazaar(test_db)
    assert result == 0


@responses.activate
def test_urlhaus_parses_hostfile_format(test_db):
    """Hostfile with 5 valid entries and comment/blank lines -> 5 domains inserted."""
    hostfile = (
        "# URLhaus Host file -- test fixture\n"
        "# Comment line\n"
        "\n"
        "0.0.0.0 malware1.example.com\n"
        "0.0.0.0 malware2.example.com\n"
        "0.0.0.0 malware3.example.com\n"
        "0.0.0.0 malware4.example.com\n"
        "0.0.0.0 malware5.example.com\n"
    )
    responses.add(responses.GET, _URLHAUS_URL, body=hostfile, content_type="text/plain")
    result = fetch_urlhaus_domains(test_db)
    assert result == 5
    assert test_db.execute("SELECT COUNT(*) FROM domain_blacklist").fetchone()[0] == 5


@responses.activate
def test_feodo_parses_csv_correctly(test_db):
    """Three CSV rows -> three ip_blacklist entries with correct IPs and ports."""
    responses.add(responses.GET, _FEODO_URL, body=_FEODO_CSV, content_type="text/csv")
    result = fetch_feodo_c2_ips(test_db)
    assert result == 3
    rows = test_db.execute("SELECT ip, port FROM ip_blacklist ORDER BY ip").fetchall()
    ip_to_port = {ip: port for ip, port in rows}
    assert ip_to_port["1.2.3.4"] == 443
    assert ip_to_port["5.6.7.8"] == 8080
    assert ip_to_port["9.10.11.12"] == 80


@responses.activate
def test_fetch_with_retry_retries_on_error(mocker):
    """Two failures followed by success -> three total calls, response returned."""
    mocker.patch("time.sleep")
    url = "https://test.nullbot.internal/retry-test"
    responses.add(responses.GET, url, body=requests.exceptions.ConnectionError())
    responses.add(responses.GET, url, body=requests.exceptions.ConnectionError())
    responses.add(responses.GET, url, json={"ok": True}, status=200)

    resp = fetch_with_retry(url, retries=3)
    assert resp.status_code == 200
    assert len(responses.calls) == 3


@responses.activate
def test_dry_run_does_not_write_to_db(test_db):
    """dry_run=True: records are parsed and counted but the DB stays empty."""
    responses.add(
        responses.POST,
        _MB_URL,
        json={
            "query_status": "ok",
            "data": [
                {"sha256_hash": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd",
                 "md5_hash": "def456", "signature": "Emotet", "first_seen": "2024-01-01 00:00:00"},
            ],
        },
        content_type="application/json",
    )
    result = fetch_malwarebazaar(test_db, dry_run=True)
    assert result == 1
    assert test_db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] == 0


@responses.activate
def test_duplicate_hashes_not_inserted_twice(test_db):
    """The same hash submitted twice -> only one row in the DB (INSERT OR IGNORE)."""
    payload = {
        "query_status": "ok",
        "data": [
            {"sha256_hash": "dup111dup111dup111dup111dup111dup111dup111dup111dup111dup111dupp",
             "md5_hash": "dup222", "signature": "Emotet", "first_seen": "2024-01-01 00:00:00"},
        ],
    }
    responses.add(responses.POST, _MB_URL, json=payload, content_type="application/json")
    responses.add(responses.POST, _MB_URL, json=payload, content_type="application/json")

    fetch_malwarebazaar(test_db)
    fetch_malwarebazaar(test_db)

    assert test_db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] == 1


# ---------------------------------------------------------------------------
# Additional tests (error paths + uncovered functions) to satisfy >80% coverage
# ---------------------------------------------------------------------------

@responses.activate
def test_malwarebazaar_bad_content_type(test_db):
    """Wrong Content-Type (not application/json) -> returns 0 without crashing."""
    responses.add(responses.POST, _MB_URL, body=b"<html>error</html>", content_type="text/html")
    result = fetch_malwarebazaar(test_db)
    assert result == 0


@responses.activate
def test_malwarebazaar_non_ok_status(test_db):
    """query_status != 'ok' -> returns 0 without crashing."""
    responses.add(
        responses.POST, _MB_URL,
        json={"query_status": "no_results"},
        content_type="application/json",
    )
    result = fetch_malwarebazaar(test_db)
    assert result == 0


@responses.activate
def test_urlhaus_network_error(test_db, mocker):
    """URLhaus ConnectionError on all retries -> returns 0, no exception propagated."""
    mocker.patch("time.sleep")
    responses.add(
        responses.GET, FEEDS["urlhaus_domains"]["url"],
        body=requests.exceptions.ConnectionError(),
    )
    result = fetch_urlhaus_domains(test_db)
    assert result == 0


@responses.activate
def test_feodo_network_error(test_db, mocker):
    """Feodo ConnectionError on all retries -> returns 0, no exception propagated."""
    mocker.patch("time.sleep")
    responses.add(
        responses.GET, FEEDS["feodo_botnet_c2"]["url"],
        body=requests.exceptions.ConnectionError(),
    )
    result = fetch_feodo_c2_ips(test_db)
    assert result == 0


@responses.activate
def test_emerging_threats_inserts_ips(test_db):
    """Three IPs in the blocklist -> three rows in ip_blacklist."""
    body = "# Emerging Threats test fixture\n1.1.1.1\n2.2.2.2\n3.3.3.3\n"
    responses.add(
        responses.GET, FEEDS["emerging_threats_ips"]["url"],
        body=body, content_type="text/plain",
    )
    result = fetch_emerging_threats_ips(test_db)
    assert result == 3
    assert test_db.execute("SELECT COUNT(*) FROM ip_blacklist").fetchone()[0] == 3


@responses.activate
def test_emerging_threats_network_error(test_db, mocker):
    """Emerging Threats ConnectionError -> returns 0, no exception propagated."""
    mocker.patch("time.sleep")
    responses.add(
        responses.GET, FEEDS["emerging_threats_ips"]["url"],
        body=requests.exceptions.ConnectionError(),
    )
    result = fetch_emerging_threats_ips(test_db)
    assert result == 0


def test_otx_skips_without_api_key(test_db):
    """OTX_API_KEY not set -> returns 0 immediately, no HTTP call made."""
    result = fetch_otx_pulses(test_db)
    assert result == 0


@responses.activate
def test_otx_inserts_indicators(test_db, monkeypatch):
    """OTX happy path: hash + domain + IP in one pulse -> 3 indicators inserted."""
    monkeypatch.setattr(_mod, "OTX_API_KEY", "test-api-key")
    responses.add(
        responses.GET,
        re.compile(r"https://otx\.alienvault\.com/.*"),
        json={
            "results": [
                {
                    "name": "TestPulse",
                    "indicators": [
                        {"type": "FileHash-SHA256",
                         "indicator": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd"},
                        {"type": "domain", "indicator": "evil.example.com"},
                        {"type": "IPv4",   "indicator": "10.0.0.1"},
                    ],
                }
            ]
        },
        content_type="application/json",
    )
    result = fetch_otx_pulses(test_db)
    assert result == 3
    assert test_db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] == 1
    assert test_db.execute("SELECT COUNT(*) FROM domain_blacklist").fetchone()[0] == 1
    assert test_db.execute("SELECT COUNT(*) FROM ip_blacklist").fetchone()[0] == 1


@responses.activate
def test_otx_bad_content_type(test_db, monkeypatch):
    """OTX returns wrong Content-Type -> returns 0 without crashing."""
    monkeypatch.setattr(_mod, "OTX_API_KEY", "test-api-key")
    responses.add(
        responses.GET,
        re.compile(r"https://otx\.alienvault\.com/.*"),
        body=b"not json",
        content_type="text/html",
    )
    result = fetch_otx_pulses(test_db)
    assert result == 0


@responses.activate
def test_otx_network_error(test_db, mocker, monkeypatch):
    """OTX ConnectionError on all retries -> returns 0, no exception propagated."""
    mocker.patch("time.sleep")
    monkeypatch.setattr(_mod, "OTX_API_KEY", "test-api-key")
    responses.add(
        responses.GET,
        re.compile(r"https://otx\.alienvault\.com/.*"),
        body=requests.exceptions.ConnectionError(),
    )
    result = fetch_otx_pulses(test_db)
    assert result == 0


def test_update_metadata_records_stats(test_db):
    """update_metadata writes feed name, timestamp, and record count to DB."""
    update_metadata(test_db, "feodo", 42)
    row = test_db.execute(
        "SELECT feed_name, record_count FROM feed_metadata WHERE feed_name='feodo'"
    ).fetchone()
    assert row is not None
    assert row[0] == "feodo"
    assert row[1] == 42


@responses.activate
def test_emerging_threats_dry_run(test_db):
    """dry_run=True on emerging threats: counts IPs but DB stays empty."""
    body = "# header\n10.10.10.10\n20.20.20.20\n"
    responses.add(
        responses.GET, FEEDS["emerging_threats_ips"]["url"],
        body=body, content_type="text/plain",
    )
    result = fetch_emerging_threats_ips(test_db, dry_run=True)
    assert result == 2
    assert test_db.execute("SELECT COUNT(*) FROM ip_blacklist").fetchone()[0] == 0


# ---------------------------------------------------------------------------
# Targeted tests to cover remaining uncovered branches and push past 80%
# ---------------------------------------------------------------------------

@responses.activate
def test_malwarebazaar_skips_sample_with_empty_sha256(test_db):
    """Samples with an empty sha256_hash are silently skipped."""
    responses.add(
        responses.POST, _MB_URL,
        json={
            "query_status": "ok",
            "data": [
                # empty sha256 — should be skipped
                {"sha256_hash": "", "md5_hash": "abc", "signature": "Emotet",
                 "first_seen": "2024-01-01 00:00:00"},
                # valid sha256 — should be inserted
                {"sha256_hash": "fff999fff999fff999fff999fff999fff999fff999fff999fff999fff999ffff",
                 "md5_hash": "ggg888", "signature": "Trickbot",
                 "first_seen": "2024-01-01 00:00:00"},
            ],
        },
        content_type="application/json",
    )
    result = fetch_malwarebazaar(test_db)
    assert result == 1
    assert test_db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] == 1


@responses.activate
def test_malwarebazaar_json_decode_error(test_db):
    """Valid Content-Type but malformed JSON body -> returns 0 (JSONDecodeError caught)."""
    responses.add(
        responses.POST, _MB_URL,
        body=b"{not: valid: json{{{}",
        content_type="application/json",
    )
    result = fetch_malwarebazaar(test_db)
    assert result == 0


@responses.activate
def test_urlhaus_skips_single_token_lines(test_db):
    """Lines with fewer than 2 whitespace-separated tokens are skipped."""
    hostfile = (
        "0.0.0.0 valid.example.com\n"
        "justonetoken\n"          # skipped — no domain part
        "0.0.0.0 also.valid.com\n"
    )
    responses.add(responses.GET, _URLHAUS_URL, body=hostfile, content_type="text/plain")
    result = fetch_urlhaus_domains(test_db)
    assert result == 2


@responses.activate
def test_urlhaus_dry_run(test_db):
    """dry_run=True on URLhaus: counts domains but DB stays empty."""
    hostfile = "0.0.0.0 dry.example.com\n"
    responses.add(responses.GET, _URLHAUS_URL, body=hostfile, content_type="text/plain")
    result = fetch_urlhaus_domains(test_db, dry_run=True)
    assert result == 1
    assert test_db.execute("SELECT COUNT(*) FROM domain_blacklist").fetchone()[0] == 0


@responses.activate
def test_feodo_skips_row_with_empty_ip(test_db):
    """CSV row with an empty dst_ip field is silently skipped."""
    csv_with_empty = (
        "# comment\n"
        "2023-01-01 00:00:00,,443,Emotet,online,h.com,AS1,P,US,CA,LA,r,2023-01-02\n"
        "2023-01-02 00:00:00,1.2.3.4,80,Emotet,online,h.com,AS1,P,US,CA,LA,r,2023-01-03\n"
    )
    responses.add(responses.GET, _FEODO_URL, body=csv_with_empty, content_type="text/csv")
    result = fetch_feodo_c2_ips(test_db)
    assert result == 1


@responses.activate
def test_feodo_dry_run(test_db):
    """dry_run=True on Feodo: counts C2 IPs but DB stays empty."""
    responses.add(responses.GET, _FEODO_URL, body=_FEODO_CSV, content_type="text/csv")
    result = fetch_feodo_c2_ips(test_db, dry_run=True)
    assert result == 3
    assert test_db.execute("SELECT COUNT(*) FROM ip_blacklist").fetchone()[0] == 0


@responses.activate
def test_otx_skips_indicator_with_empty_value(test_db, monkeypatch):
    """OTX indicators with an empty value string are silently skipped."""
    monkeypatch.setattr(_mod, "OTX_API_KEY", "test-key")
    responses.add(
        responses.GET,
        re.compile(r"https://otx\.alienvault\.com/.*"),
        json={
            "results": [{
                "name": "TestPulse",
                "indicators": [
                    {"type": "FileHash-SHA256", "indicator": ""},   # empty — skipped
                    {"type": "FileHash-SHA256",
                     "indicator": "abc111abc111abc111abc111abc111abc111abc111abc111abc111abc111abcd"},
                ],
            }]
        },
        content_type="application/json",
    )
    result = fetch_otx_pulses(test_db)
    assert result == 1


@responses.activate
def test_otx_dry_run(test_db, monkeypatch):
    """dry_run=True on OTX: counts indicators but DB stays empty."""
    monkeypatch.setattr(_mod, "OTX_API_KEY", "test-key")
    responses.add(
        responses.GET,
        re.compile(r"https://otx\.alienvault\.com/.*"),
        json={
            "results": [{
                "name": "Pulse",
                "indicators": [
                    {"type": "FileHash-SHA256",
                     "indicator": "ddd444ddd444ddd444ddd444ddd444ddd444ddd444ddd444ddd444ddd444dddd"},
                    {"type": "domain",  "indicator": "otx-dry.example.com"},
                    {"type": "IPv4",    "indicator": "9.8.7.6"},
                ],
            }]
        },
        content_type="application/json",
    )
    result = fetch_otx_pulses(test_db, dry_run=True)
    assert result == 3
    assert test_db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] == 0
    assert test_db.execute("SELECT COUNT(*) FROM domain_blacklist").fetchone()[0] == 0
    assert test_db.execute("SELECT COUNT(*) FROM ip_blacklist").fetchone()[0] == 0


@responses.activate
def test_otx_json_decode_error(test_db, monkeypatch):
    """Valid Content-Type but malformed OTX JSON body -> returns 0 (JSONDecodeError caught)."""
    monkeypatch.setattr(_mod, "OTX_API_KEY", "test-key")
    responses.add(
        responses.GET,
        re.compile(r"https://otx\.alienvault\.com/.*"),
        body=b"{{not valid json at all",
        content_type="application/json",
    )
    result = fetch_otx_pulses(test_db)
    assert result == 0
