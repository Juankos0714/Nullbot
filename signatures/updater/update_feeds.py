"""
NullBot — Signature Updater
File: signatures/updater/update_feeds.py

Fetches threat intelligence from open feeds and updates local databases:
- Abuse.ch MalwareBazaar  -> malware hash database
- Abuse.ch URLhaus        -> malicious URL/domain blacklist
- AlienVault OTX          -> IOC pulses (IPs, domains, hashes)
- Emerging Threats        -> IP reputation list
- Feodo Tracker           -> botnet C2 IP list

Run this script on a schedule (e.g., every 6 hours via Windows Task Scheduler).
"""

import argparse
import csv
import io
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests

# --- Configuration ------------------------------------------------------------

DATA_DIR = Path(os.environ.get("NULLBOT_DATA_DIR", "C:/ProgramData/NullBot/signatures"))
OTX_API_KEY = os.environ.get("NULLBOT_OTX_API_KEY", "")

# NullHandler prevents "No handlers found" warnings when imported as a library.
# main() attaches the real File + Stream handlers at runtime.
log = logging.getLogger("nullbot.updater")
log.addHandler(logging.NullHandler())

# --- Feed definitions ---------------------------------------------------------

FEEDS = {
    "malwarebazaar_recent": {
        "url":  "https://mb-api.abuse.ch/api/v1/",
        "type": "api_post",
        "body": {"query": "get_recent", "selector": "time"},
        "desc": "MalwareBazaar recent samples",
    },
    "urlhaus_domains": {
        "url":  "https://urlhaus.abuse.ch/downloads/hostfile/",
        "type": "hostfile",
        "desc": "URLhaus malicious domains",
    },
    "emerging_threats_ips": {
        "url":  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip_list",
        "desc": "Emerging Threats compromised IPs",
    },
    "feodo_botnet_c2": {
        "url":  "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "type": "feodo_csv",
        "desc": "Feodo Tracker botnet C2 IPs (Emotet, TrickBot, etc.)",
    },
}

# --- HTTP helpers -------------------------------------------------------------

def fetch_with_retry(
    url: str,
    method: str = "GET",
    retries: int = 3,
    backoff: float = 2.0,
    **kwargs,
) -> requests.Response:
    """Issue an HTTP request, retrying with exponential backoff on transient errors.

    Returns the successful Response.
    Raises requests.RequestException or IOError once all retries are exhausted.
    """
    for attempt in range(retries):
        try:
            resp = requests.request(method, url, timeout=30, **kwargs)
            resp.raise_for_status()
            return resp
        except (requests.RequestException, IOError) as e:
            if attempt == retries - 1:
                raise
            log.debug(
                "Request to %s failed (attempt %d/%d): %s — retrying",
                url, attempt + 1, retries, e,
            )
            time.sleep(backoff ** attempt)


# --- Database setup -----------------------------------------------------------

def init_db(db_path: Path) -> sqlite3.Connection:
    """Open (or create) the signatures SQLite database and apply the DDL.

    Returns an open Connection.
    Raises sqlite3.OperationalError if db_path is not writable.
    """
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            sha256         TEXT PRIMARY KEY,
            md5            TEXT,
            threat_name    TEXT NOT NULL,
            malware_family TEXT,
            first_seen     TEXT,
            source         TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS domain_blacklist (
            domain      TEXT PRIMARY KEY,
            threat_type TEXT,
            first_seen  TEXT,
            source      TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS ip_blacklist (
            ip          TEXT PRIMARY KEY,
            threat_type TEXT,
            port        INTEGER,
            first_seen  TEXT,
            source      TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS feed_metadata (
            feed_name    TEXT PRIMARY KEY,
            last_update  TEXT,
            record_count INTEGER
        )
    """)

    conn.commit()
    return conn


# --- Feed fetchers ------------------------------------------------------------

def fetch_malwarebazaar(conn: sqlite3.Connection, dry_run: bool = False) -> int:
    """Fetch recent samples from MalwareBazaar and insert hashes into the DB.

    Returns the count of new rows inserted, or the count that would be inserted
    in dry_run mode.
    Raises nothing — all errors are caught, logged, and 0 is returned.
    """
    log.info("Fetching MalwareBazaar recent samples...")
    try:
        resp = fetch_with_retry(
            FEEDS["malwarebazaar_recent"]["url"],
            method="POST",
            data=FEEDS["malwarebazaar_recent"]["body"],
        )
        ct = resp.headers.get("Content-Type", "")
        if "application/json" not in ct:
            log.warning("MalwareBazaar unexpected Content-Type: %s", ct)
            return 0

        data = resp.json()
        if data.get("query_status") != "ok":
            log.warning("MalwareBazaar non-ok status: %s", data.get("query_status"))
            return 0

        count = 0
        c = conn.cursor()
        for sample in data.get("data", []):
            sha256 = sample.get("sha256_hash", "").lower()
            md5    = sample.get("md5_hash", "").lower()
            family = sample.get("signature") or "Unknown"
            name   = f"Malware.{family}" if family != "Unknown" else "Malware.Unknown"

            if not sha256:
                continue
            if dry_run:
                count += 1
            else:
                c.execute("""
                    INSERT OR IGNORE INTO hashes
                        (sha256, md5, threat_name, malware_family, first_seen, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (sha256, md5, name, family, sample.get("first_seen"), "MalwareBazaar"))
                count += c.rowcount

        if not dry_run:
            conn.commit()

        log.info(
            "MalwareBazaar: %d hashes %s",
            count, "would be inserted" if dry_run else "inserted",
        )
        return count

    except json.JSONDecodeError as e:
        log.error("MalwareBazaar response parse error: %s", e)
        return 0
    except (requests.RequestException, IOError) as e:
        log.error("MalwareBazaar fetch failed: %s", e)
        return 0


def fetch_urlhaus_domains(conn: sqlite3.Connection, dry_run: bool = False) -> int:
    """Fetch the URLhaus hosts file and insert malicious domains into domain_blacklist.

    Returns the count of new domains inserted, or would-be inserted in dry_run mode.
    Raises nothing — all errors are caught, logged, and 0 is returned.
    """
    log.info("Fetching URLhaus domain list...")
    try:
        resp = fetch_with_retry(FEEDS["urlhaus_domains"]["url"])
        today = datetime.utcnow().isoformat()
        count = 0
        c = conn.cursor()

        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            domain = parts[1].lower()
            if dry_run:
                count += 1
            else:
                c.execute("""
                    INSERT OR IGNORE INTO domain_blacklist
                        (domain, threat_type, first_seen, source)
                    VALUES (?, ?, ?, ?)
                """, (domain, "malware_distribution", today, "URLhaus"))
                count += c.rowcount

        if not dry_run:
            conn.commit()

        log.info(
            "URLhaus: %d domains %s",
            count, "would be inserted" if dry_run else "inserted",
        )
        return count

    except (requests.RequestException, IOError) as e:
        log.error("URLhaus fetch failed: %s", e)
        return 0


def fetch_feodo_c2_ips(conn: sqlite3.Connection, dry_run: bool = False) -> int:
    """Fetch Feodo Tracker botnet C2 IPs (Emotet, TrickBot, Dridex, etc.).

    Returns the count of C2 IPs inserted, or would-be inserted in dry_run mode.
    Raises nothing — all errors are caught, logged, and 0 is returned.
    """
    log.info("Fetching Feodo Tracker C2 IPs...")
    try:
        resp = fetch_with_retry(FEEDS["feodo_botnet_c2"]["url"])
        reader = csv.DictReader(
            io.StringIO(resp.text),
            fieldnames=[
                "first_seen", "dst_ip", "dst_port", "malware", "status",
                "hostname", "as_number", "as_name", "country", "region",
                "city", "reporter", "last_online",
            ],
        )

        count = 0
        c = conn.cursor()

        for row in reader:
            # Comment/header lines put '#' in the first column (first_seen field).
            if (row.get("first_seen") or "").strip().startswith("#"):
                continue
            dst_ip = row["dst_ip"].strip()
            if not dst_ip:
                continue
            port_str = row["dst_port"].strip()
            port = int(port_str) if port_str.isdigit() else 0
            malware = (row.get("malware") or "Botnet").strip() or "Botnet"

            if dry_run:
                count += 1
            else:
                c.execute("""
                    INSERT OR REPLACE INTO ip_blacklist
                        (ip, threat_type, port, first_seen, source)
                    VALUES (?, ?, ?, ?, ?)
                """, (dst_ip, f"C2.{malware}", port, row.get("first_seen"), "FeodoTracker"))
                count += c.rowcount

        if not dry_run:
            conn.commit()

        log.info(
            "Feodo Tracker: %d C2 IPs %s",
            count, "would be inserted" if dry_run else "inserted",
        )
        return count

    except (requests.RequestException, IOError) as e:
        log.error("Feodo fetch failed: %s", e)
        return 0
    except csv.Error as e:
        log.error("Feodo CSV parse error: %s", e)
        return 0


def fetch_emerging_threats_ips(conn: sqlite3.Connection, dry_run: bool = False) -> int:
    """Fetch the Emerging Threats compromised-IP list and insert into ip_blacklist.

    Returns the count of IPs inserted, or would-be inserted in dry_run mode.
    Raises nothing — all errors are caught, logged, and 0 is returned.
    """
    log.info("Fetching Emerging Threats compromised IPs...")
    try:
        resp = fetch_with_retry(FEEDS["emerging_threats_ips"]["url"])
        today = datetime.utcnow().isoformat()
        count = 0
        c = conn.cursor()

        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if dry_run:
                count += 1
            else:
                c.execute("""
                    INSERT OR IGNORE INTO ip_blacklist
                        (ip, threat_type, port, first_seen, source)
                    VALUES (?, ?, ?, ?, ?)
                """, (line, "compromised", 0, today, "EmergingThreats"))
                count += c.rowcount

        if not dry_run:
            conn.commit()

        log.info(
            "Emerging Threats: %d IPs %s",
            count, "would be inserted" if dry_run else "inserted",
        )
        return count

    except (requests.RequestException, IOError) as e:
        log.error("Emerging Threats fetch failed: %s", e)
        return 0


def fetch_otx_pulses(conn: sqlite3.Connection, dry_run: bool = False) -> int:
    """Fetch AlienVault OTX pulse indicators from the last 24 hours.

    Requires NULLBOT_OTX_API_KEY; skips silently if the key is not set.
    Returns the count of indicators inserted, or would-be inserted in dry_run mode.
    Raises nothing — all errors are caught, logged, and 0 is returned.
    """
    if not OTX_API_KEY:
        log.info("OTX API key not set, skipping")
        return 0

    log.info("Fetching AlienVault OTX pulses...")
    try:
        since = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        url = (
            "https://otx.alienvault.com/api/v1/pulses/subscribed"
            f"?modified_since={since}&limit=100"
        )
        resp = fetch_with_retry(url, headers={"X-OTX-API-KEY": OTX_API_KEY})

        ct = resp.headers.get("Content-Type", "")
        if "application/json" not in ct:
            log.warning("OTX unexpected Content-Type: %s", ct)
            return 0

        data = resp.json()
        today = datetime.utcnow().isoformat()
        count = 0
        c = conn.cursor()

        for pulse in data.get("results", []):
            pulse_name = pulse.get("name", "Unknown")
            for indicator in pulse.get("indicators", []):
                itype = indicator.get("type", "")
                value = indicator.get("indicator", "").lower()
                if not value:
                    continue

                if itype == "FileHash-SHA256":
                    if dry_run:
                        count += 1
                    else:
                        c.execute("""
                            INSERT OR IGNORE INTO hashes
                                (sha256, md5, threat_name, malware_family, first_seen, source)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (value, "", f"OTX.{pulse_name}", "", today, "OTX"))
                        count += c.rowcount

                elif itype in ("domain", "hostname"):
                    if dry_run:
                        count += 1
                    else:
                        c.execute("""
                            INSERT OR IGNORE INTO domain_blacklist
                                (domain, threat_type, first_seen, source)
                            VALUES (?, ?, ?, ?)
                        """, (value, "malicious", today, "OTX"))
                        count += c.rowcount

                elif itype == "IPv4":
                    if dry_run:
                        count += 1
                    else:
                        c.execute("""
                            INSERT OR IGNORE INTO ip_blacklist
                                (ip, threat_type, port, first_seen, source)
                            VALUES (?, ?, ?, ?, ?)
                        """, (value, "malicious", 0, today, "OTX"))
                        count += c.rowcount

        if not dry_run:
            conn.commit()

        log.info(
            "OTX: %d indicators %s",
            count, "would be inserted" if dry_run else "inserted",
        )
        return count

    except json.JSONDecodeError as e:
        log.error("OTX response parse error: %s", e)
        return 0
    except (requests.RequestException, IOError) as e:
        log.error("OTX fetch failed: %s", e)
        return 0


# --- Metadata -----------------------------------------------------------------

def update_metadata(conn: sqlite3.Connection, feed_name: str, count: int) -> None:
    """Record the last-update timestamp and record count for a named feed."""
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO feed_metadata (feed_name, last_update, record_count)
        VALUES (?, ?, ?)
    """, (feed_name, datetime.utcnow().isoformat(), count))
    conn.commit()


# --- Entry point --------------------------------------------------------------

FEED_RUNNERS = {
    "malwarebazaar": fetch_malwarebazaar,
    "urlhaus":       fetch_urlhaus_domains,
    "feodo":         fetch_feodo_c2_ips,
    "emerging":      fetch_emerging_threats_ips,
    "otx":           fetch_otx_pulses,
}


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the updater."""
    parser = argparse.ArgumentParser(description="NullBot signature updater")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch all feeds but do not write to the database",
    )
    parser.add_argument(
        "--feed",
        choices=list(FEED_RUNNERS),
        metavar="FEED",
        help=f"Run only this feed. Choices: {', '.join(FEED_RUNNERS)}",
    )
    return parser.parse_args()


def main() -> None:
    """Fetch all (or one) threat feed and update the local signatures database."""
    args = parse_args()
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    log.setLevel(logging.INFO)
    fh = logging.FileHandler(DATA_DIR / "updater.log")
    fh.setFormatter(formatter)
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(fh)
    log.addHandler(sh)

    db_path = DATA_DIR / "signatures.db"
    log.info(
        "=== NullBot Signature Updater Starting%s ===",
        " [DRY RUN]" if args.dry_run else "",
    )

    conn = init_db(db_path)
    start = time.monotonic()

    runners = {args.feed: FEED_RUNNERS[args.feed]} if args.feed else FEED_RUNNERS
    results = {}
    for name, fn in runners.items():
        results[name] = fn(conn, dry_run=args.dry_run)

    if not args.dry_run:
        for feed, count in results.items():
            update_metadata(conn, feed, count)

    elapsed = time.monotonic() - start
    total = sum(results.values())
    log.info("=== Update complete in %.1fs — %d new indicators ===", elapsed, total)
    for feed, count in results.items():
        log.info("  %-15s %d records", feed, count)

    conn.close()


if __name__ == "__main__":
    main()
