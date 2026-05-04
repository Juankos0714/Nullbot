"""
NullBot — Signature Updater
File: signatures/updater/update_feeds.py

Fetches threat intelligence from open feeds and updates local databases:
- Abuse.ch MalwareBazaar  → malware hash database
- Abuse.ch URLhaus        → malicious URL/domain blacklist
- AlienVault OTX          → IOC pulses (IPs, domains, hashes)
- Emerging Threats        → IP reputation list

Run this script on a schedule (e.g., every 6 hours via Windows Task Scheduler).
"""

import requests
import sqlite3
import hashlib
import json
import gzip
import csv
import io
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

# ─── Configuration ────────────────────────────────────────────────────────────

DATA_DIR = Path(os.environ.get("NULLBOT_DATA_DIR", "C:/ProgramData/NullBot/signatures"))
LOG_FILE = DATA_DIR / "updater.log"

OTX_API_KEY = os.environ.get("NULLBOT_OTX_API_KEY", "")  # Optional: from AlienVault OTX

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("nullbot.updater")

# ─── Feed definitions ─────────────────────────────────────────────────────────

FEEDS = {
    "malwarebazaar_recent": {
        "url":  "https://mb-api.abuse.ch/api/v1/",
        "type": "api_post",
        "body": {"query": "get_recent", "selector": "time"},
        "desc": "MalwareBazaar recent samples"
    },
    "urlhaus_domains": {
        "url":  "https://urlhaus.abuse.ch/downloads/hostfile/",
        "type": "hostfile",
        "desc": "URLhaus malicious domains"
    },
    "emerging_threats_ips": {
        "url":  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip_list",
        "desc": "Emerging Threats compromised IPs"
    },
    "feodo_botnet_c2": {
        "url":  "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "type": "feodo_csv",
        "desc": "Feodo Tracker botnet C2 IPs (Emotet, TrickBot, etc.)"
    }
}

# ─── Database setup ───────────────────────────────────────────────────────────

def init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            sha256      TEXT PRIMARY KEY,
            md5         TEXT,
            threat_name TEXT NOT NULL,
            malware_family TEXT,
            first_seen  TEXT,
            source      TEXT
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
            feed_name   TEXT PRIMARY KEY,
            last_update TEXT,
            record_count INTEGER
        )
    """)

    conn.commit()
    return conn


# ─── Feed fetchers ────────────────────────────────────────────────────────────

def fetch_malwarebazaar(conn: sqlite3.Connection) -> int:
    """Fetch recent samples from MalwareBazaar and insert hashes."""
    log.info("Fetching MalwareBazaar recent samples...")
    try:
        resp = requests.post(
            FEEDS["malwarebazaar_recent"]["url"],
            data=FEEDS["malwarebazaar_recent"]["body"],
            timeout=30
        )
        data = resp.json()

        if data.get("query_status") != "ok":
            log.warning("MalwareBazaar returned non-ok status")
            return 0

        inserted = 0
        c = conn.cursor()
        for sample in data.get("data", []):
            sha256  = sample.get("sha256_hash", "").lower()
            md5     = sample.get("md5_hash", "").lower()
            tags    = sample.get("tags") or []
            family  = sample.get("signature") or "Unknown"
            name    = f"Malware.{family}" if family != "Unknown" else "Malware.Unknown"

            if sha256:
                c.execute("""
                    INSERT OR IGNORE INTO hashes (sha256, md5, threat_name, malware_family, first_seen, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (sha256, md5, name, family, sample.get("first_seen"), "MalwareBazaar"))
                inserted += c.rowcount

        conn.commit()
        log.info(f"MalwareBazaar: {inserted} new hashes inserted")
        return inserted

    except Exception as e:
        log.error(f"MalwareBazaar fetch failed: {e}")
        return 0


def fetch_urlhaus_domains(conn: sqlite3.Connection) -> int:
    """Fetch URLhaus hostfile (malicious domains)."""
    log.info("Fetching URLhaus domain list...")
    try:
        resp = requests.get(FEEDS["urlhaus_domains"]["url"], timeout=30)
        lines = resp.text.splitlines()

        inserted = 0
        c = conn.cursor()
        today = datetime.utcnow().isoformat()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Hostfile format: "0.0.0.0 domain.com"
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].lower()
                c.execute("""
                    INSERT OR IGNORE INTO domain_blacklist (domain, threat_type, first_seen, source)
                    VALUES (?, ?, ?, ?)
                """, (domain, "malware_distribution", today, "URLhaus"))
                inserted += c.rowcount

        conn.commit()
        log.info(f"URLhaus: {inserted} new domains inserted")
        return inserted

    except Exception as e:
        log.error(f"URLhaus fetch failed: {e}")
        return 0


def fetch_feodo_c2_ips(conn: sqlite3.Connection) -> int:
    """Fetch Feodo Tracker botnet C2 IP list (Emotet, TrickBot, Dridex, etc.)."""
    log.info("Fetching Feodo Tracker C2 IPs...")
    try:
        resp = requests.get(FEEDS["feodo_botnet_c2"]["url"], timeout=30)
        reader = csv.DictReader(
            io.StringIO(resp.text),
            fieldnames=["first_seen", "dst_ip", "dst_port", "malware", "status", "hostname", "as_number", "as_name", "country", "region", "city", "reporter", "last_online"]
        )

        inserted = 0
        c = conn.cursor()

        for row in reader:
            if row["dst_ip"].startswith("#") or not row["dst_ip"].strip():
                continue
            ip   = row["dst_ip"].strip()
            port = int(row["dst_port"].strip()) if row["dst_port"].strip().isdigit() else 0
            malware = row["malware"].strip() if row.get("malware") else "Botnet"

            c.execute("""
                INSERT OR REPLACE INTO ip_blacklist (ip, threat_type, port, first_seen, source)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, f"C2.{malware}", port, row.get("first_seen"), "FeodoTracker"))
            inserted += c.rowcount

        conn.commit()
        log.info(f"Feodo Tracker: {inserted} C2 IPs inserted")
        return inserted

    except Exception as e:
        log.error(f"Feodo fetch failed: {e}")
        return 0


def fetch_emerging_threats_ips(conn: sqlite3.Connection) -> int:
    """Fetch Emerging Threats compromised IP list."""
    log.info("Fetching Emerging Threats compromised IPs...")
    try:
        resp = requests.get(FEEDS["emerging_threats_ips"]["url"], timeout=30)
        lines = resp.text.splitlines()

        inserted = 0
        c = conn.cursor()
        today = datetime.utcnow().isoformat()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            c.execute("""
                INSERT OR IGNORE INTO ip_blacklist (ip, threat_type, port, first_seen, source)
                VALUES (?, ?, ?, ?, ?)
            """, (line, "compromised", 0, today, "EmergingThreats"))
            inserted += c.rowcount

        conn.commit()
        log.info(f"Emerging Threats: {inserted} IPs inserted")
        return inserted

    except Exception as e:
        log.error(f"Emerging Threats fetch failed: {e}")
        return 0


def fetch_otx_pulses(conn: sqlite3.Connection) -> int:
    """Fetch AlienVault OTX pulses (requires free API key)."""
    if not OTX_API_KEY:
        log.info("OTX API key not set, skipping")
        return 0

    log.info("Fetching AlienVault OTX pulses...")
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        since   = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        url     = f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}&limit=100"

        resp = requests.get(url, headers=headers, timeout=30)
        data = resp.json()

        inserted = 0
        c = conn.cursor()
        today = datetime.utcnow().isoformat()

        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                itype = indicator.get("type", "")
                value = indicator.get("indicator", "").lower()

                if itype in ("FileHash-SHA256",) and value:
                    c.execute("""
                        INSERT OR IGNORE INTO hashes (sha256, md5, threat_name, malware_family, first_seen, source)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (value, "", f"OTX.{pulse.get('name', 'Unknown')}", "", today, "OTX"))
                    inserted += c.rowcount

                elif itype in ("domain", "hostname") and value:
                    c.execute("""
                        INSERT OR IGNORE INTO domain_blacklist (domain, threat_type, first_seen, source)
                        VALUES (?, ?, ?, ?)
                    """, (value, "malicious", today, "OTX"))
                    inserted += c.rowcount

                elif itype == "IPv4" and value:
                    c.execute("""
                        INSERT OR IGNORE INTO ip_blacklist (ip, threat_type, port, first_seen, source)
                        VALUES (?, ?, ?, ?, ?)
                    """, (value, "malicious", 0, today, "OTX"))
                    inserted += c.rowcount

        conn.commit()
        log.info(f"OTX: {inserted} indicators inserted")
        return inserted

    except Exception as e:
        log.error(f"OTX fetch failed: {e}")
        return 0


# ─── Update metadata ──────────────────────────────────────────────────────────

def update_metadata(conn: sqlite3.Connection, feed_name: str, count: int):
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO feed_metadata (feed_name, last_update, record_count)
        VALUES (?, ?, ?)
    """, (feed_name, datetime.utcnow().isoformat(), count))
    conn.commit()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db_path = DATA_DIR / "signatures.db"

    log.info("=== NullBot Signature Updater Starting ===")
    conn = init_db(db_path)

    results = {
        "malwarebazaar": fetch_malwarebazaar(conn),
        "urlhaus":        fetch_urlhaus_domains(conn),
        "feodo":          fetch_feodo_c2_ips(conn),
        "emerging":       fetch_emerging_threats_ips(conn),
        "otx":            fetch_otx_pulses(conn),
    }

    for feed, count in results.items():
        update_metadata(conn, feed, count)

    total = sum(results.values())
    log.info(f"=== Update complete. {total} new indicators added. ===")

    conn.close()


if __name__ == "__main__":
    main()
