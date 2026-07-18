"""
database.py
Penyimpanan histori audit menggunakan SQLite (database/audit.db).

Skema:
  scans(id, host, scanned_at, risk_score, raw_json)
  findings(id, scan_id, category, severity, title, description, recommendation, created_at)
"""

import json
import sqlite3
from contextlib import contextmanager

from config import DB_PATH
from utils import get_logger, now_iso

logger = get_logger(__name__)


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                raw_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL UNIQUE,
                s3_buckets TEXT DEFAULT '',
                added_at TEXT NOT NULL
            )
        """)
        # Migrasi ringan untuk database lama yang dibuat sebelum kolom ini ada
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN report_path TEXT")
        except sqlite3.OperationalError:
            pass  # kolom sudah ada
    logger.info(f"Database siap di {DB_PATH}")


def update_scan_report_path(scan_id: int, report_path: str):
    with get_connection() as conn:
        conn.execute("UPDATE scans SET report_path = ? WHERE id = ?", (report_path, scan_id))


# ---------------------------------------------------------------------------
# CRUD untuk daftar target (dipakai oleh web dashboard: webapp.py)
# ---------------------------------------------------------------------------
def add_target(host: str, s3_buckets: str = "") -> bool:
    """Tambah domain/host baru untuk diaudit. Return False jika sudah ada."""
    host = host.strip().lower()
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO targets (host, s3_buckets, added_at) VALUES (?, ?, ?)",
                (host, s3_buckets, now_iso()),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def remove_target(host: str):
    with get_connection() as conn:
        conn.execute("DELETE FROM targets WHERE host = ?", (host,))


def list_targets() -> list:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM targets ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_target(host: str):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM targets WHERE host = ?", (host,)).fetchone()
        return dict(row) if row else None


def save_scan(host: str, scan_result: dict, risk_score: int) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO scans (host, scanned_at, risk_score, raw_json) VALUES (?, ?, ?, ?)",
            (host, now_iso(), risk_score, json.dumps(scan_result)),
        )
        return cur.lastrowid


def save_findings(scan_id: int, findings: list):
    with get_connection() as conn:
        for f in findings:
            conn.execute(
                """INSERT INTO findings
                   (scan_id, category, severity, title, description, recommendation, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, f["category"], f["severity"], f["title"],
                 f["description"], f["recommendation"], now_iso()),
            )


def get_latest_scan(host: str):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE host = ? ORDER BY id DESC LIMIT 1", (host,)
        ).fetchone()
        return dict(row) if row else None


def get_findings_for_scan(scan_id: int) -> list:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY "
            "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
            "WHEN 'MEDIUM' THEN 2 ELSE 3 END", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_history(host: str, limit: int = 10) -> list:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE host = ? ORDER BY id DESC LIMIT ?", (host, limit)
        ).fetchall()
        return [dict(r) for r in rows]
