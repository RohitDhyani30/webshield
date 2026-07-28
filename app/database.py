"""
SQLite persistence layer using sqlite3 directly (kept lightweight, no ORM).
Stores scans and findings so scan history/comparison is possible.
"""
import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = "webshield.db"


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                pages_crawled INTEGER DEFAULT 0,
                forms_found INTEGER DEFAULT 0,
                risk_score REAL,
                risk_level TEXT,
                status TEXT DEFAULT 'running'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                url TEXT,
                parameter TEXT,
                evidence TEXT,
                remediation TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        """)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def create_scan(target_url: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target_url, started_at, status) VALUES (?, ?, ?)",
            (target_url, datetime.now(timezone.utc).isoformat(), "running"),
        )
        conn.commit()
        return cur.lastrowid


def finish_scan(scan_id: int, pages_crawled: int, forms_found: int, risk_score: float, risk_level: str):
    with get_conn() as conn:
        conn.execute(
            """UPDATE scans SET finished_at=?, pages_crawled=?, forms_found=?,
               risk_score=?, risk_level=?, status='completed' WHERE id=?""",
            (datetime.now(timezone.utc).isoformat(), pages_crawled, forms_found,
             risk_score, risk_level, scan_id),
        )
        conn.commit()


def add_finding(scan_id: int, finding: dict):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO findings
               (scan_id, module, title, severity, confidence, url, parameter, evidence, remediation, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id, finding["module"], finding["title"], finding["severity"],
                finding["confidence"], finding.get("url"), finding.get("parameter"),
                json.dumps(finding.get("evidence", {})), finding.get("remediation", ""),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()


def get_scan(scan_id: int):
    with get_conn() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        findings = conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        return dict(scan) if scan else None, [dict(f) for f in findings]


def list_scans():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
