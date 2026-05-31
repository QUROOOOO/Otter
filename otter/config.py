"""Otter configuration and database initialization.

This module creates and initializes a local SQLite database named
`secure_flow.db` located at the project root. It enables foreign keys and
provides helper functions to obtain connections configured with
`PRAGMA foreign_keys = ON;`.

Tables created:
- scan_sessions: records scan runs
- vulnerabilities: findings produced by scanners (semgrep, etc.)

Indexes are created on `vulnerabilities(session_id)` and
`vulnerabilities(remediation_status)` as requested.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
import logging
from typing import Optional

LOG = logging.getLogger(__name__)

# Database file at the project root (two levels up from otter/config.py)
DB_PATH: Path = Path(__file__).resolve().parent.parent / "secure_flow.db"


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Return a sqlite3.Connection with foreign keys enabled.

    The connection uses `Row` factory for convenience. `check_same_thread`
    is set to False to make the connection usable across threads when
    appropriate callers manage concurrency.
    """
    path = db_path or DB_PATH
    conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys on every new connection
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Create the database schema if it doesn't exist yet."""
    path = db_path or DB_PATH
    LOG.debug("Initializing Otter DB at %s", path)
    conn = get_connection(path)
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            BEGIN;
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                target_path TEXT NOT NULL,
                semgrep_rules TEXT,
                status TEXT NOT NULL DEFAULT 'queued',
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                tool TEXT NOT NULL,
                rule_id TEXT,
                message TEXT,
                file_path TEXT,
                start_line INTEGER,
                end_line INTEGER,
                start_col INTEGER,
                end_col INTEGER,
                severity TEXT,
                remediation_status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_vuln_session_id ON vulnerabilities(session_id);
            CREATE INDEX IF NOT EXISTS idx_vuln_remediation_status ON vulnerabilities(remediation_status);
            COMMIT;
            """
        )
    finally:
        conn.commit()
        conn.close()


# Ensure DB exists and schema is present on import
try:
    init_db()
except Exception:
    LOG.exception("Failed to initialize otter database")


__all__ = ["DB_PATH", "get_connection", "init_db"]
