"""PostgreSQL connection + findings persistence (long-term memory).

The `FindingStore` uses portable SQL (TEXT/REAL columns, Python-generated ids and
timestamps, no SERIAL/JSONB) so it runs on PostgreSQL in production and on stdlib
sqlite3 in tests — real round-trips, no mocks. Creds come from env, never committed.
"""

from __future__ import annotations

import json
import time
import uuid

from agent.tools.schema import Finding

DATABASE_URL = None  # resolved lazily from env in get_connection()

_DDL = [
    """
    CREATE TABLE IF NOT EXISTS findings (
        id          TEXT PRIMARY KEY,
        session_id  TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        seq         INTEGER NOT NULL,
        tool        TEXT,
        phase       TEXT,
        target      TEXT,
        title       TEXT,
        cve         TEXT,
        cvss        REAL,
        severity    TEXT,
        data        TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)",
]

_COLUMNS = (
    "id", "session_id", "created_at", "seq", "tool", "phase",
    "target", "title", "cve", "cvss", "severity", "data",
)


class FindingStore:
    """Persist and retrieve findings. `placeholder` is the DB-API paramstyle
    ('%s' for psycopg, '?' for sqlite3)."""

    def __init__(self, conn, placeholder: str = "%s"):
        self.conn = conn
        self.ph = placeholder

    def init_schema(self) -> None:
        cur = self.conn.cursor()
        for stmt in _DDL:
            cur.execute(stmt)
        self.conn.commit()

    def save(self, session_id: str, findings: list[Finding]) -> int:
        """Insert findings for a session. Returns the number written."""
        if not findings:
            return 0
        placeholders = ", ".join([self.ph] * len(_COLUMNS))
        sql = f"INSERT INTO findings ({', '.join(_COLUMNS)}) VALUES ({placeholders})"
        base_us = int(time.time() * 1_000_000)
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cur = self.conn.cursor()
        for i, f in enumerate(findings):
            cur.execute(sql, (
                str(uuid.uuid4()), session_id, now_iso, base_us + i,
                f.tool, f.phase, f.target, f.title, f.cve, f.cvss, f.severity,
                f.model_dump_json(),
            ))
        self.conn.commit()
        return len(findings)

    def load(self, session_id: str) -> list[Finding]:
        """Return findings for a session in insertion order."""
        sql = (f"SELECT data FROM findings WHERE session_id = {self.ph} "
               f"ORDER BY seq, id")
        cur = self.conn.cursor()
        cur.execute(sql, (session_id,))
        return [Finding.model_validate_json(row[0]) for row in cur.fetchall()]


def get_connection():
    """Return a live PostgreSQL connection (psycopg). Creds from DATABASE_URL env."""
    import os
    import psycopg  # pip install "psycopg[binary]"

    url = os.environ.get("DATABASE_URL", "postgresql://redagent:redagent@localhost:5432/redagent")
    return psycopg.connect(url)


def get_store() -> FindingStore:
    """FindingStore backed by PostgreSQL, schema ensured."""
    store = FindingStore(get_connection(), placeholder="%s")
    store.init_schema()
    return store
