"""SQLite persistence: RPC code cache and analysis reports.

SQLite keeps the deployment to a single container with no external service. The
connection is shared across threads behind a lock (FastAPI runs sync endpoints in a
thread pool); WAL mode lets the CLI read reports while the server writes.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS code_cache (
    chain_id   INTEGER NOT NULL,
    address    TEXT    NOT NULL,
    code       BLOB    NOT NULL,
    fetched_at REAL    NOT NULL,
    PRIMARY KEY (chain_id, address)
);
CREATE TABLE IF NOT EXISTS reports (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    score      INTEGER NOT NULL,
    chain_id   INTEGER,
    created_at TEXT NOT NULL,
    body       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_created ON reports (created_at);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- code cache -----------------------------------------------------------------
    def get_code(self, chain_id: int, address: str, ttl: int) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT code, fetched_at FROM code_cache WHERE chain_id = ? AND address = ?",
                (chain_id, address.lower()),
            ).fetchone()
        if row is None or time.time() - row["fetched_at"] > ttl:
            return None
        return bytes(row["code"])

    def put_code(self, chain_id: int, address: str, code: bytes) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO code_cache (chain_id, address, code, fetched_at) "
                "VALUES (?, ?, ?, ?)",
                (chain_id, address.lower(), code, time.time()),
            )

    # -- reports --------------------------------------------------------------------
    def save_report(self, report: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO reports "
                "(id, kind, verdict, score, chain_id, created_at, body) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    report["id"],
                    report["kind"],
                    report["verdict"],
                    report["score"],
                    report.get("chain_id"),
                    report["created_at"],
                    json.dumps(report, separators=(",", ":")),
                ),
            )

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT body FROM reports WHERE id = ?", (report_id,)
            ).fetchone()
        return None if row is None else dict(json.loads(row["body"]))

    def list_reports(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, kind, verdict, score, chain_id, created_at FROM reports "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
