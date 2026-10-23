"""Report storage: SQLite, keyed by an unguessable 128-bit ID, deleted after 24h.

Reports contain masked addresses only, never a raw visitor IP.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path

from netcheck.verdict.model import Report

RESULT_TTL_SECONDS = 24 * 3600
REPORT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")


class ResultStore:
    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS reports "
            "(id TEXT PRIMARY KEY, created REAL NOT NULL, body TEXT NOT NULL)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS reports_created ON reports (created)")
        # Aggregate counts only (day, "card:status" -> n): no IDs, no addresses.
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS daily_counts "
            "(day TEXT NOT NULL, metric TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, metric))"
        )
        path.chmod(0o600)

    def save(self, report: Report) -> None:
        body = json.dumps(report.to_json(), separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                "INSERT INTO reports (id, created, body) VALUES (?, ?, ?)",
                (report.id, report.created, body),
            )

    def get(self, report_id: str) -> Report | None:
        if not REPORT_ID_RE.fullmatch(report_id):
            return None
        cutoff = self._clock() - RESULT_TTL_SECONDS
        with self._lock:
            row = self._conn.execute(
                "SELECT body FROM reports WHERE id = ? AND created >= ?", (report_id, cutoff)
            ).fetchone()
        return Report.from_json(json.loads(row[0])) if row else None

    def count_report(self, report: Report) -> None:
        day = time.strftime("%Y-%m-%d", time.gmtime(report.created))
        metrics = ["scans", f"overall:{report.overall}"]
        metrics += [f"{c.key}:{c.status}" for c in report.cards]
        with self._lock:
            self._conn.executemany(
                "INSERT INTO daily_counts (day, metric, n) VALUES (?, ?, 1) "
                "ON CONFLICT (day, metric) DO UPDATE SET n = n + 1",
                [(day, m) for m in metrics],
            )

    def daily_counts(self, days: int = 14) -> list[tuple[str, str, int]]:
        cutoff = time.strftime("%Y-%m-%d", time.gmtime(self._clock() - days * 86400))
        with self._lock:
            rows = self._conn.execute(
                "SELECT day, metric, n FROM daily_counts WHERE day > ? ORDER BY day, metric",
                (cutoff,),
            ).fetchall()
        return [(str(d), str(m), int(n)) for d, m, n in rows]

    def purge(self) -> int:
        cutoff = self._clock() - RESULT_TTL_SECONDS
        with self._lock:
            return self._conn.execute("DELETE FROM reports WHERE created < ?", (cutoff,)).rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
