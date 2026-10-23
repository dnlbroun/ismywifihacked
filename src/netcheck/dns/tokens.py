"""DNS-check token store: which resolver looked up which token.

The DNS server process is the only writer. The web app opens the database read-only
(different Unix user, group-readable file), so it can never alter DNS observations.
Writes are buffered and flushed in small batches so a flood of valid-looking queries
can't turn into one fsync per packet.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path

from netcheck.addrpolicy import IPAddress

TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
TOKEN_TTL_SECONDS = 600
MAX_RESOLVERS_PER_TOKEN = 8
MAX_ROWS = 200_000
MAX_PENDING = 10_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sightings (
    token    TEXT NOT NULL,
    resolver TEXT NOT NULL,
    seen_at  REAL NOT NULL,
    PRIMARY KEY (token, resolver)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS sightings_seen_at ON sightings (seen_at);
"""

Clock = Callable[[], float]


def is_valid_token(token: str) -> bool:
    return TOKEN_RE.fullmatch(token) is not None


class TokenWriter:
    def __init__(self, path: Path, *, clock: Clock = time.time) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._conn = sqlite3.connect(path, isolation_level=None)
        # Rollback journal (not WAL) so read-only readers in another uid don't need
        # write access to a -shm file.
        self._conn.execute("PRAGMA journal_mode=DELETE")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        os.chmod(path, 0o640)
        self._pending: dict[tuple[str, str], float] = {}
        self._full = False

    def record(self, token: str, resolver: IPAddress) -> bool:
        """Queue a sighting. Returns False if it was rejected."""
        if not is_valid_token(token) or self._full or len(self._pending) >= MAX_PENDING:
            return False
        self._pending.setdefault((token, str(resolver)), self._clock())
        return True

    def flush(self) -> int:
        if not self._pending:
            return 0
        batch, self._pending = self._pending, {}
        cur = self._conn.cursor()
        cur.execute("BEGIN")
        written = 0
        for (token, resolver), seen_at in batch.items():
            (count,) = cur.execute(
                "SELECT COUNT(*) FROM sightings WHERE token = ?", (token,)
            ).fetchone()
            if count >= MAX_RESOLVERS_PER_TOKEN:
                continue
            cur.execute(
                "INSERT OR IGNORE INTO sightings (token, resolver, seen_at) VALUES (?, ?, ?)",
                (token, resolver, seen_at),
            )
            written += cur.rowcount
        cur.execute("COMMIT")
        return written

    def purge(self) -> int:
        cutoff = self._clock() - TOKEN_TTL_SECONDS
        deleted = self._conn.execute("DELETE FROM sightings WHERE seen_at < ?", (cutoff,)).rowcount
        (rows,) = self._conn.execute("SELECT COUNT(*) FROM sightings").fetchone()
        self._full = rows >= MAX_ROWS
        return deleted

    def close(self) -> None:
        self.flush()
        self._conn.close()


class TokenReader:
    def __init__(self, path: Path, *, clock: Clock = time.time) -> None:
        self._path = path
        self._clock = clock

    def resolvers(self, token: str) -> list[IPAddress]:
        if not is_valid_token(token) or not self._path.exists():
            return []
        cutoff = self._clock() - TOKEN_TTL_SECONDS
        try:
            conn = sqlite3.connect(f"{self._path.as_uri()}?mode=ro", uri=True, timeout=1.0)
            try:
                rows = conn.execute(
                    "SELECT resolver FROM sightings WHERE token = ? AND seen_at >= ? "
                    "ORDER BY seen_at LIMIT ?",
                    (token, cutoff, MAX_RESOLVERS_PER_TOKEN),
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            # Locked mid-write or not created yet: the caller just polls again.
            return []
        out: list[IPAddress] = []
        for (resolver,) in rows:
            try:
                out.append(ipaddress.ip_address(resolver))
            except ValueError:
                continue
        return out
