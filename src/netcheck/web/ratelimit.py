"""Per-address scan rate limiting and short-lived address claims, all in memory.

Rate-limit keys are HMAC(salt, address-or-/64). The salt lives only in this process
and rotates every 24h (the previous one is kept for one window so a limit can't be
dodged by waiting for the rotation), so stored keys can't be turned back into IPs
once the salt is gone. Entries older than the window are dropped.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from netcheck.addrpolicy import IPAddress, ScanTarget

SALT_ROTATION_SECONDS = 24 * 3600


def limit_unit(ip: IPAddress) -> str:
    """IPv4 address, or the /64 for IPv6 (one household usually gets a /64 or more)."""
    if ip.version == 6:
        return str(ipaddress.IPv6Network(f"{ip}/64", strict=False))
    return str(ip)


@dataclass
class ScanRateLimiter:
    limit: int = 3
    window: float = 3600.0
    clock: Callable[[], float] = time.time
    _salts: list[tuple[float, bytes]] = field(default_factory=list)
    _hits: dict[bytes, deque[float]] = field(default_factory=dict)

    def _current_salts(self) -> list[bytes]:
        now = self.clock()
        if not self._salts or now - self._salts[-1][0] >= SALT_ROTATION_SECONDS:
            self._salts.append((now, secrets.token_bytes(32)))
        # Keep the previous salt only while it could still matter for the window.
        self._salts = [
            (t, s)
            for i, (t, s) in enumerate(self._salts)
            if i == len(self._salts) - 1 or now - self._salts[i + 1][0] < self.window
        ]
        return [s for _, s in reversed(self._salts)]

    def _keys(self, ip: IPAddress) -> list[bytes]:
        unit = limit_unit(ip).encode()
        return [hmac.new(s, unit, hashlib.sha256).digest() for s in self._current_salts()]

    def _count(self, key: bytes, now: float) -> int:
        q = self._hits.get(key)
        if q is None:
            return 0
        while q and now - q[0] >= self.window:
            q.popleft()
        if not q:
            del self._hits[key]
            return 0
        return len(q)

    def allowed(self, ip: IPAddress) -> bool:
        now = self.clock()
        return sum(self._count(k, now) for k in self._keys(ip)) < self.limit

    def record(self, ip: IPAddress) -> None:
        key = self._keys(ip)[0]
        self._hits.setdefault(key, deque()).append(self.clock())

    def purge(self) -> None:
        now = self.clock()
        for k in list(self._hits):
            self._count(k, now)

    def __len__(self) -> int:
        return len(self._hits)


@dataclass
class ClaimStore:
    """One-time tokens proving "a browser connected from this address just now".

    Used to scan both IPv4 and IPv6: the page asks v4.<domain> and v6.<domain> for a
    claim, and the scan request redeems them. The address in a claim always comes
    from the TCP connection that created it, never from anything the client sent.
    """

    ttl: float = 120.0
    max_entries: int = 10_000
    clock: Callable[[], float] = time.time
    _claims: dict[str, tuple[float, ScanTarget]] = field(default_factory=dict)

    def issue(self, target: ScanTarget) -> str | None:
        self.purge()
        if len(self._claims) >= self.max_entries:
            return None
        claim = secrets.token_urlsafe(16)
        self._claims[claim] = (self.clock() + self.ttl, target)
        return claim

    def redeem(self, claim: str) -> ScanTarget | None:
        entry = self._claims.pop(claim, None)
        if entry is None or entry[0] < self.clock():
            return None
        return entry[1]

    def purge(self) -> None:
        now = self.clock()
        for k in [k for k, (exp, _) in self._claims.items() if exp < now]:
            del self._claims[k]
