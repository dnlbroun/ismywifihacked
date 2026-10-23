import ipaddress
import sqlite3
from pathlib import Path

import pytest

from netcheck.dns import tokens
from netcheck.dns.tokens import TokenReader, TokenWriter

TOKEN = "0123456789abcdef0123456789abcdef"
R1 = ipaddress.IPv4Address("198.51.100.53")
R2 = ipaddress.IPv6Address("2001:db8::53")


class FakeClock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "dns" / "tokens.db"


def test_record_flush_read(db: Path, clock: FakeClock) -> None:
    w = TokenWriter(db, clock=clock)
    r = TokenReader(db, clock=clock)
    assert w.record(TOKEN, R1)
    assert w.record(TOKEN, R2)
    assert w.record(TOKEN, R1)  # duplicate is fine, stored once
    assert r.resolvers(TOKEN) == []  # nothing until flushed
    assert w.flush() == 2
    assert r.resolvers(TOKEN) == [R1, R2]


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef",
        TOKEN + "0",
        "'; DROP TABLE sightings; --",
        TOKEN + "\n",
    ],
)
def test_invalid_tokens_rejected(db: Path, clock: FakeClock, bad: str) -> None:
    w = TokenWriter(db, clock=clock)
    assert not w.record(bad, R1)
    assert w.flush() == 0
    assert TokenReader(db, clock=clock).resolvers(bad) == []


def test_tokens_expire_after_ten_minutes(db: Path, clock: FakeClock) -> None:
    w = TokenWriter(db, clock=clock)
    r = TokenReader(db, clock=clock)
    w.record(TOKEN, R1)
    w.flush()
    clock.t += 599
    assert r.resolvers(TOKEN) == [R1]
    clock.t += 2
    assert r.resolvers(TOKEN) == []  # hidden even before purge runs
    assert w.purge() == 1


def test_resolvers_per_token_capped(db: Path, clock: FakeClock) -> None:
    w = TokenWriter(db, clock=clock)
    for i in range(20):
        w.record(TOKEN, ipaddress.IPv4Address(f"198.51.100.{i + 1}"))
    w.flush()
    assert len(TokenReader(db, clock=clock).resolvers(TOKEN)) == tokens.MAX_RESOLVERS_PER_TOKEN


def test_store_stops_accepting_when_full(
    db: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tokens, "MAX_ROWS", 3)
    w = TokenWriter(db, clock=clock)
    for i in range(3):
        w.record(f"{i:032x}", R1)
    w.flush()
    w.purge()
    assert not w.record(f"{9:032x}", R1)


def test_reader_is_read_only(db: Path, clock: FakeClock) -> None:
    TokenWriter(db, clock=clock)
    conn = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM sightings")


def test_reader_missing_db(tmp_path: Path) -> None:
    assert TokenReader(tmp_path / "nope.db").resolvers(TOKEN) == []


def test_db_file_not_world_readable(db: Path, clock: FakeClock) -> None:
    TokenWriter(db, clock=clock)
    assert db.stat().st_mode & 0o007 == 0
