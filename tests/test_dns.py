"""Authoritative DNS server: never an open resolver, not an amplifier, token store."""

import asyncio
import ipaddress
import secrets
from pathlib import Path

import pytest
from dnslib import RCODE, DNSRecord

from netcheck.dns.server import Authority, DnsServer, RateDecision, ResponseRateLimiter
from netcheck.dns.tokens import TokenReader, TokenWriter

ZONE = "dns.example.com"
VPS4 = ipaddress.IPv4Address("203.0.113.10")
SRC = ipaddress.IPv4Address("198.51.100.53")
TOKEN = "0123456789abcdef0123456789abcdef"


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def seen() -> list[str]:
    return []


@pytest.fixture
def auth(seen: list[str]) -> Authority:
    return Authority(ZONE, "ns1.example.com", VPS4, None, lambda t, s: seen.append(t))


def ask(auth: Authority, name: str, qtype: str = "A") -> DNSRecord:
    raw = auth.handle(DNSRecord.question(name, qtype).pack(), SRC)
    assert raw is not None
    return DNSRecord.parse(raw)


def test_token_lookup_answered_and_recorded(auth: Authority, seen: list[str]) -> None:
    r = ask(auth, f"{TOKEN.upper()}.DnS.example.com")  # resolvers randomise case
    assert (r.header.aa, r.header.ra, r.header.rcode) == (1, 0, RCODE.NOERROR)
    assert str(r.rr[0].rdata) == str(VPS4)
    assert seen == [TOKEN]


@pytest.mark.parametrize(
    ("name", "qtype"),
    [("www.google.com", "A"), ("dns.example.com.evil.net", "A"), (ZONE, "ANY"), (f"{TOKEN}.{ZONE}", "ANY")],
)  # fmt: skip
def test_refuses_out_of_zone_recursion_and_any(
    auth: Authority, seen: list[str], name: str, qtype: str
) -> None:
    r = ask(auth, name, qtype)
    assert r.header.rcode == RCODE.REFUSED
    assert r.header.ra == 0  # never offers recursion
    assert not r.rr
    assert not seen


def test_bad_tokens_and_garbage(auth: Authority, seen: list[str]) -> None:
    assert ask(auth, f"not-a-token.{ZONE}").header.rcode == RCODE.NXDOMAIN
    assert auth.handle(b"\xff" * 30, SRC) is None
    assert auth.handle(DNSRecord.question("x.com").reply().pack(), SRC) is None  # responses
    assert not seen


def test_responses_are_small(auth: Authority) -> None:
    for name, qtype in [(f"{TOKEN}.{ZONE}", "A"), (ZONE, "SOA"), ("google.com", "A")]:
        q = DNSRecord.question(name, qtype).pack()
        raw = auth.handle(q, SRC)
        assert raw is not None
        assert len(raw) <= max(3 * len(q), 160)


def test_rate_limiter_per_prefix_with_slip() -> None:
    rrl = ResponseRateLimiter(rate=1.0, burst=2.0, slip=2, clock=Clock())
    a, b = ipaddress.IPv4Address("198.51.100.1"), ipaddress.IPv4Address("198.51.100.99")
    assert [rrl.check(a), rrl.check(b)] == [RateDecision.SEND] * 2  # same /24 shares a bucket
    assert [rrl.check(a), rrl.check(a)] == [RateDecision.DROP, RateDecision.SLIP]
    assert rrl.check(ipaddress.IPv4Address("192.0.2.1")) is RateDecision.SEND


def test_token_store_validates_and_expires(tmp_path: Path) -> None:
    clock = Clock()
    w = TokenWriter(tmp_path / "t.db", clock=clock)
    r = TokenReader(tmp_path / "t.db", clock=clock)
    assert not w.record("'; DROP TABLE sightings; --", SRC)
    assert w.record(TOKEN, SRC)
    w.flush()
    assert r.resolvers(TOKEN) == [SRC]
    clock.t += 601
    assert r.resolvers(TOKEN) == []


async def test_real_server_udp_and_tcp(tmp_path: Path) -> None:
    store = TokenWriter(tmp_path / "t.db")
    server = DnsServer(Authority(ZONE, "ns1.example.com", VPS4, None, store.record))
    port = await server.start(["127.0.0.1"], 0)
    try:
        token = secrets.token_hex(16)
        for tcp in (False, True):
            q = DNSRecord.question(f"{token}.{ZONE}")
            r = DNSRecord.parse(
                await asyncio.to_thread(q.send, "127.0.0.1", port, tcp=tcp, timeout=2)
            )
            assert str(r.rr[0].rdata) == str(VPS4)
            q = DNSRecord.question("www.google.com")
            r = DNSRecord.parse(
                await asyncio.to_thread(q.send, "127.0.0.1", port, tcp=tcp, timeout=2)
            )
            assert r.header.rcode == RCODE.REFUSED
        store.flush()
        assert TokenReader(tmp_path / "t.db").resolvers(token)
    finally:
        await server.close()
        store.close()
