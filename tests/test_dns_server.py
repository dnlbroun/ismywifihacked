"""End-to-end: real UDP/TCP sockets on localhost, a real token store, and the web API."""

import asyncio
import ipaddress
import secrets
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from dnslib import QTYPE, RCODE, DNSRecord

from netcheck.dns.server import Authority, DnsServer, ResponseRateLimiter
from netcheck.dns.tokens import TokenReader, TokenWriter
from tests.webharness import build

ZONE = "dns.example.com"
VPS4 = ipaddress.IPv4Address("203.0.113.10")


@dataclass
class Running:
    port: int
    store: TokenWriter
    reader: TokenReader
    server: DnsServer


@pytest.fixture
async def running(tmp_path: Path) -> AsyncIterator[Running]:
    db = tmp_path / "tokens.db"
    store = TokenWriter(db)
    server = DnsServer(
        Authority(ZONE, "ns1.example.com", VPS4, None, store.record),
        rrl=ResponseRateLimiter(rate=5.0, burst=10.0, slip=2),
    )
    port = await server.start(["127.0.0.1"], 0)
    yield Running(port, store, TokenReader(db), server)
    await server.close()
    store.close()


async def query(port: int, name: str, qtype: str = "A", *, tcp: bool = False) -> DNSRecord:
    q = DNSRecord.question(name, qtype)
    raw = await asyncio.to_thread(q.send, "127.0.0.1", port, tcp=tcp, timeout=2)
    return DNSRecord.parse(raw)


@pytest.mark.parametrize("tcp", [False, True])
async def test_token_lookup_end_to_end(running: Running, tcp: bool, tmp_path: Path) -> None:
    token = secrets.token_hex(16)
    h = build(tmp_path / "web")
    h.deps.token_reader = running.reader
    async with h.app.router.lifespan_context(h.app), h.async_client() as client:
        assert (await client.get(f"/api/dns/{token}")).json() == {"seen": False}

        r = await query(running.port, f"{token}.{ZONE}", tcp=tcp)
        assert r.header.rcode == RCODE.NOERROR
        assert r.header.ra == 0
        assert str(r.rr[0].rdata) == str(VPS4)

        running.store.flush()
        assert running.reader.resolvers(token) == [ipaddress.IPv4Address("127.0.0.1")]
        resp = await client.get(f"/api/dns/{token}")
    assert resp.json() == {"seen": True}
    assert resp.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("tcp", [False, True])
async def test_not_an_open_resolver(running: Running, tcp: bool) -> None:
    r = await query(running.port, "www.google.com", tcp=tcp)
    assert r.header.rcode == RCODE.REFUSED
    assert r.header.ra == 0
    assert not r.rr


@pytest.mark.parametrize("tcp", [False, True])
async def test_any_refused(running: Running, tcp: bool) -> None:
    r = await query(running.port, ZONE, "ANY", tcp=tcp)
    assert r.header.rcode == RCODE.REFUSED


def test_api_rejects_bad_token(tmp_path: Path) -> None:
    h = build(tmp_path)
    with h.client() as client:
        for bad in ["abc", "0123456789ABCDEF0123456789ABCDEF", "..%2F..%2Fetc%2Fpasswd"]:
            assert client.get(f"/api/dns/{bad}").status_code == 404


async def test_udp_rate_limit(running: Running) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    q = DNSRecord.question("www.google.com").pack()
    for _ in range(40):
        await loop.sock_sendto(sock, q, ("127.0.0.1", running.port))
    replies: list[DNSRecord] = []
    try:
        while True:
            async with asyncio.timeout(0.5):
                replies.append(DNSRecord.parse(await loop.sock_recv(sock, 4096)))
    except TimeoutError:
        pass
    finally:
        sock.close()
    full = [r for r in replies if not r.header.tc]
    slipped = [r for r in replies if r.header.tc]
    assert len(full) <= 11  # burst + a little refill
    assert 10 <= len(slipped) <= 16  # about half the excess, so resolvers can retry on TCP
    assert len(replies) < 40


async def test_tcp_rejects_oversized_and_idle(running: Running) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", running.port)
    writer.write((4000).to_bytes(2, "big") + b"x" * 10)
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 2) == b""
    writer.close()


async def test_soa_over_tcp(running: Running) -> None:
    r = await query(running.port, ZONE, "SOA", tcp=True)
    assert r.rr[0].rtype == QTYPE.SOA
