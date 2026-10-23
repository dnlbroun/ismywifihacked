"""Minimal authoritative DNS server for the dns.<DOMAIN> zone.

What it answers:
  <token>.dns.<DOMAIN>  A/AAAA -> the VPS address (TTL 0), and records token -> resolver
  dns.<DOMAIN>          SOA / NS
  anything else in zone NXDOMAIN (or NODATA for a valid token with another qtype)
  anything out of zone  REFUSED
  ANY                   REFUSED

It never recurses and never sets RA, so it can't be used as an open resolver. Every
response is small and fixed-shape, and UDP responses are rate-limited per source
prefix (with "slip": every Nth limited query gets a tiny TC=1 reply so real resolvers
retry over TCP), so it isn't useful as a reflection/amplification source.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from dnslib import (
    AAAA,
    CLASS,
    EDNS0,
    NS,
    OPCODE,
    QTYPE,
    RCODE,
    RR,
    SOA,
    A,
    DNSHeader,
    DNSLabel,
    DNSRecord,
)

from netcheck.addrpolicy import IPAddress
from netcheck.dns.tokens import is_valid_token

log = logging.getLogger(__name__)

MAX_QUERY_BYTES = 512  # our queries are tiny; anything larger is not for us
EDNS_UDP_SIZE = 1232
SOA_TTL = 60
NEGATIVE_TTL = 0

TokenSink = Callable[[str, IPAddress], object]


class Authority:
    def __init__(
        self,
        zone: str,
        ns_host: str,
        ipv4: ipaddress.IPv4Address,
        ipv6: ipaddress.IPv6Address | None,
        on_token: TokenSink,
    ) -> None:
        self._zone = DNSLabel(zone.lower())
        self._zone_labels = tuple(lbl.lower() for lbl in self._zone.label)
        self._ns = DNSLabel(ns_host.lower())
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        self._on_token = on_token
        self._soa = SOA(
            mname=self._ns,
            rname=DNSLabel(f"hostmaster.{zone.split('.', 1)[1]}"),
            times=(1, 3600, 600, 86400, NEGATIVE_TTL),
        )

    def handle(self, data: bytes, src: IPAddress, *, truncate: bool = False) -> bytes | None:
        """Build the response for one query, or None to drop it silently."""
        if len(data) > MAX_QUERY_BYTES:
            return None
        try:
            req = DNSRecord.parse(data)
        except Exception:  # malformed input of any kind is dropped
            return None
        if req.header.qr:  # a response, not a query: never answer (reflection loops)
            return None

        resp = self._skeleton(req)
        if req.header.opcode != OPCODE.QUERY:
            resp.header.rcode = RCODE.NOTIMP
            return _pack(resp)
        if len(req.questions) != 1 or req.rr or req.auth:
            resp.header.rcode = RCODE.FORMERR
            return _pack(resp)
        if truncate:
            resp.header.tc = 1
            return _pack(resp)

        q = req.questions[0]
        labels = tuple(lbl.lower() for lbl in q.qname.label)
        if q.qclass != CLASS.IN or not self._in_zone(labels) or q.qtype == QTYPE.ANY:
            resp.header.rcode = RCODE.REFUSED
            return _pack(resp)

        resp.header.aa = 1
        sub = labels[: len(labels) - len(self._zone_labels)]
        if not sub:
            self._answer_apex(resp, q.qname, q.qtype)
        elif len(sub) == 1 and is_valid_token(token := sub[0].decode("ascii", "replace")):
            self._on_token(token, src)
            self._answer_token(resp, q.qname, q.qtype)
        else:
            resp.header.rcode = RCODE.NXDOMAIN
            resp.add_auth(RR(self._zone, QTYPE.SOA, rdata=self._soa, ttl=SOA_TTL))
        return _pack(resp)

    def _skeleton(self, req: DNSRecord) -> DNSRecord:
        # Built by hand rather than req.reply(): that copies the request's whole flag
        # bitmap and sets RA, which an authoritative-only server must never do.
        hdr = DNSHeader(id=req.header.id, qr=1, opcode=req.header.opcode, rd=req.header.rd, ra=0)
        resp = DNSRecord(hdr, questions=req.questions[:1])
        if any(rr.rtype == QTYPE.OPT for rr in req.ar):
            resp.add_ar(EDNS0(udp_len=EDNS_UDP_SIZE))
        return resp

    def _in_zone(self, labels: tuple[bytes, ...]) -> bool:
        n = len(self._zone_labels)
        return len(labels) >= n and labels[-n:] == self._zone_labels

    def _answer_apex(self, resp: DNSRecord, qname: DNSLabel, qtype: int) -> None:
        if qtype == QTYPE.SOA:
            resp.add_answer(RR(qname, QTYPE.SOA, rdata=self._soa, ttl=SOA_TTL))
        elif qtype == QTYPE.NS:
            resp.add_answer(RR(qname, QTYPE.NS, rdata=NS(self._ns), ttl=SOA_TTL))
        else:
            resp.add_auth(RR(self._zone, QTYPE.SOA, rdata=self._soa, ttl=SOA_TTL))

    def _answer_token(self, resp: DNSRecord, qname: DNSLabel, qtype: int) -> None:
        if qtype == QTYPE.A:
            resp.add_answer(RR(qname, QTYPE.A, rdata=A(str(self._ipv4)), ttl=0))
        elif qtype == QTYPE.AAAA and self._ipv6 is not None:
            resp.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(str(self._ipv6)), ttl=0))
        else:
            resp.add_auth(RR(self._zone, QTYPE.SOA, rdata=self._soa, ttl=SOA_TTL))


def _pack(record: DNSRecord) -> bytes:
    return bytes(record.pack())


class RateDecision(Enum):
    SEND = "send"
    SLIP = "slip"
    DROP = "drop"


@dataclass
class _Bucket:
    tokens: float
    updated: float
    limited: int = 0


@dataclass
class ResponseRateLimiter:
    """Token bucket per source prefix (/24 for IPv4, /56 for IPv6)."""

    rate: float = 20.0
    burst: float = 40.0
    slip: int = 2
    max_entries: int = 100_000
    clock: Callable[[], float] = time.monotonic
    _buckets: dict[str, _Bucket] = field(default_factory=dict)

    @staticmethod
    def key(src: IPAddress) -> str:
        prefix = 24 if src.version == 4 else 56
        return str(ipaddress.ip_network(f"{src}/{prefix}", strict=False))

    def check(self, src: IPAddress) -> RateDecision:
        now = self.clock()
        k = self.key(src)
        b = self._buckets.get(k)
        if b is None:
            if len(self._buckets) >= self.max_entries:
                self.sweep()
                if len(self._buckets) >= self.max_entries:
                    return RateDecision.DROP
            b = self._buckets[k] = _Bucket(tokens=self.burst, updated=now)
        b.tokens = min(self.burst, b.tokens + (now - b.updated) * self.rate)
        b.updated = now
        if b.tokens >= 1.0:
            b.tokens -= 1.0
            return RateDecision.SEND
        b.limited += 1
        if self.slip and b.limited % self.slip == 0:
            return RateDecision.SLIP
        return RateDecision.DROP

    def sweep(self) -> None:
        """Forget sources whose bucket has fully refilled."""
        now = self.clock()
        full_after = self.burst / self.rate
        for k in [k for k, b in self._buckets.items() if now - b.updated >= full_after]:
            del self._buckets[k]

    def __len__(self) -> int:
        return len(self._buckets)


def _source_ip(host: str) -> IPAddress | None:
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, authority: Authority, rrl: ResponseRateLimiter) -> None:
        self._authority = authority
        self._rrl = rrl
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)  # noqa: S101
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | object, ...]) -> None:
        src = _source_ip(str(addr[0]))
        if src is None or self._transport is None:
            return
        decision = self._rrl.check(src)
        if decision is RateDecision.DROP:
            return
        resp = self._authority.handle(data, src, truncate=decision is RateDecision.SLIP)
        if resp is not None:
            self._transport.sendto(resp, addr)


@dataclass
class DnsServer:
    authority: Authority
    rrl: ResponseRateLimiter = field(default_factory=ResponseRateLimiter)
    tcp_max_connections: int = 64
    tcp_idle_timeout: float = 5.0
    tcp_max_queries: int = 16
    _transports: list[asyncio.DatagramTransport] = field(default_factory=list)
    _servers: list[asyncio.Server] = field(default_factory=list)
    _tcp_active: int = 0

    async def start(self, hosts: list[str], port: int) -> int:
        """Bind UDP+TCP on each host. Returns the port (useful when port=0 in tests)."""
        loop = asyncio.get_running_loop()
        for host in hosts:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port))
            port = sock.getsockname()[1]
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpProtocol(self.authority, self.rrl), sock=sock
            )
            self._transports.append(transport)
            server = await asyncio.start_server(
                self._handle_tcp, host=host, port=port, family=family, reuse_address=True
            )
            self._servers.append(server)
            log.info("DNS listening on %s port %d (udp+tcp)", host, port)
        return port

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        src = _source_ip(str(peer[0])) if peer else None
        if src is None or self._tcp_active >= self.tcp_max_connections:
            writer.close()
            return
        self._tcp_active += 1
        try:
            for _ in range(self.tcp_max_queries):
                async with asyncio.timeout(self.tcp_idle_timeout):
                    length = int.from_bytes(await reader.readexactly(2), "big")
                    if not 0 < length <= MAX_QUERY_BYTES:
                        return
                    data = await reader.readexactly(length)
                resp = self.authority.handle(data, src)
                if resp is None:
                    return
                writer.write(len(resp).to_bytes(2, "big") + resp)
                await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self._tcp_active -= 1
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def close(self) -> None:
        for t in self._transports:
            t.close()
        for s in self._servers:
            s.close()
            await s.wait_closed()
