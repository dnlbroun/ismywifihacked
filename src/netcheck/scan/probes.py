"""Individual network probes against a ScanTarget.

All probes take a ScanTarget (which only AddressPolicy can create) and talk to
exactly that address. Everything read back is passed through clean_text().
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ssl
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import NameOID
from dnslib import QTYPE, RCODE, DNSRecord

from netcheck.addrpolicy import ScanTarget
from netcheck.scan.models import (
    DnsResolverResult,
    NatPmpResult,
    PortResult,
    PortState,
    clean_text,
)

USER_AGENT = "netcheck/1 (security self-check requested by this IP's user)"
MAX_HEADER_BYTES = 8 * 1024
MAX_UDP_BYTES = 2048

_REACHABLE_ERRNOS = {errno.ECONNREFUSED}


async def tcp_connect(
    target: ScanTarget, port: int, timeout: float
) -> tuple[PortResult, tuple[asyncio.StreamReader, asyncio.StreamWriter] | None]:
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(str(target.ip), port)
    except TimeoutError:
        return PortResult(port, PortState.FILTERED), None
    except OSError as exc:
        state = PortState.CLOSED if exc.errno in _REACHABLE_ERRNOS else PortState.FILTERED
        return PortResult(port, state), None
    return PortResult(port, PortState.OPEN), (reader, writer)


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(Exception):
        async with asyncio.timeout(1):
            await writer.wait_closed()


def _http_head(target: ScanTarget, port: int) -> bytes:
    host = f"[{target.ip}]" if target.version == 6 else str(target.ip)
    return (
        f"HEAD / HTTP/1.0\r\nHost: {host}:{port}\r\nUser-Agent: {USER_AGENT}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


async def _read_server_header(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, request: bytes
) -> str | None:
    writer.write(request)
    await writer.drain()
    data = b""
    while b"\r\n\r\n" not in data and len(data) < MAX_HEADER_BYTES:
        chunk = await reader.read(MAX_HEADER_BYTES - len(data))
        if not chunk:
            break
        data += chunk
    head = data.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if sep and name.strip().lower() == b"server":
            return clean_text(value)
    return None


async def http_server_header(target: ScanTarget, port: int, timeout: float) -> str | None:
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(str(target.ip), port)
            try:
                return await _read_server_header(reader, writer, _http_head(target, port))
            finally:
                await close_writer(writer)
    except (TimeoutError, OSError):
        return None


def _fingerprint_tls_context() -> ssl.SSLContext:
    # Fingerprinting only: we read the certificate the device presents, we don't
    # trust it or send anything sensitive. Old routers speak old TLS, so allow it.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


def _name_summary(name: x509.Name) -> str | None:
    parts: list[str] = []
    for oid, label in ((NameOID.COMMON_NAME, "CN"), (NameOID.ORGANIZATION_NAME, "O")):
        for attr in name.get_attributes_for_oid(oid)[:1]:
            value = attr.value if isinstance(attr.value, str) else attr.value.decode("latin-1")
            parts.append(f"{label}={value}")
    return clean_text(", ".join(parts)) if parts else None


@dataclass
class TlsInfo:
    subject: str | None
    issuer: str | None
    server_header: str | None


async def tls_info(target: ScanTarget, port: int, timeout: float) -> TlsInfo | None:
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(
                str(target.ip), port, ssl=_fingerprint_tls_context(), server_hostname=None
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
                subject = issuer = None
                if der:
                    try:
                        cert = x509.load_der_x509_certificate(der)
                        subject, issuer = _name_summary(cert.subject), _name_summary(cert.issuer)
                    except ValueError:
                        pass
                server = await _read_server_header(reader, writer, _http_head(target, port))
                return TlsInfo(subject, issuer, server)
            finally:
                await close_writer(writer)
    except (TimeoutError, OSError, ssl.SSLError):
        return None


class _UdpCollector(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.replies: list[bytes] = []
        self.unreachable = False
        self.got_reply = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple[str | object, ...]) -> None:
        # The socket is connected to the target, so the kernel only delivers
        # datagrams from that address and port.
        if len(self.replies) < 8:
            self.replies.append(data[:MAX_UDP_BYTES])
        self.got_reply.set()

    def error_received(self, exc: Exception) -> None:
        # ICMP port unreachable: the host answered, nothing on that port.
        if isinstance(exc, ConnectionRefusedError):
            self.unreachable = True


@dataclass
class UdpExchange:
    replies: list[bytes]
    unreachable: bool


async def udp_exchange(
    target: ScanTarget, port: int, payload: bytes, timeout: float, *, linger: float = 0.3
) -> UdpExchange:
    loop = asyncio.get_running_loop()
    try:
        transport, proto = await loop.create_datagram_endpoint(
            _UdpCollector, remote_addr=(str(target.ip), port)
        )
    except OSError:
        return UdpExchange([], False)
    try:
        transport.sendto(payload)
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(timeout):
                await proto.got_reply.wait()
            # Give a device a moment to send any further replies.
            await asyncio.sleep(linger)
        return UdpExchange(list(proto.replies), proto.unreachable)
    finally:
        transport.close()


def ssdp_msearch(target: ScanTarget, port: int) -> bytes:
    host = f"[{target.ip}]" if target.version == 6 else str(target.ip)
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host}:{port}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: upnp:rootdevice\r\n"
        f"USER-AGENT: {USER_AGENT}\r\n\r\n"
    ).encode("ascii")


def parse_ssdp_headers(reply: bytes) -> dict[str, str]:
    lines = reply.split(b"\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:30]:
        name, sep, value = line.partition(b":")
        if sep:
            key = name.strip().lower().decode("ascii", "replace")
            headers.setdefault(key, value.strip().decode("latin-1"))
    return headers


async def natpmp_probe(target: ScanTarget, port: int, timeout: float) -> tuple[NatPmpResult, bool]:
    """Returns (result, host_answered_somehow)."""
    # NAT-PMP v0 "external address" request. A PCP server answers this too (with
    # UNSUPP_VERSION), which is equally a sign the port-mapping service is exposed.
    ex = await udp_exchange(target, port, b"\x00\x00", timeout, linger=0)
    # Responses have the high bit set in the opcode byte; version 0 = NAT-PMP, 2 = PCP.
    responded = any(len(r) >= 4 and r[0] in (0, 2) and r[1] & 0x80 for r in ex.replies)
    return NatPmpResult(responded=responded), bool(ex.replies) or ex.unreachable


async def dns_resolver_probe(
    target: ScanTarget, port: int, qname: str, timeout: float
) -> tuple[DnsResolverResult, bool]:
    """Ask the target to resolve one of our own names. Returns (result, host_answered).

    `qname` is a fresh name under our zone, so an open resolver has to come to our
    authoritative server to answer it, and a cached or forged answer is impossible.
    """
    query = DNSRecord.question(qname, "A")
    query.header.rd = 1
    ex = await udp_exchange(target, port, query.pack(), timeout, linger=0)
    result = DnsResolverResult()
    for raw in ex.replies:
        try:
            reply = DNSRecord.parse(raw)
        except Exception:  # noqa: S112 - not DNS: something else is on port 53
            continue
        if reply.header.id != query.header.id or not reply.header.qr:
            continue
        result.responded = True
        if reply.header.rcode == RCODE.NOERROR and any(rr.rtype == QTYPE.A for rr in reply.rr):
            result.recursion = True
    return result, bool(ex.replies) or ex.unreachable
