"""Local listeners for scanner tests. Everything binds to 127.0.0.1 on ephemeral ports."""

from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

LOCALHOST = "127.0.0.1"


@dataclass
class HttpServer:
    response: Callable[[], bytes]
    delay: float = 0.0
    hits: int = 0
    server: asyncio.Server | None = None
    port: int = 0
    ssl_ctx: ssl.SSLContext | None = None
    requests: list[bytes] = field(default_factory=list)

    async def start(self) -> HttpServer:
        self.server = await asyncio.start_server(self._handle, LOCALHOST, 0, ssl=self.ssl_ctx)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.hits += 1
        try:
            req = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            self.requests.append(req)
            if self.delay:
                await asyncio.sleep(self.delay)
            writer.write(self.response())
            await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    async def close(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


def http_response(body: bytes, *, status: str = "200 OK", headers: dict[str, str] | None = None,
                  content_length: bool = True) -> bytes:  # fmt: skip
    lines = [f"HTTP/1.1 {status}"]
    hdrs = {"Content-Type": "text/xml"} | (headers or {})
    if content_length:
        hdrs["Content-Length"] = str(len(body))
    lines += [f"{k}: {v}" for k, v in hdrs.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


class _UdpResponder(asyncio.DatagramProtocol):
    def __init__(self, reply: Callable[[bytes], bytes | None]) -> None:
        self.reply = reply
        self.received: list[bytes] = []
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | object, ...]) -> None:
        self.received.append(data)
        out = self.reply(data)
        if out is not None and self.transport is not None:
            self.transport.sendto(out, addr)


async def udp_responder(
    reply: Callable[[bytes], bytes | None],
) -> tuple[asyncio.DatagramTransport, _UdpResponder, int]:
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(
        lambda: _UdpResponder(reply), local_addr=(LOCALHOST, 0)
    )
    return transport, proto, transport.get_extra_info("sockname")[1]


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    """A port with nothing listening (bound then released)."""
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind((LOCALHOST, 0))
        port: int = s.getsockname()[1]
        return port


def self_signed_ctx(tmp: Path, common_name: str, org: str) -> ssl.SSLContext:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


DEVICE_XML = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>My Router (secret home name)</friendlyName>
    <manufacturer>ACME Networks</manufacturer>
    <modelName>WR-1000</modelName>
    <modelNumber>v2</modelNumber>
    <serialNumber>SN-SHOULD-NOT-BE-KEPT</serialNumber>
    <UDN>uuid:should-not-be-kept</UDN>
    <firmwareVersion>1.2.3</firmwareVersion>
    <deviceList>
      <device><manufacturer>Embedded Co</manufacturer><modelName>Inner</modelName></device>
    </deviceList>
  </device>
</root>
"""
