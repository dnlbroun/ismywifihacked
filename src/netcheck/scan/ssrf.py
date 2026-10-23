"""Guarded fetch of an SSDP LOCATION (UPnP device description) URL.

The LOCATION header comes from whatever answered on UDP 1900, so it's attacker-
controlled. We only fetch it if the host is an IP literal equal to the scan target,
the target still passes the address policy, and the URL is plain http. No hostnames
(no DNS), no redirects, no proxies, bounded size and time.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from netcheck.addrpolicy import AddressPolicy, RefusedAddress, ScanTarget

MAX_URL_LEN = 512
MAX_BODY_BYTES = 64 * 1024
FETCH_TIMEOUT = 3.0
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/%?-]{0,255}$")


class LocationRejected(Exception):
    pass


@dataclass(frozen=True)
class SafeLocation:
    url: str  # rebuilt from validated parts; never the raw header value
    host_header: str


def validate_location(raw: str, target: ScanTarget, policy: AddressPolicy) -> SafeLocation:
    if len(raw) > MAX_URL_LEN or any(ch.isspace() or ord(ch) < 0x20 for ch in raw):
        raise LocationRejected("malformed")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise LocationRejected("malformed") from None
    if parts.scheme.lower() != "http":
        raise LocationRejected("scheme")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise LocationRejected("userinfo")
    if parts.fragment:
        raise LocationRejected("fragment")
    host = parts.hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise LocationRejected("not an IP literal") from None
    if ip != target.ip:
        raise LocationRejected("off-host")
    try:
        policy.check(ip)
    except RefusedAddress:
        raise LocationRejected("address not allowed") from None
    port = 80 if port is None else port
    if not 0 < port < 65536:
        raise LocationRejected("port")
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    if not _PATH_RE.match(path):
        raise LocationRejected("path")
    host_literal = f"[{ip}]" if ip.version == 6 else str(ip)
    return SafeLocation(
        url=f"http://{host_literal}:{port}{path}", host_header=f"{host_literal}:{port}"
    )


async def fetch_location(
    raw: str,
    target: ScanTarget,
    policy: AddressPolicy,
    *,
    timeout: float = FETCH_TIMEOUT,
    max_bytes: int = MAX_BODY_BYTES,
) -> bytes:
    """Fetch the device description. Raises LocationRejected on any guard failure."""
    loc = validate_location(raw, target, policy)
    try:
        async with asyncio.timeout(timeout):
            async with (
                httpx.AsyncClient(
                    follow_redirects=False,
                    trust_env=False,
                    timeout=timeout,
                    headers={
                        "Host": loc.host_header,
                        "Accept": "text/xml",
                        # Raw bytes only: no decompression, so no zip bombs.
                        "Accept-Encoding": "identity",
                    },
                ) as client,
                client.stream("GET", loc.url) as resp,
            ):
                if resp.status_code != 200:
                    raise LocationRejected(f"status {resp.status_code}")
                if resp.headers.get("content-encoding", "identity").lower() != "identity":
                    raise LocationRejected("encoded body")
                declared = resp.headers.get("content-length")
                if declared is not None and (not declared.isdigit() or int(declared) > max_bytes):
                    raise LocationRejected("too large")
                body = bytearray()
                async for chunk in resp.aiter_raw():
                    body += chunk
                    if len(body) > max_bytes:
                        raise LocationRejected("too large")
                return bytes(body)
    except TimeoutError:
        raise LocationRejected("timeout") from None
    except httpx.HTTPError:
        raise LocationRejected("fetch failed") from None
