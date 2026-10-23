"""Shodan InternetDB client (free for non-commercial use, no key, IPv4).

GET https://internetdb.shodan.io/{ip}
  200 -> {"ip", "ports": [int], "vulns": ["CVE-..."], "tags": [str], "cpes", "hostnames"}
  404 -> {"detail": "No information available"}

Shodan's data is collected weekly, so it shows what was open recently, including
ports outside our own list. Failures become UNKNOWN, never "nothing seen".
"""

from __future__ import annotations

import enum
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field

import httpx

from netcheck.addrpolicy import ScanTarget

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://internetdb.shodan.io"
TIMEOUT = 4.0
MAX_BODY_BYTES = 64 * 1024
MAX_ITEMS = 50
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_TAG_RE = re.compile(r"^[a-z0-9-]{1,32}$")


class History(enum.Enum):
    NOTHING_SEEN = "nothing_seen"
    SEEN = "seen"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class HistoryResult:
    verdict: History
    ports: list[int] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    reason: str | None = None


def _unknown(reason: str) -> HistoryResult:
    return HistoryResult(History.UNKNOWN, reason=reason)


class InternetDbClient:
    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Accept": "application/json", "User-Agent": "netcheck/1"},
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def check(self, target: ScanTarget) -> HistoryResult:
        if target.version != 4:
            return _unknown("ipv6_unsupported")
        try:
            async with self._client.stream("GET", f"/{target.ip}") as resp:
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_BODY_BYTES:
                        return _unknown("oversize response")
                status = resp.status_code
        except httpx.TimeoutException:
            return _unknown("timeout")
        except httpx.HTTPError as exc:
            log.warning("InternetDB request failed: %s", type(exc).__name__)
            return _unknown("request failed")

        if status not in (200, 404):
            return _unknown(f"http {status}")
        try:
            data = json.loads(body)
        except ValueError:
            return _unknown("malformed response")
        if not isinstance(data, dict):
            return _unknown("malformed response")
        if status == 404:
            # Only the documented "no information" answer counts as nothing seen.
            if str(data.get("detail", "")).startswith("No information"):
                return HistoryResult(History.NOTHING_SEEN)
            return _unknown("malformed response")
        return _interpret(data, target)


def _interpret(data: dict[str, object], target: ScanTarget) -> HistoryResult:
    try:
        if ipaddress.ip_address(str(data.get("ip"))) != target.ip:
            return _unknown("response for a different address")
    except ValueError:
        return _unknown("malformed response")
    ports, vulns, tags = data.get("ports"), data.get("vulns"), data.get("tags")
    if not isinstance(ports, list) or not isinstance(vulns, list) or not isinstance(tags, list):
        return _unknown("malformed response")
    clean_ports = sorted({p for p in ports if isinstance(p, int) and 0 < p < 65536})[:MAX_ITEMS]
    clean_vulns = sorted({v for v in vulns if isinstance(v, str) and _CVE_RE.match(v)})[:MAX_ITEMS]
    clean_tags = sorted({t for t in tags if isinstance(t, str) and _TAG_RE.match(t)})[:MAX_ITEMS]
    if not clean_ports and not clean_vulns:
        return HistoryResult(History.NOTHING_SEEN, tags=clean_tags)
    return HistoryResult(History.SEEN, ports=clean_ports, vulns=clean_vulns, tags=clean_tags)
