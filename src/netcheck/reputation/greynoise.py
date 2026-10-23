"""GreyNoise Community API client (free tier, IPv4 only).

GET https://api.greynoise.io/v3/community/{ip}
  200 -> {"ip", "noise", "riot", "classification", "name", "link", "last_seen", "message"}
  404 -> IP not observed scanning the internet and not a known business service

Only an explicit 404 "not observed" or a well-formed 200 counts as an answer. Any
other status, timeout, oversize or malformed body becomes UNKNOWN ("couldn't check").
"""

from __future__ import annotations

import enum
import ipaddress
import json
import logging
import re
from dataclasses import dataclass

import httpx
from pydantic import SecretStr

from netcheck.addrpolicy import ScanTarget
from netcheck.scan.models import clean_text

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.greynoise.io"
TIMEOUT = 4.0
MAX_BODY_BYTES = 16 * 1024
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_LINK_PREFIX = "https://viz.greynoise.io/"


class Reputation(enum.Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    BUSINESS_OR_VPN = "business_or_vpn"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReputationResult:
    verdict: Reputation
    classification: str | None = None  # "malicious" / "benign" / "unknown" as reported
    name: str | None = None  # actor or organisation name, if GreyNoise has one
    last_seen: str | None = None
    link: str | None = None
    reason: str | None = None  # why we couldn't check


def _unknown(reason: str) -> ReputationResult:
    return ReputationResult(Reputation.UNKNOWN, reason=reason)


class GreyNoiseClient:
    def __init__(
        self,
        api_key: SecretStr | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        headers = {"Accept": "application/json", "User-Agent": "netcheck/1"}
        if api_key is not None:
            headers["key"] = api_key.get_secret_value()
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def check(self, target: ScanTarget) -> ReputationResult:
        if target.version != 4:
            return _unknown("ipv6_unsupported")
        try:
            async with self._client.stream("GET", f"/v3/community/{target.ip}") as resp:
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_BODY_BYTES:
                        return _unknown("oversize response")
                status = resp.status_code
        except httpx.TimeoutException:
            return _unknown("timeout")
        except httpx.HTTPError as exc:
            log.warning("GreyNoise request failed: %s", type(exc).__name__)
            return _unknown("request failed")

        if status == 429:
            return _unknown("rate limited")
        if status not in (200, 404):
            return _unknown(f"http {status}")
        try:
            data = json.loads(body)
        except ValueError:
            return _unknown("malformed response")
        if not isinstance(data, dict):
            return _unknown("malformed response")
        return _interpret(status, data, target)


def _interpret(status: int, data: dict[str, object], target: ScanTarget) -> ReputationResult:
    try:
        if ipaddress.ip_address(str(data.get("ip"))) != target.ip:
            return _unknown("response for a different address")
    except ValueError:
        return _unknown("malformed response")

    noise, riot = data.get("noise"), data.get("riot")
    if not isinstance(noise, bool) or not isinstance(riot, bool):
        return _unknown("malformed response")

    if status == 404:
        # The documented "not observed" answer; anything else at 404 is suspect.
        if noise or riot:
            return _unknown("malformed response")
        return ReputationResult(Reputation.CLEAN)

    raw_class, raw_name = data.get("classification"), data.get("name")
    raw_seen, raw_link = data.get("last_seen"), data.get("link")
    classification = raw_class if raw_class in ("benign", "malicious", "unknown") else None

    def details(verdict: Reputation) -> ReputationResult:
        return ReputationResult(
            verdict,
            classification=str(classification) if classification else None,
            name=clean_text(raw_name) if isinstance(raw_name, str) else None,
            last_seen=raw_seen if isinstance(raw_seen, str) and _DATE_RE.match(raw_seen) else None,
            link=(
                raw_link
                if isinstance(raw_link, str)
                and raw_link.startswith(_LINK_PREFIX)
                and len(raw_link) < 200
                else None
            ),
        )

    if noise and classification != "benign":
        return details(Reputation.SUSPICIOUS)
    if riot or (noise and classification == "benign"):
        return details(Reputation.BUSINESS_OR_VPN)
    return details(Reputation.CLEAN)
