"""AbuseIPDB v2 check endpoint (free plan: non-commercial, 1,000 checks/day).

GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=30
    Header: Key: <api key>
  200 -> {"data": {"ipAddress", "abuseConfidenceScore", "totalReports",
                   "numDistinctUsers", "lastReportedAt", "isTor", "isWhitelisted", ...}}

The verdict follows abuseConfidenceScore, which AbuseIPDB recommends acting on, not
the raw report count: well-known services collect hundreds of reports at score 0.

Only a well-formed 200 for the address we asked about counts as an answer; quota
exhaustion (429), auth errors and timeouts all become UNKNOWN.
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

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.abuseipdb.com"
TIMEOUT = 4.0
MAX_AGE_DAYS = 30
MAX_BODY_BYTES = 32 * 1024
SUSPICIOUS_SCORE = 25
_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})T")


class Abuse(enum.Enum):
    NO_REPORTS = "no_reports"  # none, or AbuseIPDB rates them 0/100 confidence
    LOW_CONFIDENCE = "low_confidence"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AbuseResult:
    verdict: Abuse
    score: int = 0
    reports: int = 0
    reporters: int = 0
    last_reported: str | None = None  # YYYY-MM-DD
    is_tor: bool = False
    reason: str | None = None


def _unknown(reason: str) -> AbuseResult:
    return AbuseResult(Abuse.UNKNOWN, reason=reason)


class AbuseIpDbClient:
    def __init__(
        self,
        api_key: SecretStr,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={
                "Accept": "application/json",
                "User-Agent": "netcheck/1",
                "Key": api_key.get_secret_value(),
            },
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def check(self, target: ScanTarget) -> AbuseResult:
        params = {"ipAddress": str(target.ip), "maxAgeInDays": str(MAX_AGE_DAYS)}
        try:
            async with self._client.stream("GET", "/api/v2/check", params=params) as resp:
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_BODY_BYTES:
                        return _unknown("oversize response")
                status = resp.status_code
        except httpx.TimeoutException:
            return _unknown("timeout")
        except httpx.HTTPError as exc:
            log.warning("AbuseIPDB request failed: %s", type(exc).__name__)
            return _unknown("request failed")

        if status == 429:
            log.warning("AbuseIPDB daily quota exhausted")
            return _unknown("rate limited")
        if status in (401, 403):
            log.error("AbuseIPDB rejected the API key (HTTP %d)", status)
            return _unknown("auth failed")
        if status != 200:
            return _unknown(f"http {status}")
        try:
            data = json.loads(body).get("data")
        except (ValueError, AttributeError):
            return _unknown("malformed response")
        if not isinstance(data, dict):
            return _unknown("malformed response")
        return _interpret(data, target)


def _interpret(data: dict[str, object], target: ScanTarget) -> AbuseResult:
    try:
        if ipaddress.ip_address(str(data.get("ipAddress"))) != target.ip:
            return _unknown("response for a different address")
    except ValueError:
        return _unknown("malformed response")
    score, reports = data.get("abuseConfidenceScore"), data.get("totalReports")
    if (
        not isinstance(score, int)
        or isinstance(score, bool)
        or not isinstance(reports, int)
        or isinstance(reports, bool)
        or not 0 <= score <= 100
        or reports < 0
    ):
        return _unknown("malformed response")
    reporters = data.get("numDistinctUsers")
    last = data.get("lastReportedAt")
    m = _DATE_RE.match(last) if isinstance(last, str) else None
    if reports == 0 or score == 0:
        verdict = Abuse.NO_REPORTS
    elif score >= SUSPICIOUS_SCORE:
        verdict = Abuse.SUSPICIOUS
    else:
        verdict = Abuse.LOW_CONFIDENCE
    return AbuseResult(
        verdict,
        score=score,
        reports=reports,
        reporters=reporters if isinstance(reporters, int) and reporters >= 0 else 0,
        last_reported=m.group(1) if m else None,
        is_tor=data.get("isTor") is True,
    )
