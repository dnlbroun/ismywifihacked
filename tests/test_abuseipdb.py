from collections.abc import AsyncIterator

import httpx
import pytest
import respx
from pydantic import SecretStr

from netcheck.addrpolicy import AddressPolicy, ScanTarget
from netcheck.reputation.abuseipdb import Abuse, AbuseIpDbClient

BASE = "https://abuse.test"
IP = "24.0.1.2"
URL = f"{BASE}/api/v2/check"


@pytest.fixture
def target() -> ScanTarget:
    return AddressPolicy([]).check(IP)


@pytest.fixture
async def client() -> AsyncIterator[AbuseIpDbClient]:
    c = AbuseIpDbClient(SecretStr("k3y"), base_url=BASE, timeout=0.5)
    yield c
    await c.aclose()


def data(**kw: object) -> dict[str, object]:
    return {
        "data": {
            "ipAddress": IP,
            "isPublic": True,
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None,
            "isTor": False,
            "isWhitelisted": False,
        }
        | kw
    }


@respx.mock
async def test_request_shape(client: AbuseIpDbClient, target: ScanTarget) -> None:
    route = respx.get(URL).respond(200, json=data())
    await client.check(target)
    req = route.calls.last.request
    assert req.headers["key"] == "k3y"
    assert req.url.params["ipAddress"] == IP
    assert req.url.params["maxAgeInDays"] == "30"


@pytest.mark.parametrize(
    ("kw", "verdict"),
    [
        ({}, Abuse.NO_REPORTS),
        ({"totalReports": 2, "numDistinctUsers": 1, "abuseConfidenceScore": 5}, Abuse.LOW_CONFIDENCE),
        # Real-world case (1.1.1.1): many reports, but rated 0 -> not a problem.
        ({"totalReports": 102, "numDistinctUsers": 36, "abuseConfidenceScore": 0}, Abuse.NO_REPORTS),
        ({"totalReports": 40, "numDistinctUsers": 12, "abuseConfidenceScore": 100}, Abuse.SUSPICIOUS),
        ({"totalReports": 3, "abuseConfidenceScore": 25}, Abuse.SUSPICIOUS),
    ],
)  # fmt: skip
@respx.mock
async def test_verdicts(
    client: AbuseIpDbClient, target: ScanTarget, kw: dict[str, object], verdict: Abuse
) -> None:
    respx.get(URL).respond(200, json=data(lastReportedAt="2026-10-20T11:22:33+00:00", **kw))
    r = await client.check(target)
    assert r.verdict is verdict
    assert r.last_reported == "2026-10-20"


@pytest.mark.parametrize(
    ("status", "kwargs", "reason"),
    [
        (429, {"json": {"errors": []}}, "rate limited"),
        (401, {"json": {"errors": []}}, "auth failed"),
        (403, {}, "auth failed"),
        (500, {"text": "x"}, "http 500"),
        (302, {"headers": {"Location": "https://evil.test"}}, "http 302"),
        (200, {"text": "nope"}, "malformed response"),
        (200, {"json": []}, "malformed response"),
        (200, {"json": {"data": []}}, "malformed response"),
        (200, {"json": data(ipAddress="1.1.1.1")}, "response for a different address"),
        (200, {"json": data(abuseConfidenceScore="100")}, "malformed response"),
        (200, {"json": data(abuseConfidenceScore=101)}, "malformed response"),
        (200, {"json": data(totalReports=True)}, "malformed response"),
        (200, {"content": b"{" + b" " * 40_000 + b"}"}, "oversize response"),
    ],
)
@respx.mock
async def test_failures_are_unknown(
    client: AbuseIpDbClient,
    target: ScanTarget,
    status: int,
    kwargs: dict[str, object],
    reason: str,
) -> None:
    respx.get(URL).respond(status, **kwargs)  # type: ignore[arg-type]
    r = await client.check(target)
    assert r.verdict is Abuse.UNKNOWN
    assert r.reason == reason


@respx.mock
async def test_timeout_is_unknown(client: AbuseIpDbClient, target: ScanTarget) -> None:
    respx.get(URL).mock(side_effect=httpx.ConnectTimeout)
    assert (await client.check(target)).verdict is Abuse.UNKNOWN


@respx.mock
async def test_ipv6_supported(client: AbuseIpDbClient) -> None:
    v6 = "2001:558::1"
    respx.get(URL).respond(200, json=data(ipAddress=v6))
    r = await client.check(AddressPolicy([]).check(v6))
    assert r.verdict is Abuse.NO_REPORTS
