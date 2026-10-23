from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from netcheck.addrpolicy import AddressPolicy, ScanTarget
from netcheck.reputation.internetdb import History, InternetDbClient

BASE = "https://idb.test"
IP = "24.0.1.2"
URL = f"{BASE}/{IP}"


@pytest.fixture
def target() -> ScanTarget:
    return AddressPolicy([]).check(IP)


@pytest.fixture
async def client() -> AsyncIterator[InternetDbClient]:
    c = InternetDbClient(base_url=BASE, timeout=0.5)
    yield c
    await c.aclose()


@respx.mock
async def test_no_information_is_nothing_seen(client: InternetDbClient, target: ScanTarget) -> None:
    respx.get(URL).respond(404, json={"detail": "No information available"})
    assert (await client.check(target)).verdict is History.NOTHING_SEEN


@respx.mock
async def test_seen_ports_and_vulns_cleaned(client: InternetDbClient, target: ScanTarget) -> None:
    respx.get(URL).respond(
        200,
        json={
            "ip": IP,
            "ports": [8080, 80, 80, "x", -1, 70000],
            "vulns": ["CVE-2021-44228", "<script>", "CVE-2019-0708"],
            "tags": ["self-signed", "Bad Tag!"],
            "cpes": [],
            "hostnames": ["secret-home.example"],
        },
    )
    r = await client.check(target)
    assert r.verdict is History.SEEN
    assert r.ports == [80, 8080]
    assert r.vulns == ["CVE-2019-0708", "CVE-2021-44228"]
    assert r.tags == ["self-signed"]


@respx.mock
async def test_empty_lists_is_nothing_seen(client: InternetDbClient, target: ScanTarget) -> None:
    respx.get(URL).respond(200, json={"ip": IP, "ports": [], "vulns": [], "tags": []})
    assert (await client.check(target)).verdict is History.NOTHING_SEEN


@pytest.mark.parametrize(
    ("status", "kwargs", "reason"),
    [
        (429, {"json": {"detail": "slow down"}}, "http 429"),
        (500, {"text": "x"}, "http 500"),
        (404, {"json": {"detail": "something else"}}, "malformed response"),
        (404, {"text": "<html>"}, "malformed response"),
        (200, {"json": {"ip": "1.1.1.1", "ports": [], "vulns": [], "tags": []}}, "response for a different address"),
        (200, {"json": {"ip": IP, "ports": "80"}}, "malformed response"),
        (200, {"content": b"[" + b" " * 70_000 + b"]"}, "oversize response"),
    ],
)  # fmt: skip
@respx.mock
async def test_failures_are_unknown(
    client: InternetDbClient,
    target: ScanTarget,
    status: int,
    kwargs: dict[str, object],
    reason: str,
) -> None:
    respx.get(URL).respond(status, **kwargs)  # type: ignore[arg-type]
    r = await client.check(target)
    assert r.verdict is History.UNKNOWN
    assert r.reason == reason


@respx.mock
async def test_timeout_is_unknown(client: InternetDbClient, target: ScanTarget) -> None:
    respx.get(URL).mock(side_effect=httpx.ReadTimeout)
    assert (await client.check(target)).verdict is History.UNKNOWN


async def test_ipv6_is_unknown(client: InternetDbClient) -> None:
    r = await client.check(AddressPolicy([]).check("2001:558::1"))
    assert r.verdict is History.UNKNOWN
