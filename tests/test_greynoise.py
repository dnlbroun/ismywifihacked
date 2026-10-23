from collections.abc import AsyncIterator

import httpx
import pytest
import respx
from pydantic import SecretStr

from netcheck.addrpolicy import AddressPolicy, ScanTarget
from netcheck.reputation.greynoise import GreyNoiseClient, Reputation

BASE = "https://gn.test"
IP = "24.0.1.2"
URL = f"{BASE}/v3/community/{IP}"
NOT_OBSERVED = {
    "ip": IP,
    "noise": False,
    "riot": False,
    "message": "IP not observed scanning the internet or contained in RIOT data set.",
}


@pytest.fixture
def target() -> ScanTarget:
    return AddressPolicy([]).check(IP)


@pytest.fixture
async def client() -> AsyncIterator[GreyNoiseClient]:
    c = GreyNoiseClient(SecretStr("k3y"), base_url=BASE, timeout=0.5)
    yield c
    await c.aclose()


def observed(**kw: object) -> dict[str, object]:
    return {
        "ip": IP,
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "unknown",
        "link": f"https://viz.greynoise.io/ip/{IP}",
        "last_seen": "2026-10-20",
        "message": "Success",
    } | kw


@respx.mock
async def test_not_observed_is_clean(client: GreyNoiseClient, target: ScanTarget) -> None:
    route = respx.get(URL).respond(404, json=NOT_OBSERVED)
    res = await client.check(target)
    assert res.verdict is Reputation.CLEAN
    assert route.calls.last.request.headers["key"] == "k3y"


@respx.mock
async def test_malicious_noise_is_suspicious(client: GreyNoiseClient, target: ScanTarget) -> None:
    respx.get(URL).respond(200, json=observed(name="Mirai <b>"))
    res = await client.check(target)
    assert res.verdict is Reputation.SUSPICIOUS
    assert res.classification == "malicious"
    assert res.name == "Mirai <b>"  # escaping happens in the template
    assert res.last_seen == "2026-10-20"
    assert res.link == f"https://viz.greynoise.io/ip/{IP}"


@respx.mock
async def test_unknown_noise_is_suspicious(client: GreyNoiseClient, target: ScanTarget) -> None:
    respx.get(URL).respond(200, json=observed(classification="unknown"))
    assert (await client.check(target)).verdict is Reputation.SUSPICIOUS


@pytest.mark.parametrize(
    "payload",
    [
        observed(noise=False, riot=True, classification="benign", name="Acme Corp"),
        observed(classification="benign", name="Shodan.io"),
    ],
)
@respx.mock
async def test_business(
    client: GreyNoiseClient, target: ScanTarget, payload: dict[str, object]
) -> None:
    respx.get(URL).respond(200, json=payload)
    assert (await client.check(target)).verdict is Reputation.BUSINESS_OR_VPN


@respx.mock
async def test_untrusted_fields_sanitised(client: GreyNoiseClient, target: ScanTarget) -> None:
    respx.get(URL).respond(
        200,
        json=observed(
            classification="evil", link="javascript:alert(1)", last_seen="<img>", name="x" * 500
        ),
    )
    res = await client.check(target)
    assert res.classification is None
    assert res.link is None
    assert res.last_seen is None
    assert res.name == "x" * 128


@pytest.mark.parametrize(
    ("status", "kwargs", "reason"),
    [
        (429, {"json": {"message": "rate limit"}}, "rate limited"),
        (500, {"text": "oops"}, "http 500"),
        (503, {}, "http 503"),
        (401, {"json": {"message": "bad key"}}, "http 401"),
        (400, {"json": {"message": "invalid ip"}}, "http 400"),
        (301, {"headers": {"Location": "https://evil.test/"}}, "http 301"),
        (200, {"text": "not json"}, "malformed response"),
        (200, {"json": ["a", "list"]}, "malformed response"),
        (200, {"json": {"ip": IP}}, "malformed response"),  # missing noise/riot
        (200, {"json": observed(noise="yes")}, "malformed response"),
        (200, {"json": observed(ip="1.1.1.1")}, "response for a different address"),
        (404, {"json": {"ip": IP, "noise": True, "riot": False}}, "malformed response"),
        (404, {"text": "<html>not found</html>"}, "malformed response"),
        (200, {"content": b"{" + b" " * 20_000 + b"}"}, "oversize response"),
    ],
)
@respx.mock
async def test_failures_are_unknown_never_clean(
    client: GreyNoiseClient,
    target: ScanTarget,
    status: int,
    kwargs: dict[str, object],
    reason: str,
) -> None:
    respx.get(URL).respond(status, **kwargs)  # type: ignore[arg-type]
    res = await client.check(target)
    assert res.verdict is Reputation.UNKNOWN
    assert res.reason == reason


@pytest.mark.parametrize(
    ("exc", "reason"),
    [
        (httpx.ConnectTimeout, "timeout"),
        (httpx.ReadTimeout, "timeout"),
        (httpx.ConnectError, "request failed"),
        (httpx.RemoteProtocolError, "request failed"),
    ],
)
@respx.mock
async def test_network_errors_are_unknown(
    client: GreyNoiseClient, target: ScanTarget, exc: type[Exception], reason: str
) -> None:
    respx.get(URL).mock(side_effect=exc)
    res = await client.check(target)
    assert res.verdict is Reputation.UNKNOWN
    assert res.reason == reason


async def test_ipv6_not_supported_is_unknown(client: GreyNoiseClient) -> None:
    res = await client.check(AddressPolicy([]).check("2001:558::1"))
    assert res.verdict is Reputation.UNKNOWN
    assert res.reason == "ipv6_unsupported"


async def test_real_timeout_against_hanging_server() -> None:
    """No mocks: a server that never answers must yield UNKNOWN within the timeout."""
    import asyncio

    async def hang(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(5)
        writer.close()

    server = await asyncio.start_server(hang, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    c = GreyNoiseClient(base_url=f"http://127.0.0.1:{port}", timeout=0.3)
    try:
        res = await c.check(AddressPolicy([]).check(IP))
    finally:
        await c.aclose()
        server.close()
    assert res.verdict is Reputation.UNKNOWN
    assert res.reason == "timeout"
