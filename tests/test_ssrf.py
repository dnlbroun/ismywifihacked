from collections.abc import AsyncIterator

import pytest

from netcheck.addrpolicy import AddressPolicy, ScanTarget
from netcheck.scan.ssrf import LocationRejected, fetch_location, validate_location
from tests.netfixtures import DEVICE_XML, LOCALHOST, HttpServer, http_response

TEST_POLICY = AddressPolicy([], allow_loopback=True)
PROD_POLICY = AddressPolicy([])


@pytest.fixture
def local() -> ScanTarget:
    return TEST_POLICY.check(LOCALHOST)


@pytest.fixture
async def device_server() -> AsyncIterator[HttpServer]:
    srv = await HttpServer(lambda: http_response(DEVICE_XML)).start()
    yield srv
    await srv.close()


def test_accepts_same_host(local: ScanTarget) -> None:
    loc = validate_location("http://127.0.0.1:49152/rootDesc.xml", local, TEST_POLICY)
    assert loc.url == "http://127.0.0.1:49152/rootDesc.xml"
    assert validate_location("http://127.0.0.1/a?b=c", local, TEST_POLICY).url == (
        "http://127.0.0.1:80/a?b=c"
    )


@pytest.mark.parametrize(
    "url",
    [
        # off-host, including private / metadata ranges
        "http://127.0.0.2:80/desc.xml",
        "http://10.0.0.1/desc.xml",
        "http://192.168.1.1/desc.xml",
        "http://169.254.169.254/latest/meta-data/",
        "http://[fd00::1]/desc.xml",
        "http://8.8.8.8/desc.xml",
        # hostnames and alternative IP spellings
        "http://localhost/desc.xml",
        "http://router.local/desc.xml",
        "http://127.0.0.1.nip.io/desc.xml",
        "http://2130706433/desc.xml",
        "http://0x7f000001/desc.xml",
        "http://0177.0.0.1/desc.xml",
        "http://127.1/desc.xml",
        "http://[::ffff:127.0.0.1]/desc.xml",
        # userinfo / parser confusion
        "http://127.0.0.1@evil.example/desc.xml",
        "http://evil.example@127.0.0.1/desc.xml",
        "http://evil.example#@127.0.0.1/desc.xml",
        "http://127.0.0.1\\@evil.example/desc.xml",
        "http://127.0.0.1/desc.xml#frag",
        # schemes
        "https://127.0.0.1/desc.xml",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_FLUSHALL",
        "ftp://127.0.0.1/desc.xml",
        "//127.0.0.1/desc.xml",
        "/desc.xml",
        # header injection and junk
        "http://127.0.0.1/desc.xml\r\nHost: evil.example",
        "http://127.0.0.1/desc xml",
        "http://127.0.0.1:0/desc.xml",
        "http://127.0.0.1:99999/desc.xml",
        "http://127.0.0.1:abc/desc.xml",
        "http://127.0.0.1/" + "a" * 600,
        "",
    ],
)
def test_rejects(local: ScanTarget, url: str) -> None:
    with pytest.raises(LocationRejected):
        validate_location(url, local, TEST_POLICY)


def test_production_policy_rechecked() -> None:
    """Even a same-host URL is refused if the address fails the production policy."""
    local = TEST_POLICY.check(LOCALHOST)
    with pytest.raises(LocationRejected, match="not allowed"):
        validate_location("http://127.0.0.1/desc.xml", local, PROD_POLICY)


def test_public_target_rejects_metadata() -> None:
    public = PROD_POLICY.check("8.8.8.8")
    assert validate_location("http://8.8.8.8:5000/d.xml", public, PROD_POLICY)
    for url in ("http://169.254.169.254/", "http://127.0.0.1/", "http://8.8.4.4/"):
        with pytest.raises(LocationRejected):
            validate_location(url, public, PROD_POLICY)


async def test_fetch_ok(local: ScanTarget, device_server: HttpServer) -> None:
    body = await fetch_location(
        f"http://127.0.0.1:{device_server.port}/rootDesc.xml", local, TEST_POLICY
    )
    assert body == DEVICE_XML
    req = device_server.requests[0]
    assert req.startswith(b"GET /rootDesc.xml HTTP/1.1\r\n")
    assert f"host: 127.0.0.1:{device_server.port}".encode() in req.lower()


async def test_redirect_not_followed(local: ScanTarget, device_server: HttpServer) -> None:
    redirect = await HttpServer(
        lambda: http_response(
            b"",
            status="302 Found",
            headers={"Location": f"http://127.0.0.1:{device_server.port}/rootDesc.xml"},
        )
    ).start()
    try:
        with pytest.raises(LocationRejected, match="status 302"):
            await fetch_location(f"http://127.0.0.1:{redirect.port}/", local, TEST_POLICY)
        assert device_server.hits == 0
    finally:
        await redirect.close()


@pytest.mark.parametrize("content_length", [True, False])
async def test_oversize_body_rejected(local: ScanTarget, content_length: bool) -> None:
    srv = await HttpServer(
        lambda: http_response(b"<a>" + b"x" * 70_000 + b"</a>", content_length=content_length)
    ).start()
    try:
        with pytest.raises(LocationRejected, match="too large"):
            await fetch_location(f"http://127.0.0.1:{srv.port}/", local, TEST_POLICY)
    finally:
        await srv.close()


async def test_chunked_oversize_rejected(local: ScanTarget) -> None:
    chunk = b"x" * 8000
    body = b"".join(b"%x\r\n%s\r\n" % (len(chunk), chunk) for _ in range(10)) + b"0\r\n\r\n"
    srv = await HttpServer(
        lambda: http_response(body, headers={"Transfer-Encoding": "chunked"}, content_length=False)
    ).start()
    try:
        with pytest.raises(LocationRejected, match="too large"):
            await fetch_location(f"http://127.0.0.1:{srv.port}/", local, TEST_POLICY)
    finally:
        await srv.close()


async def test_compressed_body_rejected(local: ScanTarget) -> None:
    srv = await HttpServer(
        lambda: http_response(b"\x1f\x8b...", headers={"Content-Encoding": "gzip"})
    ).start()
    try:
        with pytest.raises(LocationRejected, match="encoded"):
            await fetch_location(f"http://127.0.0.1:{srv.port}/", local, TEST_POLICY)
    finally:
        await srv.close()


async def test_slow_server_times_out(local: ScanTarget) -> None:
    srv = await HttpServer(lambda: http_response(DEVICE_XML), delay=1.5).start()
    try:
        with pytest.raises(LocationRejected, match="timeout"):
            await fetch_location(f"http://127.0.0.1:{srv.port}/", local, TEST_POLICY, timeout=0.5)
    finally:
        await srv.close()


async def test_connection_refused(local: ScanTarget) -> None:
    from tests.netfixtures import free_port

    with pytest.raises(LocationRejected, match="fetch failed"):
        await fetch_location(f"http://127.0.0.1:{free_port()}/", local, TEST_POLICY)


async def test_proxy_env_ignored(
    local: ScanTarget, device_server: HttpServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://10.255.255.1:3128")
    monkeypatch.setenv("ALL_PROXY", "http://10.255.255.1:3128")
    body = await fetch_location(f"http://127.0.0.1:{device_server.port}/", local, TEST_POLICY)
    assert body == DEVICE_XML
