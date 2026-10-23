import asyncio
import ipaddress
import re
from pathlib import Path

import pytest
import respx

from netcheck.reputation.greynoise import GreyNoiseClient, Reputation, ReputationResult
from netcheck.scan.models import DeviceInfo, ExposureResult, PortResult, PortState, SsdpResult
from netcheck.web.app import make_templates
from tests.webharness import (
    CADDY,
    COMCAST_V4,
    COMCAST_V6,
    ORIGIN,
    Harness,
    build,
    csrf_from,
    run_scan,
    scan_headers,
)

TEMPLATES = Path(__file__).resolve().parents[1] / "src" / "netcheck" / "web" / "templates"
XSS = '<script>alert("pwn")</script>'


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return build(tmp_path)


def result_page(h: Harness, resp_location: str) -> str:
    with h.client() as c:
        page = c.get(resp_location)
    assert page.status_code == 200
    return page.text


# --- scan target --------------------------------------------------------------


def test_scan_targets_connecting_address(h: Harness) -> None:
    with h.client() as c:
        resp = run_scan(c, COMCAST_V4)
        assert resp.status_code == 303
        location = resp.headers["location"]
        assert re.fullmatch(r"/r/[A-Za-z0-9_-]{22}", location)
        page = c.get(location).text
    assert h.scan.calls == [COMCAST_V4]
    assert h.reputation.calls == [COMCAST_V4]
    assert "24.0.1.x" in page
    assert COMCAST_V4 not in page  # raw IP never shown or stored
    assert "Xfinity" in page


def test_scan_target_cannot_be_overridden(h: Harness) -> None:
    spoof = "1.1.1.1"
    headers = scan_headers(
        f"{spoof}, {COMCAST_V4}",  # Caddy's own (rightmost) entry wins
        **{
            "X-Real-IP": spoof,
            "Forwarded": f"for={spoof}",
            "True-Client-IP": spoof,
            "CF-Connecting-IP": spoof,
            "X-Client-IP": spoof,
            "Host": spoof,
        },
    )
    with h.client() as c:
        resp = run_scan(
            c,
            COMCAST_V4,
            data={"target": spoof, "ip": spoof, "host": spoof, "address": spoof, "claim": spoof},
            params={"target": spoof, "ip": spoof},
            headers=headers,
        )
    assert resp.status_code == 303
    assert h.scan.calls == [COMCAST_V4]
    assert h.reputation.calls == [COMCAST_V4]


def test_forwarded_header_ignored_from_untrusted_peer(h: Harness) -> None:
    direct = ("24.0.9.9", 5555)  # not our local Caddy
    with h.client(peer=direct) as c:
        page = c.get("/")
        token = csrf_from(c, page.text)
        resp = c.post("/scan", data={"csrf": token}, headers=scan_headers("1.1.1.1"))
    assert resp.status_code == 303
    assert h.scan.calls == ["24.0.9.9"]


@pytest.mark.parametrize("xff", [None, "not-an-ip", "", "24.0.1.2, garbage"])
def test_bad_forwarded_header_from_proxy_fails_closed(h: Harness, xff: str | None) -> None:
    headers = {"Sec-Fetch-Site": "same-origin"}
    if xff is not None:
        headers["X-Forwarded-For"] = xff
    with h.client() as c:
        token = csrf_from(c, c.get("/").text)
        resp = c.post("/scan", data={"csrf": token}, headers=headers)
    assert resp.status_code == 500
    assert h.scan.calls == []


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fd12:3456::1",
        "::ffff:192.168.0.1",
        "8.9.10.11",  # our own VPS
    ],
)
def test_private_reserved_and_own_addresses_refused(h: Harness, ip: str) -> None:
    with h.client() as c:
        resp = run_scan(c, ip)
    assert resp.status_code == 400
    assert "can&#39;t check this connection" in resp.text
    assert h.scan.calls == []
    assert h.reputation.calls == []


def test_cgnat_client_address_explained_not_passed(h: Harness) -> None:
    with h.client() as c:
        resp = run_scan(c, "100.70.1.2")
    assert resp.status_code == 200
    assert "can&#39;t see your router" in resp.text
    assert "isn&#39;t a pass" in resp.text
    assert h.scan.calls == []


# --- CSRF / origin -------------------------------------------------------------


@pytest.mark.parametrize(
    ("csrf", "headers"),
    [
        (lambda t: "", scan_headers(COMCAST_V4)),
        (lambda t: "wrong" + t, scan_headers(COMCAST_V4)),
        (None, scan_headers(COMCAST_V4, **{"Sec-Fetch-Site": "cross-site"})),
        (None, scan_headers(COMCAST_V4, **{"Sec-Fetch-Site": "same-site"})),
        (None, scan_headers(COMCAST_V4, Origin="https://evil.example")),
        (None, scan_headers(COMCAST_V4, Origin="https://v4.example.com")),
    ],
)
def test_scan_requires_same_origin_and_csrf(
    h: Harness, csrf: object, headers: dict[str, str]
) -> None:
    with h.client() as c:
        resp = run_scan(c, COMCAST_V4, headers=headers, csrf=csrf)  # type: ignore[arg-type]
    assert resp.status_code == 403
    assert h.scan.calls == []


def test_csrf_cookie_is_locked_down(h: Harness) -> None:
    with h.client() as c:
        cookie = c.get("/").headers["set-cookie"]
    assert cookie.startswith("__Host-csrf=")
    for attr in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
        assert attr.lower() in cookie.lower()


def test_get_cannot_start_scan(h: Harness) -> None:
    with h.client() as c:
        assert c.get("/scan").status_code in (404, 405)
    assert h.scan.calls == []


def test_real_origin_accepted(h: Harness) -> None:
    with h.client() as c:
        resp = run_scan(c, COMCAST_V4, headers=scan_headers(COMCAST_V4, Origin=ORIGIN))
    assert resp.status_code == 303


# --- rate limiting / concurrency -----------------------------------------------


def test_rate_limit_three_per_hour(h: Harness) -> None:
    with h.client() as c:
        codes = [run_scan(c, COMCAST_V4).status_code for _ in range(4)]
        assert codes == [303, 303, 303, 429]
        assert run_scan(c, "24.0.1.3").status_code == 303  # different address
        h.clock.t += 3601
        assert run_scan(c, COMCAST_V4).status_code == 303
    assert len(h.scan.calls) == 5


def test_rate_limit_ipv6_per_64(h: Harness) -> None:
    with h.client() as c:
        for i in range(3):
            assert run_scan(c, f"2001:558::{i + 1}").status_code == 303
        assert run_scan(c, "2001:558::ffff:1").status_code == 429  # same /64
        assert run_scan(c, "2001:558:0:1::1").status_code == 303  # next /64


def test_rate_limit_survives_salt_rotation(h: Harness) -> None:
    with h.client() as c:
        h.clock.t += 24 * 3600 - 60  # rotation happens mid-window
        for _ in range(3):
            assert run_scan(c, COMCAST_V4).status_code == 303
        h.clock.t += 120
        assert run_scan(c, COMCAST_V4).status_code == 429


async def test_global_concurrency_cap(tmp_path: Path) -> None:
    h = build(tmp_path, max_concurrent=1)
    h.scan.gate = asyncio.Event()
    async with h.app.router.lifespan_context(h.app), h.async_client() as c:
        page1 = await c.get("/", headers={"X-Forwarded-For": COMCAST_V4})
        tok = csrf_from(c, page1.text)
        first = asyncio.create_task(
            c.post("/scan", data={"csrf": tok}, headers=scan_headers(COMCAST_V4))
        )
        await asyncio.wait_for(h.scan.entered.wait(), 5)
        second = await c.post("/scan", data={"csrf": tok}, headers=scan_headers("24.0.1.3"))
        assert second.status_code == 503
        h.scan.gate.set()
        assert (await first).status_code == 303
    assert h.scan.calls == [COMCAST_V4]


# --- escaping / headers ----------------------------------------------------------


def test_untrusted_strings_render_escaped(h: Harness) -> None:
    h.scan.results[COMCAST_V4] = ExposureResult(
        ip_version=4,
        ports=[
            PortResult(80, PortState.OPEN, server_header=XSS),
            PortResult(443, PortState.OPEN, tls_subject=f"CN={XSS}"),
            PortResult(22, PortState.CLOSED),
        ]
        + [PortResult(p, PortState.FILTERED) for p in range(1000, 1010)],
        ssdp=SsdpResult(
            responded=True,
            device=DeviceInfo(manufacturer='"><img src=x onerror=alert(1)>', model=XSS),
        ),
        any_response=True,
    )
    h.reputation.result = ReputationResult(
        Reputation.SUSPICIOUS, classification="malicious", name=XSS
    )
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert(&#34;pwn&#34;)&lt;/script&gt;" in page
    assert "&#34;&gt;&lt;img src=x onerror=alert(1)&gt;" in page
    # The only script tags are our own external ones (none on the result page).
    assert re.findall(r"<script\b[^>]*>", page) == []


def test_no_safe_filter_anywhere() -> None:
    env = make_templates()
    assert "safe" not in env.filters
    for tpl in TEMPLATES.glob("*.html"):
        text = tpl.read_text()
        assert "|safe" not in text.replace(" ", "")
        assert "autoescape false" not in text
        assert "Markup" not in text


def test_templates_have_no_inline_scripts_or_handlers() -> None:
    for tpl in TEMPLATES.glob("*.html"):
        text = tpl.read_text()
        for tag in re.findall(r"<script\b[^>]*>", text):
            assert 'src="/static/' in tag
        assert not re.search(r"\son[a-z]+\s*=", text)
        assert "style=" not in text


@pytest.mark.parametrize("path", ["/", "/r/AAAAAAAAAAAAAAAAAAAAAA", "/api/dns/x", "/nope"])
def test_security_headers(h: Harness, path: str) -> None:
    with h.client() as c:
        r = c.get(path, headers={"X-Forwarded-For": COMCAST_V4})
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "https://*.dns.example.com" in csp
    assert r.headers["strict-transport-security"].startswith("max-age=31536000")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-frame-options"] == "DENY"


def test_static_assets_served_with_headers(h: Harness) -> None:
    with h.client() as c:
        js = c.get("/static/scan.js")
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]
    assert js.headers["x-content-type-options"] == "nosniff"


# --- results storage ---------------------------------------------------------------


def test_results_expire_after_24h(h: Harness) -> None:
    with h.client() as c:
        loc = run_scan(c, COMCAST_V4).headers["location"]
        h.clock.t += 24 * 3600 - 1
        assert c.get(loc).status_code == 200
        h.clock.t += 2
        assert c.get(loc).status_code == 404
    assert h.results.purge() == 1


@pytest.mark.parametrize("rid", ["x", "../../etc/passwd", "A" * 23, "A" * 21 + "!", "A" * 22])
def test_unknown_or_malformed_result_ids(h: Harness, rid: str) -> None:
    with h.client() as c:
        assert c.get(f"/r/{rid}").status_code == 404


def test_report_ids_are_distinct_and_long(h: Harness) -> None:
    with h.client() as c:
        a = run_scan(c, COMCAST_V4).headers["location"]
        b = run_scan(c, COMCAST_V4).headers["location"]
    assert a != b
    assert len(a.removeprefix("/r/")) == 22  # 16 random bytes, base64url


def test_report_storage_has_no_raw_ip(h: Harness) -> None:
    import sqlite3

    with h.client() as c:
        run_scan(c, COMCAST_V4)
    rows = (
        sqlite3.connect(h.settings.results_db_path).execute("SELECT body FROM reports").fetchall()
    )
    assert rows
    assert all(COMCAST_V4 not in body for (body,) in rows)


# --- dual stack claims ------------------------------------------------------------


def test_ipv4_plus_ipv6_via_claim(h: Harness) -> None:
    with h.client() as c:
        claim = c.post("/api/claim", headers={"X-Forwarded-For": COMCAST_V6, "Origin": ORIGIN})
        assert claim.headers["access-control-allow-origin"] == ORIGIN
        token = claim.json()["claim"]
        assert isinstance(token, str)
        resp = run_scan(c, COMCAST_V4, data={"claim": [token, ""]})
        page = c.get(resp.headers["location"]).text
        # one-time use
        assert h.claims.redeem(token) is None
    assert sorted(h.scan.calls) == sorted([COMCAST_V4, str(ipaddress.ip_address(COMCAST_V6))])
    assert "Open to the internet (IPv4)" in page
    assert "Open to the internet (IPv6)" in page
    assert h.reputation.calls == [COMCAST_V4]


def test_claim_requires_our_origin(h: Harness) -> None:
    with h.client() as c:
        for origin in ("https://evil.example", "null", ""):
            r = c.post("/api/claim", headers={"X-Forwarded-For": COMCAST_V6, "Origin": origin})
            assert r.status_code == 403
            assert "access-control-allow-origin" not in r.headers


def test_claim_for_private_address_is_null(h: Harness) -> None:
    with h.client() as c:
        r = c.post("/api/claim", headers={"X-Forwarded-For": "fd00::1", "Origin": ORIGIN})
    assert r.json() == {"claim": None}


def test_same_family_or_bogus_claims_ignored(h: Harness) -> None:
    with h.client() as c:
        other_v4 = c.post("/api/claim", headers={"X-Forwarded-For": "24.0.7.7", "Origin": ORIGIN})
        resp = run_scan(c, COMCAST_V4, data={"claim": [other_v4.json()["claim"], "made-up-claim"]})
    assert resp.status_code == 303
    assert h.scan.calls == [COMCAST_V4]


def test_expired_claim_ignored(h: Harness) -> None:
    with h.client() as c:
        token = c.post(
            "/api/claim", headers={"X-Forwarded-For": COMCAST_V6, "Origin": ORIGIN}
        ).json()["claim"]
        h.clock.t += 121
        run_scan(c, COMCAST_V4, data={"claim": token})
    assert h.scan.calls == [COMCAST_V4]


# --- verdicts ---------------------------------------------------------------------


def card(page: str, key: str) -> str:
    m = re.search(rf'<article class="card status-(\w+)" id="{key}">(.*?)</article>', page, re.S)
    assert m is not None, key
    return m.group(1) + "|" + m.group(2)


def test_greynoise_failure_is_couldnt_check(h: Harness) -> None:
    h.reputation.result = ReputationResult(Reputation.UNKNOWN, reason="timeout")
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    rep = card(page, "reputation")
    assert rep.startswith("unknown|")
    assert "Couldn&#39;t check" in rep
    assert "Everything we could check looks good" not in page


def test_greynoise_exception_is_couldnt_check(h: Harness) -> None:
    h.reputation.error = RuntimeError("boom")
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    assert card(page, "reputation").startswith("unknown|")


@pytest.mark.parametrize("status", [500, 429, 403])
@respx.mock
async def test_real_greynoise_client_http_error_is_couldnt_check(h: Harness, status: int) -> None:
    respx.get(f"https://api.greynoise.io/v3/community/{COMCAST_V4}").respond(status)
    real = GreyNoiseClient()
    h.deps.reputation = real
    try:
        with h.client() as c:
            page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    finally:
        await real.aclose()
    assert card(page, "reputation").startswith("unknown|")


def test_scan_exception_is_couldnt_check(h: Harness) -> None:
    h.scan.error = OSError("network down")
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    assert card(page, "exposure_v4").startswith("unknown|")


def test_all_green_only_when_everything_checked(h: Harness) -> None:
    token = "ab" * 16
    h.tokens.record(token, ipaddress.ip_address("24.0.0.53"))  # Comcast resolver
    h.tokens.flush()
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4, data={"dns_token": token}).headers["location"]).text
    assert card(page, "dns").startswith("good|")
    assert card(page, "exposure_v4").startswith("good|")
    assert card(page, "reputation").startswith("good|")
    assert "Everything we could check looks good" in page


def test_no_response_means_cant_see_router(h: Harness) -> None:
    h.scan.results[COMCAST_V4] = ExposureResult(
        ip_version=4, ports=[PortResult(22, PortState.FILTERED)], any_response=False
    )
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    exp = card(page, "exposure_v4")
    assert exp.startswith("unknown|")
    assert "can&#39;t see your router" in exp
    assert "Everything we could check looks good" not in page


def test_mobile_carrier_asn_means_cant_see_router(h: Harness) -> None:
    with h.client() as c:
        page = c.get(run_scan(c, "172.58.1.1").headers["location"]).text  # T-Mobile
    exp = card(page, "exposure_v4")
    assert exp.startswith("unknown|")
    assert "carrier-grade NAT" in exp


def test_vpn_or_hosting_address_not_scanned(h: Harness) -> None:
    with h.client() as c:
        page = c.get(run_scan(c, "198.199.70.1").headers["location"]).text  # DigitalOcean
    assert h.scan.calls == []
    exp = card(page, "exposure_v4")
    assert exp.startswith("unknown|")
    assert "VPN" in exp


def test_incomplete_scan_with_nothing_found_is_not_a_pass(h: Harness) -> None:
    h.scan.results[COMCAST_V4] = ExposureResult(
        ip_version=4, ports=[PortResult(22, PortState.CLOSED)], any_response=True, complete=False
    )
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    assert card(page, "exposure_v4").startswith("unknown|")


@pytest.mark.parametrize(
    ("ports", "ssdp", "natpmp", "expected"),
    [
        ([23], False, False, "bad"),
        ([7547], False, False, "bad"),
        ([445], False, False, "bad"),
        ([3389], False, False, "bad"),
        ([80], False, False, "bad"),
        ([8443], False, False, "bad"),
        ([], True, False, "bad"),
        ([], False, True, "bad"),
        ([22], False, False, "warn"),
        ([32400], False, False, "warn"),
        ([22, 23], False, False, "bad"),
    ],
)
def test_severity(h: Harness, ports: list[int], ssdp: bool, natpmp: bool, expected: str) -> None:
    from netcheck.scan.models import NatPmpResult

    all_ports = [PortResult(p, PortState.OPEN) for p in ports] + [
        PortResult(p, PortState.CLOSED) for p in range(2000, 2012)
    ]
    h.scan.results[COMCAST_V4] = ExposureResult(
        ip_version=4,
        ports=all_ports,
        ssdp=SsdpResult(responded=ssdp),
        natpmp=NatPmpResult(responded=natpmp),
        any_response=True,
    )
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    exp = card(page, "exposure_v4")
    assert exp.startswith(f"{expected}|")
    assert "How to fix" in exp


def test_firewall_answering_everything_is_not_reported_as_open(h: Harness) -> None:
    h.scan.results[COMCAST_V4] = ExposureResult(
        ip_version=4,
        ports=[PortResult(p, PortState.OPEN) for p in (21, 22, 23, 80, 443, 445, 3389, 8080)],
        any_response=True,
    )
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    assert card(page, "exposure_v4").startswith("unknown|")


@pytest.mark.parametrize(
    ("resolver", "expected", "text"),
    [
        ("24.0.0.53", "good", "your internet provider"),
        ("8.8.8.8", "unknown", "secure-DNS"),  # Google: may be browser DoH
        ("1.0.0.1", "unknown", "secure-DNS"),  # Cloudflare
        ("203.1.0.9", "bad", "don&#39;t recognise"),  # some random hosting network
        ("45.0.0.1", "bad", "don&#39;t recognise"),  # unrouted / unknown ASN
    ],
)
def test_dns_classification(h: Harness, resolver: str, expected: str, text: str) -> None:
    token = "cd" * 16
    h.tokens.record(token, ipaddress.ip_address(resolver))
    h.tokens.flush()
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4, data={"dns_token": token}).headers["location"]).text
    dns = card(page, "dns")
    assert dns.startswith(f"{expected}|")
    assert text in dns


@pytest.mark.parametrize("token", [None, "", "not-a-token", "ef" * 16])
def test_dns_missing_or_unseen_is_couldnt_check(h: Harness, token: str | None) -> None:
    with h.client() as c:
        data = {"dns_token": token} if token is not None else {}
        page = c.get(run_scan(c, COMCAST_V4, data=data).headers["location"]).text  # type: ignore[arg-type]
    assert card(page, "dns").startswith("unknown|")


def test_dns_api_uses_token_store(h: Harness) -> None:
    token = "12" * 16
    with h.client() as c:
        assert c.get(f"/api/dns/{token}").json() == {"seen": False}
        h.tokens.record(token, ipaddress.ip_address("24.0.0.53"))
        h.tokens.flush()
        r = c.get(f"/api/dns/{token}")
    assert r.json() == {"seen": True}
    assert r.headers["cache-control"] == "no-store"


def test_page_shows_limits_and_privacy(h: Harness) -> None:
    with h.client() as c:
        home = c.get("/").text
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    assert "Privacy" in home
    assert "What we can't check" in page
    assert "Wi-Fi password" in page
    assert CADDY[0] not in page


def test_head_requests_supported(h: Harness) -> None:
    with h.client() as c:
        r = c.head("/")
    assert r.status_code == 200
    assert "content-security-policy" in r.headers


# --- new checks -------------------------------------------------------------------


def test_spectrum_resolver_on_sibling_network_is_own_isp(h: Harness) -> None:
    token = "a1" * 16
    h.tokens.record(token, ipaddress.ip_address("67.0.0.53"))  # TWC-11351, a Spectrum ASN
    h.tokens.flush()
    with h.client() as c:
        page = c.get(
            run_scan(c, "66.0.0.7", data={"dns_token": token}).headers["location"]  # Charter
        ).text
    dns = card(page, "dns")
    assert dns.startswith("good|")
    assert "your internet provider" in dns


@pytest.mark.parametrize(
    ("port", "expected"),
    [(5555, "bad"), (5900, "bad"), (37777, "bad"), (34567, "bad"), (8291, "bad"),
     (52869, "bad"), (49000, "bad"), (9100, "warn"), (631, "warn"), (1883, "warn"),
     (554, "warn"), (8000, "warn")],
)  # fmt: skip
def test_new_port_severities(h: Harness, port: int, expected: str) -> None:
    h.scan.results[COMCAST_V4] = ExposureResult(
        ip_version=4,
        ports=[PortResult(port, PortState.OPEN)]
        + [PortResult(p, PortState.CLOSED) for p in range(2000, 2012)],
        any_response=True,
    )
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    exp = card(page, "exposure_v4")
    assert exp.startswith(f"{expected}|")
    assert "How to fix" in exp


@pytest.mark.parametrize(("recursion", "expected"), [(True, "bad"), (False, "warn")])
def test_dns_on_wan(h: Harness, recursion: bool, expected: str) -> None:
    from netcheck.scan.models import DnsResolverResult

    h.scan.results[COMCAST_V4] = ExposureResult(
        ip_version=4,
        ports=[PortResult(22, PortState.CLOSED)],
        dns=DnsResolverResult(responded=True, recursion=recursion),
        any_response=True,
    )
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    exp = card(page, "exposure_v4")
    assert exp.startswith(f"{expected}|")
    if recursion:
        assert "open DNS" in exp


def test_history_card(h: Harness) -> None:
    from netcheck.reputation.internetdb import History, HistoryResult

    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    assert card(page, "history").startswith("good|")
    assert h.history.calls == [COMCAST_V4]

    h.history.result = HistoryResult(History.SEEN, ports=[8080], vulns=["CVE-2021-44228"])
    with h.client() as c:
        page = c.get(run_scan(c, "24.0.1.9").headers["location"]).text
    hist = card(page, "history")
    assert hist.startswith("bad|")
    assert "CVE-2021-44228" in hist
    assert "8080" in hist

    h.history.result = HistoryResult(History.SEEN, ports=[32400])
    with h.client() as c:
        page = c.get(run_scan(c, "24.0.1.10").headers["location"]).text
    assert card(page, "history").startswith("warn|")

    h.history.result = HistoryResult(History.UNKNOWN, reason="timeout")
    with h.client() as c:
        page = c.get(run_scan(c, "24.0.1.11").headers["location"]).text
    assert card(page, "history").startswith("unknown|")


def test_wifi_checklist_on_results(h: Harness) -> None:
    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
    assert 'id="wifi-check"' in page
    assert "WPA2 or WPA3" in page


def test_daily_counts_are_aggregate_only(h: Harness) -> None:
    import sqlite3

    with h.client() as c:
        run_scan(c, COMCAST_V4)
        run_scan(c, "24.0.1.9")
    counts = {m: n for _, m, n in h.results.daily_counts()}
    assert counts["scans"] == 2
    assert counts["reputation:good"] == 2
    rows = (
        sqlite3.connect(h.settings.results_db_path).execute("SELECT * FROM daily_counts").fetchall()
    )
    assert all(COMCAST_V4 not in str(r) and "/r/" not in str(r) for r in rows)
    assert {len(r) for r in rows} == {3}  # day, metric, n - nothing else


def test_abuse_card_only_when_configured(h: Harness) -> None:
    from netcheck.reputation.abuseipdb import Abuse, AbuseResult
    from tests.webharness import FakeAbuse

    with h.client() as c:
        page = c.get(run_scan(c, COMCAST_V4).headers["location"]).text
        home = c.get("/").text
    assert 'id="abuse"' not in page
    assert "GreyNoise and Shodan." in home

    h.deps.abuse = FakeAbuse(
        AbuseResult(
            Abuse.SUSPICIOUS, score=100, reports=40, reporters=12, last_reported="2026-10-20"
        )
    )
    with h.client() as c:  # new lifespan picks up the configured service
        page = c.get(run_scan(c, "24.0.1.9").headers["location"]).text
        home = c.get("/").text
    abuse = card(page, "abuse")
    assert abuse.startswith("bad|")
    assert "40 reports from 12 reporters" in abuse
    assert "GreyNoise, Shodan and AbuseIPDB." in home

    for result, status in [
        (AbuseResult(Abuse.NO_REPORTS), "good"),
        (AbuseResult(Abuse.LOW_CONFIDENCE, score=3, reports=1, reporters=1), "warn"),
        (AbuseResult(Abuse.NO_REPORTS, score=0, reports=102, reporters=36), "good"),
        (AbuseResult(Abuse.UNKNOWN, reason="rate limited"), "unknown"),
    ]:
        h.clock.t += 3601
        h.deps.abuse = FakeAbuse(result)
        with h.client() as c:
            page = c.get(run_scan(c, "24.0.1.9").headers["location"]).text
        assert card(page, "abuse").startswith(f"{status}|")
