"""The web app end to end, with fake network checks (nothing leaves the machine)."""

import asyncio
import ipaddress
import re
import secrets
import sqlite3
from pathlib import Path

import pytest

from netcheck.reputation.abuseipdb import Abuse, AbuseResult
from netcheck.reputation.greynoise import Reputation, ReputationResult
from netcheck.reputation.internetdb import History, HistoryResult
from netcheck.scan.models import (
    DeviceInfo,
    DnsResolverResult,
    ExposureResult,
    NatPmpResult,
    PortResult,
    PortState,
    SsdpResult,
)
from netcheck.web.app import make_templates
from tests.webharness import (
    COMCAST_V4,
    COMCAST_V6,
    ORIGIN,
    FakeAbuse,
    Harness,
    build,
    csrf_from,
    run_scan,
    scan_headers,
)

TEMPLATES = Path(__file__).resolve().parents[1] / "src" / "netcheck" / "web" / "templates"


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return build(tmp_path)


def scan_page(h: Harness, ip: str = COMCAST_V4, dns_resolver: str | None = None) -> str:
    data = {}
    if dns_resolver:
        token = secrets.token_hex(16)
        h.tokens.record(token, ipaddress.ip_address(dns_resolver))
        h.tokens.flush()
        data["dns_token"] = token
    with h.client() as c:
        resp = run_scan(c, ip, data=data)  # type: ignore[arg-type]
        assert resp.status_code == 303, resp.text
        return c.get(resp.headers["location"]).text


def card(page: str, key: str) -> tuple[str, str]:
    m = re.search(rf'<article class="card status-(\w+)" id="{key}">(.*?)</article>', page, re.S)
    assert m is not None, key
    return m.group(1), m.group(2)


def exposure(*open_ports: int, **kw: object) -> ExposureResult:
    ports = [PortResult(p, PortState.OPEN) for p in open_ports]
    ports += [PortResult(p, PortState.CLOSED) for p in range(2000, 2012)]
    return ExposureResult(ip_version=4, ports=ports, any_response=True, **kw)  # type: ignore[arg-type]


# --- security requirements -------------------------------------------------------------


def test_scan_target_cannot_be_overridden(h: Harness) -> None:
    spoof = "1.1.1.1"
    headers = scan_headers(
        f"{spoof}, {COMCAST_V4}", **{"X-Real-IP": spoof, "Forwarded": f"for={spoof}"}
    )
    with h.client() as c:
        resp = run_scan(
            c,
            COMCAST_V4,
            data={"target": spoof, "ip": spoof},
            params={"target": spoof},
            headers=headers,
        )
    assert resp.status_code == 303
    assert h.scan.calls == [COMCAST_V4]
    assert h.reputation.calls == [COMCAST_V4]

    # A peer that isn't our local Caddy can't set X-Forwarded-For at all.
    with h.client(peer=("24.0.9.9", 5555)) as c:
        token = csrf_from(c, c.get("/").text)
        c.post("/scan", data={"csrf": token}, headers=scan_headers(spoof))
    assert h.scan.calls[-1] == "24.0.9.9"


@pytest.mark.parametrize(
    "ip", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "fd12::1", "8.9.10.11"]
)
def test_private_reserved_and_own_addresses_refused(h: Harness, ip: str) -> None:
    with h.client() as c:
        assert run_scan(c, ip).status_code == 400
    assert h.scan.calls == []
    assert h.reputation.calls == []


def test_csrf_and_origin_required(h: Harness) -> None:
    with h.client() as c:
        assert run_scan(c, COMCAST_V4, csrf=lambda t: "wrong").status_code == 403
        bad_site = scan_headers(COMCAST_V4, **{"Sec-Fetch-Site": "cross-site"})
        assert run_scan(c, COMCAST_V4, headers=bad_site).status_code == 403
        bad_origin = scan_headers(COMCAST_V4, Origin="https://evil.example")
        assert run_scan(c, COMCAST_V4, headers=bad_origin).status_code == 403
        assert c.get("/scan").status_code in (404, 405)
    assert h.scan.calls == []


def test_untrusted_strings_are_escaped(h: Harness) -> None:
    xss = '<script>alert("x")</script>'
    h.scan.results[COMCAST_V4] = exposure(
        ssdp=SsdpResult(
            responded=True, device=DeviceInfo(manufacturer='"><img src=x onerror=1>', model=xss)
        )
    )
    h.scan.results[COMCAST_V4].ports[0:0] = [PortResult(80, PortState.OPEN, server_header=xss)]
    h.reputation.result = ReputationResult(Reputation.SUSPICIOUS, name=xss)
    page = scan_page(h)
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;" in page


def test_templates_cannot_bypass_escaping() -> None:
    assert "safe" not in make_templates().filters
    for tpl in TEMPLATES.glob("*.html"):
        text = tpl.read_text()
        assert all('src="/static/' in tag for tag in re.findall(r"<script\b[^>]*>", text)), tpl
        assert not re.search(r"\son[a-z]+\s*=", text), tpl


def test_security_headers(h: Harness) -> None:
    with h.client() as c:
        for path in ("/", "/wifi", "/nope"):
            r = c.get(path)
            csp = r.headers["content-security-policy"]
            assert "script-src 'self'" in csp
            assert "frame-ancestors 'none'" in csp
            assert "unsafe-inline" not in csp
            assert r.headers["strict-transport-security"].startswith("max-age=")
            assert r.headers["x-content-type-options"] == "nosniff"
            assert r.headers["referrer-policy"] == "no-referrer"


def test_rate_limit(h: Harness) -> None:
    with h.client() as c:
        assert [run_scan(c, COMCAST_V4).status_code for _ in range(4)] == [303, 303, 303, 429]
        for i in range(3):
            run_scan(c, f"2001:558::{i + 1}")
        assert run_scan(c, "2001:558::ffff").status_code == 429  # same IPv6 /64
        h.clock.t += 3601
        assert run_scan(c, COMCAST_V4).status_code == 303


async def test_concurrency_cap(tmp_path: Path) -> None:
    h = build(tmp_path, max_concurrent=1)
    h.scan.gate = asyncio.Event()
    async with h.app.router.lifespan_context(h.app), h.async_client() as c:
        tok = csrf_from(c, (await c.get("/")).text)
        first = asyncio.create_task(
            c.post("/scan", data={"csrf": tok}, headers=scan_headers(COMCAST_V4))
        )
        await asyncio.wait_for(h.scan.entered.wait(), 5)
        busy = await c.post("/scan", data={"csrf": tok}, headers=scan_headers("24.0.1.3"))
        assert busy.status_code == 503
        h.scan.gate.set()
        assert (await first).status_code == 303


def test_failed_checks_say_couldnt_check(h: Harness) -> None:
    h.reputation.result = ReputationResult(Reputation.UNKNOWN, reason="timeout")
    h.scan.error = OSError("network down")
    page = scan_page(h)
    assert card(page, "reputation")[0] == "unknown"
    assert card(page, "exposure_v4")[0] == "unknown"
    assert "some checks didn&#39;t work" in page

    h.reputation.error = RuntimeError("boom")  # an exception is also "couldn't check"
    assert card(scan_page(h, "24.0.1.9"), "reputation")[0] == "unknown"


def test_results_expire_and_never_store_raw_ip(h: Harness) -> None:
    with h.client() as c:
        loc = run_scan(c, COMCAST_V4).headers["location"]
        assert re.fullmatch(r"/r/[A-Za-z0-9_-]{22}", loc)  # 128-bit id
        page = c.get(loc).text
        assert "24.0.1.x" in page
        assert COMCAST_V4 not in page
        h.clock.t += 24 * 3600 + 1
        assert c.get(loc).status_code == 404
    rows = (
        sqlite3.connect(h.settings.results_db_path).execute("SELECT body FROM reports").fetchall()
    )
    assert all(COMCAST_V4 not in body for (body,) in rows)


def test_daily_counts_are_aggregate_only(h: Harness) -> None:
    scan_page(h)
    counts = {m: n for _, m, n in h.results.daily_counts()}
    assert counts["scans"] == 1
    rows = (
        sqlite3.connect(h.settings.results_db_path).execute("SELECT * FROM daily_counts").fetchall()
    )
    assert {len(r) for r in rows} == {3}  # day, metric, count: nothing about the visitor


# --- what the results say ------------------------------------------------------------------


def test_ipv4_and_ipv6_via_claim(h: Harness) -> None:
    with h.client() as c:
        assert (
            c.post(
                "/api/claim",
                headers={"X-Forwarded-For": COMCAST_V6, "Origin": "https://evil.example"},
            ).status_code
            == 403
        )
        claim = c.post(
            "/api/claim", headers={"X-Forwarded-For": COMCAST_V6, "Origin": ORIGIN}
        ).json()["claim"]
        page = c.get(run_scan(c, COMCAST_V4, data={"claim": claim}).headers["location"]).text
    assert sorted(h.scan.calls) == sorted([COMCAST_V4, COMCAST_V6])
    assert 'id="exposure_v6"' in page


def test_vpn_or_hosting_address_not_scanned(h: Harness) -> None:
    page = scan_page(h, "198.199.70.1")  # DigitalOcean
    assert h.scan.calls == []
    assert "VPN" in card(page, "exposure_v4")[1]


def test_quiet_router_is_reassuring_but_not_a_pass(h: Harness) -> None:
    h.scan.results[COMCAST_V4] = ExposureResult(ip_version=4, any_response=False)
    page = scan_page(h, dns_resolver="24.0.0.53")
    assert card(page, "exposure_v4")[0] == "quiet"
    assert "usually a good sign" in page
    assert "Everything we could check looks good" not in page

    page = scan_page(h, "172.58.1.1")  # T-Mobile: carrier-grade NAT
    assert "carrier-grade" in card(page, "exposure_v4")[1]


def test_all_green_only_when_everything_checked(h: Harness) -> None:
    page = scan_page(h, dns_resolver="24.0.0.53")
    assert "Everything we could check looks good" in page


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (exposure(23), "bad"),
        (exposure(7547), "bad"),
        (exposure(80), "bad"),
        (exposure(5555), "bad"),
        (exposure(ssdp=SsdpResult(responded=True)), "bad"),
        (exposure(natpmp=NatPmpResult(responded=True)), "bad"),
        (exposure(dns=DnsResolverResult(responded=True, recursion=True)), "bad"),
        (exposure(22), "warn"),
        (exposure(32400), "warn"),
    ],
)
def test_exposure_severity(h: Harness, result: ExposureResult, expected: str) -> None:
    h.scan.results[COMCAST_V4] = result
    status, body = card(scan_page(h), "exposure_v4")
    assert status == expected
    assert "How to fix" in body


@pytest.mark.parametrize(
    ("resolver", "expected"),
    [
        ("24.0.0.53", "good"),  # visitor's own ISP
        ("8.8.8.8", "quiet"),  # Google: may be the browser's secure DNS
        ("203.1.0.9", "bad"),  # unknown network: possible hijack
    ],
)
def test_dns_classification(h: Harness, resolver: str, expected: str) -> None:
    assert card(scan_page(h, dns_resolver=resolver), "dns")[0] == expected


def test_dns_resolver_on_sibling_isp_network_is_fine(h: Harness) -> None:
    # Charter customer, resolver on a TWC network: both are Spectrum.
    assert card(scan_page(h, "66.0.0.7", dns_resolver="67.0.0.53"), "dns")[0] == "good"


def test_dns_without_token_is_couldnt_check(h: Harness) -> None:
    assert card(scan_page(h), "dns")[0] == "unknown"


def test_isp_specific_help(h: Harness) -> None:
    h.scan.results[COMCAST_V4] = exposure(80, ssdp=SsdpResult(responded=True))
    body = card(scan_page(h), "exposure_v4")[1]
    assert "On your Xfinity (Comcast) router:" in body
    assert "Device Discovery" in body

    h.scan.results["8.8.4.4"] = exposure(80)  # not a known ISP
    assert 'class="isp-help"' not in scan_page(h, "8.8.4.4")


def test_history_card(h: Harness) -> None:
    h.history.result = HistoryResult(History.SEEN, ports=[8080], vulns=["CVE-2021-44228"])
    assert card(scan_page(h), "history")[0] == "bad"


def test_botnet_card_combines_greynoise_and_abuseipdb(h: Harness) -> None:
    page = scan_page(h)
    assert 'id="abuse"' not in page  # one combined card, AbuseIPDB off without a key
    assert card(page, "reputation")[0] == "good"

    # Either source flagging the address turns the card red.
    h.deps.abuse = FakeAbuse(AbuseResult(Abuse.SUSPICIOUS, score=100, reports=40, reporters=12))
    status, body = card(scan_page(h, "24.0.1.9"), "reputation")
    assert status == "bad"
    assert "40 reports from 12 reporters" in body
    assert "GreyNoise: not seen" in body

    # GreyNoise out of quota: still answered from AbuseIPDB, not "couldn't check".
    h.clock.t += 3601
    h.reputation.result = ReputationResult(Reputation.UNKNOWN, reason="rate limited")
    h.deps.abuse = FakeAbuse(AbuseResult(Abuse.NO_REPORTS))
    status, body = card(scan_page(h, "24.0.1.10"), "reputation")
    assert status == "good"
    assert "GreyNoise didn&#39;t answer, so this is based on AbuseIPDB alone." in body

    # Both down: couldn't check.
    h.deps.abuse = FakeAbuse(AbuseResult(Abuse.UNKNOWN, reason="rate limited"))
    assert card(scan_page(h, "24.0.1.11"), "reputation")[0] == "unknown"


def test_pages(h: Harness) -> None:
    with h.client() as c:
        wifi = c.get("/wifi", headers={"X-Forwarded-For": COMCAST_V4}).text
        assert "You seem to be on Xfinity (Comcast)" in wifi
        assert (
            "You seem to be on" not in c.get("/wifi", headers={"X-Forwarded-For": "8.8.4.4"}).text
        )
        how = c.get("/how-it-works").text
        assert 'id="privacy"' in how
        assert "GreyNoise and Shodan" in how
        assert c.head("/").status_code == 200
