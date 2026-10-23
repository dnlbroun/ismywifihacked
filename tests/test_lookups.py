"""Third-party lookups (GreyNoise, AbuseIPDB, Shodan) and the offline ASN database."""

import ipaddress
from pathlib import Path

import httpx
import pytest
import respx
from pydantic import SecretStr

from netcheck.addrpolicy import AddressPolicy
from netcheck.asn import AsnClasses, AsnDatabase
from netcheck.reputation.abuseipdb import Abuse, AbuseIpDbClient
from netcheck.reputation.greynoise import GreyNoiseClient, Reputation
from netcheck.reputation.internetdb import History, InternetDbClient
from netcheck.verdict.content import IspContent

IP = "24.0.1.2"
TARGET = AddressPolicy([]).check(IP)
ROOT = Path(__file__).resolve().parents[1]


# --- GreyNoise -------------------------------------------------------------------------

GN = f"https://gn.test/v3/community/{IP}"


@pytest.mark.parametrize(
    ("status", "body", "verdict"),
    [
        (404, {"ip": IP, "noise": False, "riot": False, "message": "not observed"}, Reputation.CLEAN),
        (200, {"ip": IP, "noise": True, "riot": False, "classification": "malicious"}, Reputation.SUSPICIOUS),
        (200, {"ip": IP, "noise": False, "riot": True, "classification": "benign"}, Reputation.BUSINESS_OR_VPN),
    ],
)  # fmt: skip
@respx.mock
async def test_greynoise_verdicts(
    status: int, body: dict[str, object], verdict: Reputation
) -> None:
    respx.get(GN).respond(status, json=body)
    c = GreyNoiseClient(base_url="https://gn.test")
    assert (await c.check(TARGET)).verdict is verdict
    await c.aclose()


@pytest.mark.parametrize(
    "mock",
    [
        {"status_code": 500},
        {"status_code": 429},
        {"status_code": 200, "text": "not json"},
        {"status_code": 200, "json": {"ip": "1.1.1.1", "noise": False, "riot": False}},
    ],
)
@respx.mock
async def test_greynoise_failures_are_couldnt_check(mock: dict[str, object]) -> None:
    respx.get(GN).respond(**mock)  # type: ignore[arg-type]
    c = GreyNoiseClient(base_url="https://gn.test", timeout=0.5)
    assert (await c.check(TARGET)).verdict is Reputation.UNKNOWN  # never "clean"
    respx.get(GN).mock(side_effect=httpx.ReadTimeout)
    assert (await c.check(TARGET)).verdict is Reputation.UNKNOWN
    await c.aclose()


# --- AbuseIPDB -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "score", "reports", "verdict"),
    [
        (200, 0, 0, Abuse.NO_REPORTS),
        (200, 0, 102, Abuse.NO_REPORTS),  # real case: well-known service, rated 0/100
        (200, 5, 2, Abuse.LOW_CONFIDENCE),
        (200, 100, 40, Abuse.SUSPICIOUS),
        (429, 0, 0, Abuse.UNKNOWN),
    ],
)
@respx.mock
async def test_abuseipdb(status: int, score: int, reports: int, verdict: Abuse) -> None:
    body = {"data": {"ipAddress": IP, "abuseConfidenceScore": score, "totalReports": reports}}
    route = respx.get("https://ab.test/api/v2/check").respond(status, json=body)
    c = AbuseIpDbClient(SecretStr("k"), base_url="https://ab.test")
    assert (await c.check(TARGET)).verdict is verdict
    assert route.calls.last.request.headers["key"] == "k"
    await c.aclose()


# --- Shodan InternetDB -----------------------------------------------------------------


@respx.mock
async def test_internetdb() -> None:
    url = f"https://idb.test/{IP}"
    c = InternetDbClient(base_url="https://idb.test")
    respx.get(url).respond(404, json={"detail": "No information available"})
    assert (await c.check(TARGET)).verdict is History.NOTHING_SEEN
    respx.get(url).respond(
        200, json={"ip": IP, "ports": [80, "x"], "vulns": ["CVE-2021-44228", "<b>"], "tags": []}
    )
    r = await c.check(TARGET)
    assert (r.verdict, r.ports, r.vulns) == (History.SEEN, [80], ["CVE-2021-44228"])
    respx.get(url).respond(500)
    assert (await c.check(TARGET)).verdict is History.UNKNOWN
    await c.aclose()


# --- ASN database and content -------------------------------------------------------------


def test_asn_lookup_and_classes() -> None:
    db = AsnDatabase.load(ROOT / "tests" / "data" / "ip2asn-sample.tsv.gz")
    classes = AsnClasses.load(ROOT / "content")
    comcast = db.lookup(ipaddress.ip_address("2001:558::1"))
    assert comcast is not None
    assert classes.isp_slug(comcast) == "xfinity"
    assert db.lookup(ipaddress.ip_address("45.0.0.1")) is None  # unrouted
    assert classes.is_hosting(db.lookup(ipaddress.ip_address("198.199.70.1")))  # DigitalOcean


def test_isp_content_is_sourced() -> None:
    content = IspContent.load(ROOT / "content")
    for slug in ("xfinity", "verizon_fios", "spectrum", "optimum", "att"):
        isp = content.isp(slug)
        assert isp.howto, slug
        assert isp.sources, slug  # every ISP-specific instruction cites a source
