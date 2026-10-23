import ipaddress
from pathlib import Path

import pytest

from netcheck.asn import AsnClasses, AsnDatabase

DATA = Path(__file__).parent / "data"
CONTENT = Path(__file__).resolve().parents[1] / "content"


@pytest.fixture(scope="module", params=["ip2asn-sample.tsv", "ip2asn-sample.tsv.gz"])
def db(request: pytest.FixtureRequest) -> AsnDatabase:
    return AsnDatabase.load(DATA / request.param)


@pytest.fixture(scope="module")
def classes() -> AsnClasses:
    return AsnClasses.load(CONTENT)


@pytest.mark.parametrize(
    ("ip", "asn"),
    [
        ("1.0.0.0", 13335),
        ("1.0.0.255", 13335),
        ("8.8.8.8", 15169),
        ("24.0.200.1", 7922),
        ("2001:558::1", 7922),
        ("2606:4700::1111", 13335),
    ],
)
def test_lookup_hits(db: AsnDatabase, ip: str, asn: int) -> None:
    info = db.lookup(ipaddress.ip_address(ip))
    assert info is not None
    assert info.asn == asn


@pytest.mark.parametrize("ip", ["0.255.255.255", "1.0.1.0", "45.0.0.10", "9.9.9.9", "::2"])
def test_lookup_misses_gaps_and_unrouted(db: AsnDatabase, ip: str) -> None:
    assert db.lookup(ipaddress.ip_address(ip)) is None


def test_malformed_rows_skipped(db: AsnDatabase) -> None:
    # 12 rows in the fixture: one malformed, one AS0.
    assert len(db) == 10


def test_isp_detection(db: AsnDatabase, classes: AsnClasses) -> None:
    assert classes.isp_slug(db.lookup(ipaddress.ip_address("24.0.0.1"))) == "xfinity"
    assert classes.isp_slug(db.lookup(ipaddress.ip_address("8.8.8.8"))) == "generic"
    assert classes.isp_slug(None) == "generic"


def test_cgnat_and_hosting(db: AsnDatabase, classes: AsnClasses) -> None:
    tmobile = db.lookup(ipaddress.ip_address("172.58.1.1"))
    assert tmobile is not None
    assert tmobile.asn in classes.cgnat
    assert classes.is_hosting(db.lookup(ipaddress.ip_address("198.199.70.1")))
    # keyword match on the AS description
    assert classes.is_hosting(db.lookup(ipaddress.ip_address("203.1.0.5")))
    assert not classes.is_hosting(db.lookup(ipaddress.ip_address("24.0.0.1")))


def test_every_isp_file_has_required_keys(classes: AsnClasses) -> None:
    import yaml

    generic = yaml.safe_load((CONTENT / "isps" / "generic.yaml").read_text())
    for f in (CONTENT / "isps").glob("*.yaml"):
        data = yaml.safe_load(f.read_text())
        assert isinstance(data["name"], str)
        assert isinstance(data["asns"], list)
        assert isinstance(data["steps"], dict)
        # ISP files may only override keys that exist in the generic fallback.
        assert set(data["steps"]) <= set(generic["steps"])
