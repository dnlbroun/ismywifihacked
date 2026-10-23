import ipaddress

import pytest
from dnslib import CLASS, EDNS0, OPCODE, QTYPE, RCODE, DNSHeader, DNSQuestion, DNSRecord

from netcheck.addrpolicy import IPAddress
from netcheck.dns.server import Authority, RateDecision, ResponseRateLimiter

ZONE = "dns.example.com"
VPS4 = ipaddress.IPv4Address("203.0.113.10")
VPS6 = ipaddress.IPv6Address("2001:db8::10")
SRC = ipaddress.IPv4Address("198.51.100.53")
TOKEN = "0123456789abcdef0123456789abcdef"


class Sink:
    def __init__(self) -> None:
        self.seen: list[tuple[str, IPAddress]] = []

    def __call__(self, token: str, src: IPAddress) -> None:
        self.seen.append((token, src))


@pytest.fixture
def sink() -> Sink:
    return Sink()


@pytest.fixture
def auth(sink: Sink) -> Authority:
    return Authority(ZONE, "ns1.example.com", VPS4, VPS6, sink)


def ask(auth: Authority, name: str, qtype: str = "A", *, rd: bool = True) -> DNSRecord:
    q = DNSRecord.question(name, qtype)
    q.header.rd = int(rd)
    raw = auth.handle(q.pack(), SRC)
    assert raw is not None
    return DNSRecord.parse(raw)


def assert_not_resolver(r: DNSRecord) -> None:
    assert r.header.qr == 1
    assert r.header.ra == 0


def test_token_a_query_answers_vps_ip_and_records(auth: Authority, sink: Sink) -> None:
    r = ask(auth, f"{TOKEN}.{ZONE}")
    assert_not_resolver(r)
    assert r.header.aa == 1
    assert r.header.rcode == RCODE.NOERROR
    assert [str(rr.rdata) for rr in r.rr] == [str(VPS4)]
    assert r.rr[0].ttl == 0
    assert sink.seen == [(TOKEN, SRC)]


def test_token_aaaa(auth: Authority) -> None:
    r = ask(auth, f"{TOKEN}.{ZONE}", "AAAA")
    assert [str(rr.rdata) for rr in r.rr] == [str(VPS6)]


def test_aaaa_without_ipv6_is_nodata(sink: Sink) -> None:
    a = Authority(ZONE, "ns1.example.com", VPS4, None, sink)
    r = ask(a, f"{TOKEN}.{ZONE}", "AAAA")
    assert r.header.rcode == RCODE.NOERROR
    assert not r.rr
    assert r.auth[0].rtype == QTYPE.SOA


def test_0x20_case_randomisation(auth: Authority, sink: Sink) -> None:
    name = f"{TOKEN.upper()}.DnS.ExAmPlE.CoM"
    r = ask(auth, name)
    assert str(r.q.qname) == name + "."  # question echoed unchanged
    assert str(r.rr[0].rname) == name + "."
    assert sink.seen == [(TOKEN, SRC)]  # stored lowercase


@pytest.mark.parametrize(
    "name",
    ["google.com", "example.com", "evil-dns.example.com", "dns.example.com.attacker.net", "com"],
)
@pytest.mark.parametrize("rd", [True, False])
def test_out_of_zone_refused_never_recursed(
    auth: Authority, sink: Sink, name: str, rd: bool
) -> None:
    r = ask(auth, name, rd=rd)
    assert_not_resolver(r)
    assert r.header.rcode == RCODE.REFUSED
    assert r.header.aa == 0
    assert not r.rr
    assert not r.auth
    assert not sink.seen


@pytest.mark.parametrize("name", [f"{TOKEN}.{ZONE}", ZONE, "google.com"])
def test_any_refused(auth: Authority, sink: Sink, name: str) -> None:
    r = ask(auth, name, "ANY")
    assert r.header.rcode == RCODE.REFUSED
    assert not r.rr
    assert not sink.seen


@pytest.mark.parametrize(
    "label",
    [
        "0123456789abcdef0123456789abcde",  # 31 chars
        "0123456789abcdef0123456789abcdef0",  # 33 chars
        "0123456789abcdef0123456789abcdeg",  # non-hex
        "x",
        "*",
        f"a.{TOKEN}",  # nested
        f"{TOKEN}.a",
    ],
)
def test_bad_token_nxdomain_not_recorded(auth: Authority, sink: Sink, label: str) -> None:
    r = ask(auth, f"{label}.{ZONE}")
    assert r.header.rcode == RCODE.NXDOMAIN
    assert r.header.aa == 1
    assert not r.rr
    assert not sink.seen


def test_apex_soa_and_ns(auth: Authority) -> None:
    soa = ask(auth, ZONE, "SOA")
    assert soa.rr[0].rtype == QTYPE.SOA
    ns = ask(auth, ZONE, "NS")
    assert str(ns.rr[0].rdata) == "ns1.example.com."
    a = ask(auth, ZONE, "A")
    assert not a.rr
    assert a.header.rcode == RCODE.NOERROR


def test_non_in_class_refused(auth: Authority) -> None:
    q = DNSRecord(DNSHeader(rd=1), q=DNSQuestion(f"{TOKEN}.{ZONE}", QTYPE.TXT, CLASS.CH))
    raw = auth.handle(q.pack(), SRC)
    assert raw is not None
    assert DNSRecord.parse(raw).header.rcode == RCODE.REFUSED


def test_non_query_opcode_notimp(auth: Authority) -> None:
    q = DNSRecord.question(f"{TOKEN}.{ZONE}")
    q.header.opcode = OPCODE.UPDATE
    raw = auth.handle(q.pack(), SRC)
    assert raw is not None
    assert DNSRecord.parse(raw).header.rcode == RCODE.NOTIMP


def test_multiple_questions_formerr(auth: Authority, sink: Sink) -> None:
    q = DNSRecord.question(f"{TOKEN}.{ZONE}")
    q.add_question(DNSQuestion("google.com"))
    raw = auth.handle(q.pack(), SRC)
    assert raw is not None
    assert DNSRecord.parse(raw).header.rcode == RCODE.FORMERR
    assert not sink.seen


@pytest.mark.parametrize(
    "data", [b"", b"\x00", b"\xff" * 12, b"\x00" * 600, b"garbage that is not dns at all"]
)
def test_garbage_dropped(auth: Authority, data: bytes) -> None:
    assert auth.handle(data, SRC) is None


def test_responses_are_dropped(auth: Authority) -> None:
    resp = DNSRecord.question("google.com").reply()
    assert auth.handle(resp.pack(), SRC) is None


def test_request_flags_not_reflected(auth: Authority) -> None:
    q = DNSRecord.question(f"{TOKEN}.{ZONE}")
    q.header.tc = 1
    q.header.ad = 1
    q.header.ra = 1
    raw = auth.handle(q.pack(), SRC)
    assert raw is not None
    r = DNSRecord.parse(raw)
    assert (r.header.tc, r.header.ad, r.header.ra) == (0, 0, 0)


def test_edns_echoed_with_bounded_size(auth: Authority) -> None:
    q = DNSRecord.question(f"{TOKEN}.{ZONE}")
    q.add_ar(EDNS0(udp_len=4096))
    raw = auth.handle(q.pack(), SRC)
    assert raw is not None
    opt = [rr for rr in DNSRecord.parse(raw).ar if rr.rtype == QTYPE.OPT]
    assert len(opt) == 1
    assert opt[0].rclass == 1232


@pytest.mark.parametrize(
    ("name", "qtype"),
    [
        (f"{TOKEN}.{ZONE}", "A"),
        (f"{TOKEN}.{ZONE}", "AAAA"),
        (f"{TOKEN}.{ZONE}", "TXT"),
        (ZONE, "SOA"),
        (ZONE, "NS"),
        ("nope.dns.example.com", "A"),
        ("google.com", "A"),
    ],
)
def test_no_amplification(auth: Authority, name: str, qtype: str) -> None:
    q = DNSRecord.question(name, qtype).pack()
    raw = auth.handle(q, SRC)
    assert raw is not None
    # Amplification factor stays small for every response type we can produce.
    assert len(raw) <= max(3 * len(q), 160)


def test_truncate_gives_empty_tc_reply(auth: Authority, sink: Sink) -> None:
    raw = auth.handle(DNSRecord.question(f"{TOKEN}.{ZONE}").pack(), SRC, truncate=True)
    assert raw is not None
    r = DNSRecord.parse(raw)
    assert r.header.tc == 1
    assert not r.rr
    assert not sink.seen


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_rate_limiter_buckets_by_prefix_and_slips() -> None:
    clock = FakeClock()
    rrl = ResponseRateLimiter(rate=1.0, burst=3.0, slip=2, clock=clock)
    a = ipaddress.IPv4Address("198.51.100.1")
    b = ipaddress.IPv4Address("198.51.100.200")  # same /24
    other = ipaddress.IPv4Address("192.0.2.1")
    assert [rrl.check(a) for _ in range(3)] == [RateDecision.SEND] * 3
    assert [rrl.check(b) for _ in range(4)] == [
        RateDecision.DROP,
        RateDecision.SLIP,
        RateDecision.DROP,
        RateDecision.SLIP,
    ]
    assert rrl.check(other) is RateDecision.SEND
    clock.t += 1.0
    assert rrl.check(a) is RateDecision.SEND


def test_rate_limiter_ipv6_uses_56() -> None:
    rrl = ResponseRateLimiter(rate=1.0, burst=1.0, slip=0, clock=FakeClock())
    assert rrl.check(ipaddress.IPv6Address("2001:db8:0:1::1")) is RateDecision.SEND
    assert rrl.check(ipaddress.IPv6Address("2001:db8:0:ff::2")) is RateDecision.DROP
    assert rrl.check(ipaddress.IPv6Address("2001:db8:0:100::1")) is RateDecision.SEND


def test_rate_limiter_table_is_bounded() -> None:
    clock = FakeClock()
    rrl = ResponseRateLimiter(rate=1.0, burst=1.0, max_entries=10, clock=clock)
    for i in range(10):
        rrl.check(ipaddress.IPv4Address(f"10.{i}.0.1"))
    assert rrl.check(ipaddress.IPv4Address("10.99.0.1")) is RateDecision.DROP
    assert len(rrl) == 10
    clock.t += 5
    assert rrl.check(ipaddress.IPv4Address("10.99.0.1")) is RateDecision.SEND
    assert len(rrl) == 1
