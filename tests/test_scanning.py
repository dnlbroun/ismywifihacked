"""Scan targeting, SSRF guard, device XML, and the scanner against local listeners."""

import socket
import struct
from pathlib import Path

import pytest
from dnslib import QTYPE, RR, A, DNSRecord

from netcheck.addrpolicy import AddressPolicy, RefusalReason, RefusedAddress, ScanTarget
from netcheck.scan.device import DeviceParseError, parse_device_description
from netcheck.scan.models import PortState
from netcheck.scan.runner import ScanPlan, scan_exposure
from netcheck.scan.ssrf import LocationRejected, fetch_location, validate_location
from tests.netfixtures import (
    DEVICE_XML,
    LOCALHOST,
    HttpServer,
    free_port,
    http_response,
    self_signed_ctx,
    udp_responder,
)

POLICY = AddressPolicy([], allow_loopback=True)  # tests only: lets us scan 127.0.0.1
LOCAL = POLICY.check(LOCALHOST)


# --- who may be scanned ------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("10.0.0.5", RefusalReason.NOT_PUBLIC),
        ("192.168.1.1", RefusalReason.NOT_PUBLIC),
        ("169.254.169.254", RefusalReason.NOT_PUBLIC),  # cloud metadata
        ("fd00::1", RefusalReason.NOT_PUBLIC),
        ("::ffff:192.168.1.1", RefusalReason.NOT_PUBLIC),  # private IPv4 hidden in IPv6
        ("2002:a00:1::1", RefusalReason.NOT_PUBLIC),  # 6to4 wrapping 10.0.0.1
        ("100.72.1.2", RefusalReason.CGNAT),
        ("8.9.10.11", RefusalReason.OWN_ADDRESS),
        ("example.com", RefusalReason.INVALID),
    ],
)
def test_policy_refuses(raw: str, reason: RefusalReason) -> None:
    with pytest.raises(RefusedAddress) as exc:
        AddressPolicy([AddressPolicy([]).check("8.9.10.11").ip]).check(raw)
    assert exc.value.reason is reason


def test_policy_allows_public_and_test_switch_is_narrow() -> None:
    assert str(AddressPolicy([]).check("2001:558::1").ip) == "2001:558::1"
    assert not AddressPolicy([]).is_allowed("127.0.0.1")
    assert not POLICY.is_allowed("10.0.0.1")  # the loopback switch opens nothing else
    with pytest.raises(TypeError):
        ScanTarget(LOCAL.ip, object())  # targets can't be forged


# --- SSRF guard on the SSDP LOCATION header ------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.2/desc.xml",  # off-host
        "http://169.254.169.254/latest/meta-data/",  # private / metadata
        "http://localhost/desc.xml",  # hostname
        "http://2130706433/desc.xml",  # IP in disguise
        "http://evil.example@127.0.0.1/desc.xml",  # userinfo trick
        "https://127.0.0.1/desc.xml",
        "file:///etc/passwd",
        "http://127.0.0.1/desc.xml\r\nHost: evil",
    ],
)
def test_ssrf_rejects(url: str) -> None:
    with pytest.raises(LocationRejected):
        validate_location(url, LOCAL, POLICY)


def test_ssrf_rechecks_production_policy() -> None:
    with pytest.raises(LocationRejected):
        validate_location("http://127.0.0.1/desc.xml", LOCAL, AddressPolicy([]))


async def test_ssrf_no_redirects_and_size_cap() -> None:
    target = await HttpServer(lambda: http_response(DEVICE_XML)).start()
    redirect = await HttpServer(
        lambda: http_response(
            b"", status="302 Found", headers={"Location": f"http://127.0.0.1:{target.port}/"}
        )
    ).start()
    huge = await HttpServer(lambda: http_response(b"x" * 70_000, content_length=False)).start()
    try:
        with pytest.raises(LocationRejected, match="302"):
            await fetch_location(f"http://127.0.0.1:{redirect.port}/", LOCAL, POLICY)
        assert target.hits == 0
        with pytest.raises(LocationRejected, match="too large"):
            await fetch_location(f"http://127.0.0.1:{huge.port}/", LOCAL, POLICY)
        assert await fetch_location(f"http://127.0.0.1:{target.port}/", LOCAL, POLICY) == DEVICE_XML
    finally:
        for s in (target, redirect, huge):
            await s.close()


# --- device description XML ----------------------------------------------------------


def test_device_xml_whitelist_only() -> None:
    d = parse_device_description(DEVICE_XML)
    assert (d.manufacturer, d.model, d.firmware) == ("ACME Networks", "WR-1000 v2", "1.2.3")


@pytest.mark.parametrize(
    "xml",
    [
        b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><root><device>&x;</device></root>',
        b'<!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]><root><device>&b;</device></root>',
    ],
)
def test_device_xml_blocks_xxe_and_entity_bombs(xml: bytes) -> None:
    with pytest.raises(DeviceParseError):
        parse_device_description(xml)


# --- the scanner end to end ----------------------------------------------------------


async def test_full_scan_against_local_listeners(tmp_path: Path) -> None:
    xss = "<script>x</script>"
    web = await HttpServer(
        lambda: http_response(b"", headers={"Server": f"lighttpd\r\x07{xss}"})
    ).start()
    tls = await HttpServer(
        lambda: http_response(b""), ssl_ctx=self_signed_ctx(tmp_path, "router", "ACME")
    ).start()
    desc = await HttpServer(lambda: http_response(DEVICE_XML)).start()
    ssdp_reply = (
        f"HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:{desc.port}/d.xml\r\nST: upnp:rootdevice\r\n\r\n"
    ).encode()
    ssdp_t, _, ssdp_port = await udp_responder(lambda d: ssdp_reply)
    nat_t, _, nat_port = await udp_responder(
        lambda d: struct.pack("!BBHI4s", 0, 128, 0, 1, socket.inet_aton("1.2.3.4"))
    )

    def open_resolver(data: bytes) -> bytes:
        q = DNSRecord.parse(data)
        r = q.reply()
        r.add_answer(RR(q.q.qname, QTYPE.A, rdata=A("203.0.113.10")))
        return bytes(r.pack())

    dns_t, _, dns_port = await udp_responder(open_resolver)
    closed = free_port()
    try:
        res = await scan_exposure(
            LOCAL,
            POLICY,
            ScanPlan(
                tcp_ports=(web.port, tls.port, closed),
                http_ports=frozenset({web.port}),
                https_ports=frozenset({tls.port}),
                ssdp_port=ssdp_port,
                natpmp_port=nat_port,
                dns_port=dns_port,
                dns_probe_zone="dns.example.com",
            ),
        )
    finally:
        for s in (web, tls, desc):
            await s.close()
        for t in (ssdp_t, nat_t, dns_t):
            t.close()

    states = {p.port: p for p in res.ports}
    assert states[web.port].state is PortState.OPEN
    assert states[closed].state is PortState.CLOSED
    assert states[web.port].server_header == f"lighttpd {xss}"  # control chars stripped
    assert states[tls.port].tls_subject == "CN=router, O=ACME"
    assert res.ssdp is not None and res.ssdp.device is not None  # noqa: PT018
    assert res.ssdp.device.model == "WR-1000 v2"
    assert res.natpmp is not None and res.natpmp.responded  # noqa: PT018
    assert res.dns is not None and res.dns.recursion  # noqa: PT018
    assert res.complete


async def test_scan_timeout_never_reports_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    async def hang(*args: object) -> None:
        await asyncio.sleep(10)

    monkeypatch.setattr("netcheck.scan.runner.tcp_connect", hang)
    plan = ScanPlan(
        tcp_ports=(free_port(),),
        ssdp_port=free_port(socket.SOCK_DGRAM),
        natpmp_port=free_port(socket.SOCK_DGRAM),
        budget=0.2,
    )
    res = await scan_exposure(LOCAL, POLICY, plan)
    assert not res.complete
    assert [p.state for p in res.ports] == [PortState.FILTERED]
