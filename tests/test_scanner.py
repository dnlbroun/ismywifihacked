"""Exposure scan end-to-end against local listeners on 127.0.0.1."""

import asyncio
import socket
import struct
from pathlib import Path

import pytest

from netcheck.addrpolicy import AddressPolicy
from netcheck.scan.models import PortState
from netcheck.scan.runner import ScanPlan, scan_exposure
from tests.netfixtures import (
    DEVICE_XML,
    LOCALHOST,
    HttpServer,
    free_port,
    http_response,
    self_signed_ctx,
    udp_responder,
)

POLICY = AddressPolicy([], allow_loopback=True)
XSS = '<script>alert("x")</script>'


def ssdp_reply(location: str) -> bytes:
    return (
        "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=120\r\n"
        f"LOCATION: {location}\r\n"
        f"SERVER: Linux/3.4 UPnP/1.0 {XSS}\r\n"
        "ST: upnp:rootdevice\r\n\r\n"
    ).encode()


async def test_full_scan(tmp_path: Path) -> None:
    web = await HttpServer(
        lambda: http_response(b"", headers={"Server": f"lighttpd\r\x07 {XSS}"})
    ).start()
    tls = await HttpServer(
        lambda: http_response(b"", headers={"Server": "mini_httpd"}),
        ssl_ctx=self_signed_ctx(tmp_path, f"router{XSS}", "ACME"),
    ).start()
    desc = await HttpServer(lambda: http_response(DEVICE_XML)).start()
    ssdp_t, ssdp, ssdp_port = await udp_responder(
        lambda d: (
            ssdp_reply(f"http://127.0.0.1:{desc.port}/rootDesc.xml")
            if d.startswith(b"M-SEARCH")
            else None
        )
    )
    nat_t, _, nat_port = await udp_responder(
        lambda d: struct.pack("!BBHI4s", 0, 128, 0, 1234, socket.inet_aton("1.2.3.4"))
    )
    closed = free_port()
    try:
        plan = ScanPlan(
            tcp_ports=(web.port, tls.port, closed),
            http_ports=frozenset({web.port}),
            https_ports=frozenset({tls.port}),
            ssdp_port=ssdp_port,
            natpmp_port=nat_port,
            budget=8,
        )
        res = await scan_exposure(POLICY.check(LOCALHOST), POLICY, plan)
    finally:
        for s in (web, tls, desc):
            await s.close()
        ssdp_t.close()
        nat_t.close()

    assert res.complete
    assert res.any_response
    by_port = {p.port: p for p in res.ports}
    assert by_port[web.port].state is PortState.OPEN
    assert by_port[closed].state is PortState.CLOSED
    # Untrusted strings are cleaned (control chars gone) but not HTML-escaped here.
    assert by_port[web.port].server_header == f"lighttpd {XSS}"
    assert by_port[tls.port].tls_subject == f"CN=router{XSS}, O=ACME"
    assert by_port[tls.port].server_header == "mini_httpd"
    assert res.ssdp is not None
    assert res.ssdp.responded
    assert res.ssdp.server_header == f"Linux/3.4 UPnP/1.0 {XSS}"
    assert res.ssdp.device is not None
    assert res.ssdp.device.model == "WR-1000 v2"
    assert res.natpmp is not None
    assert res.natpmp.responded
    assert ssdp.received[0].startswith(b"M-SEARCH * HTTP/1.1\r\n")


async def test_ssdp_offhost_location_not_fetched() -> None:
    desc = await HttpServer(lambda: http_response(DEVICE_XML)).start()
    ssdp_t, _, ssdp_port = await udp_responder(
        lambda d: ssdp_reply(f"http://169.254.169.254:{desc.port}/latest/meta-data/")
    )
    try:
        plan = ScanPlan(tcp_ports=(), ssdp_port=ssdp_port, natpmp_port=free_port(socket.SOCK_DGRAM))
        res = await scan_exposure(POLICY.check(LOCALHOST), POLICY, plan)
    finally:
        await desc.close()
        ssdp_t.close()
    assert res.ssdp is not None
    assert res.ssdp.responded
    assert res.ssdp.device is None
    assert res.ssdp.device_error == "off-host"
    assert desc.hits == 0


async def test_nothing_listening() -> None:
    plan = ScanPlan(
        tcp_ports=(free_port(), free_port()),
        ssdp_port=free_port(socket.SOCK_DGRAM),
        natpmp_port=free_port(socket.SOCK_DGRAM),
        udp_timeout=0.5,
    )
    res = await scan_exposure(POLICY.check(LOCALHOST), POLICY, plan)
    assert not res.open_ports
    assert res.ssdp is not None
    assert not res.ssdp.responded
    assert res.natpmp is not None
    assert not res.natpmp.responded
    # Loopback refuses connections, so the host is "reachable"; on the internet a
    # firewalled router gives no answer at all and any_response stays False.
    assert all(p.state is PortState.CLOSED for p in res.ports)


async def test_budget_timeout_keeps_open_ports_and_marks_incomplete() -> None:
    hang = await HttpServer(lambda: http_response(b""), delay=2.5).start()
    try:
        plan = ScanPlan(
            tcp_ports=(hang.port,),
            http_ports=frozenset({hang.port}),
            ssdp_port=free_port(socket.SOCK_DGRAM),
            natpmp_port=free_port(socket.SOCK_DGRAM),
            budget=1.0,
            fingerprint_timeout=5,
        )
        loop = asyncio.get_running_loop()
        start = loop.time()
        res = await scan_exposure(POLICY.check(LOCALHOST), POLICY, plan)
        assert loop.time() - start < 2
    finally:
        await hang.close()
    assert not res.complete
    assert [p.state for p in res.ports] == [PortState.OPEN]


async def test_unprobed_ports_reported_filtered_not_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def hang(*args: object) -> None:
        await asyncio.sleep(10)

    monkeypatch.setattr("netcheck.scan.runner.tcp_connect", hang)
    plan = ScanPlan(
        tcp_ports=(free_port(), free_port()),
        ssdp_port=free_port(socket.SOCK_DGRAM),
        natpmp_port=free_port(socket.SOCK_DGRAM),
        budget=0.2,
    )
    res = await scan_exposure(POLICY.check(LOCALHOST), POLICY, plan)
    assert not res.complete
    assert [p.state for p in res.ports] == [PortState.FILTERED, PortState.FILTERED]


def test_production_policy_cannot_target_loopback() -> None:
    from netcheck.addrpolicy import RefusedAddress

    with pytest.raises(RefusedAddress):
        AddressPolicy([]).check(LOCALHOST)


async def test_open_resolver_detected() -> None:
    from dnslib import QTYPE, RR, A, DNSRecord

    def resolver(data: bytes) -> bytes:
        q = DNSRecord.parse(data)
        assert q.header.rd == 1
        assert str(q.q.qname).endswith(".dns.example.com.")
        r = q.reply()
        r.add_answer(RR(q.q.qname, QTYPE.A, rdata=A("203.0.113.10"), ttl=0))
        return bytes(r.pack())

    t, _, port = await udp_responder(resolver)
    try:
        plan = ScanPlan(
            tcp_ports=(),
            ssdp_port=free_port(socket.SOCK_DGRAM),
            natpmp_port=free_port(socket.SOCK_DGRAM),
            dns_port=port,
            dns_probe_zone="dns.example.com",
        )
        res = await scan_exposure(POLICY.check(LOCALHOST), POLICY, plan)
    finally:
        t.close()
    assert res.dns is not None
    assert res.dns.responded
    assert res.dns.recursion


@pytest.mark.parametrize(
    ("reply", "responded"),
    [
        ("refused", True),
        ("garbage", False),
        ("wrong-id", False),
    ],
)
async def test_non_recursive_dns(reply: str, responded: bool) -> None:
    from dnslib import RCODE, DNSRecord

    def answer(data: bytes) -> bytes:
        q = DNSRecord.parse(data)
        if reply == "garbage":
            return b"not dns at all"
        r = q.reply()
        if reply == "wrong-id":
            r.header.id = (q.header.id + 1) % 65536
        r.header.rcode = RCODE.REFUSED
        return bytes(r.pack())

    t, _, port = await udp_responder(answer)
    try:
        plan = ScanPlan(
            tcp_ports=(),
            ssdp_port=free_port(socket.SOCK_DGRAM),
            natpmp_port=free_port(socket.SOCK_DGRAM),
            dns_port=port,
            dns_probe_zone="dns.example.com",
        )
        res = await scan_exposure(POLICY.check(LOCALHOST), POLICY, plan)
    finally:
        t.close()
    assert res.dns is not None
    assert res.dns.responded is responded
    assert not res.dns.recursion
    assert res.any_response  # a reply of any kind shows the host is reachable


async def test_dns_probe_skipped_without_zone() -> None:
    plan = ScanPlan(
        tcp_ports=(),
        ssdp_port=free_port(socket.SOCK_DGRAM),
        natpmp_port=free_port(socket.SOCK_DGRAM),
        udp_timeout=0.3,
    )
    res = await scan_exposure(POLICY.check(LOCALHOST), POLICY, plan)
    assert res.dns is None
