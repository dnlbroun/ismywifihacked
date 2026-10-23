"""Run the exposure scan for one ScanTarget within a fixed time budget."""

from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass

from netcheck.addrpolicy import AddressPolicy, ScanTarget
from netcheck.scan.device import DeviceParseError, parse_device_description
from netcheck.scan.models import ExposureResult, PortResult, PortState, SsdpResult, clean_text
from netcheck.scan.probes import (
    close_writer,
    dns_resolver_probe,
    http_server_header,
    natpmp_probe,
    parse_ssdp_headers,
    ssdp_msearch,
    tcp_connect,
    tls_info,
    udp_exchange,
)
from netcheck.scan.ssrf import LocationRejected, fetch_location

log = logging.getLogger(__name__)

DEFAULT_TCP_PORTS = (
    21, 22, 23, 80, 81, 443, 445, 554, 631, 1723, 1883, 3389, 5000, 5001, 5555, 5900,
    7547, 8000, 8080, 8291, 8443, 8888, 9100, 32400, 34567, 37215, 37777, 49000, 52869,
)  # fmt: skip
HTTP_PORTS = frozenset({80, 81, 631, 5000, 7547, 8000, 8080, 8888, 32400, 37215, 49000, 52869})
HTTPS_PORTS = frozenset({443, 5001, 8443})


@dataclass(frozen=True)
class ScanPlan:
    """Which ports to probe. Tests substitute ephemeral local ports."""

    tcp_ports: tuple[int, ...] = DEFAULT_TCP_PORTS
    http_ports: frozenset[int] = HTTP_PORTS
    https_ports: frozenset[int] = HTTPS_PORTS
    ssdp_port: int = 1900
    natpmp_port: int = 5351
    dns_port: int = 53
    # Zone for the open-resolver probe (dns.<DOMAIN>); None skips the probe.
    dns_probe_zone: str | None = None
    budget: float = 10.0
    connect_timeout: float = 2.5
    udp_timeout: float = 2.0
    fingerprint_timeout: float = 2.5


async def scan_exposure(
    target: ScanTarget, policy: AddressPolicy, plan: ScanPlan | None = None
) -> ExposureResult:
    plan = plan or ScanPlan()
    result = ExposureResult(ip_version=target.version)
    try:
        async with asyncio.timeout(plan.budget):
            await _scan(target, policy, plan, result)
    except TimeoutError:
        result.complete = False
    # Anything we didn't get to counts as unanswered, never as closed.
    probed = {p.port for p in result.ports}
    result.ports.extend(
        PortResult(port, PortState.FILTERED) for port in plan.tcp_ports if port not in probed
    )
    result.ports.sort(key=lambda p: p.port)
    return result


async def _scan(
    target: ScanTarget, policy: AddressPolicy, plan: ScanPlan, result: ExposureResult
) -> None:
    async def tcp(port: int) -> None:
        port_result, conn = await tcp_connect(target, port, plan.connect_timeout)
        if conn is not None:
            await close_writer(conn[1])
        if port_result.state is not PortState.FILTERED:
            result.any_response = True
        # Record before fingerprinting so an open port survives a budget timeout.
        result.ports.append(port_result)
        if port_result.state is PortState.OPEN:
            await _fingerprint(target, port_result, plan)

    async def ssdp() -> None:
        result.ssdp = await _ssdp(target, policy, plan, result)

    async def dns() -> None:
        if plan.dns_probe_zone is None:
            return
        qname = f"{secrets.token_hex(16)}.{plan.dns_probe_zone}"
        res, answered = await dns_resolver_probe(target, plan.dns_port, qname, plan.udp_timeout)
        result.dns = res
        result.any_response |= answered

    async def natpmp() -> None:
        res, answered = await natpmp_probe(target, plan.natpmp_port, plan.udp_timeout)
        result.natpmp = res
        result.any_response |= answered

    async with asyncio.TaskGroup() as tg:
        for port in plan.tcp_ports:
            tg.create_task(tcp(port))
        tg.create_task(ssdp())
        tg.create_task(natpmp())
        tg.create_task(dns())


async def _fingerprint(target: ScanTarget, port: PortResult, plan: ScanPlan) -> None:
    if port.port in plan.https_ports:
        info = await tls_info(target, port.port, plan.fingerprint_timeout)
        if info is not None:
            port.tls_subject, port.tls_issuer = info.subject, info.issuer
            port.server_header = info.server_header
    elif port.port in plan.http_ports:
        port.server_header = await http_server_header(target, port.port, plan.fingerprint_timeout)


async def _ssdp(
    target: ScanTarget, policy: AddressPolicy, plan: ScanPlan, result: ExposureResult
) -> SsdpResult:
    ex = await udp_exchange(
        target, plan.ssdp_port, ssdp_msearch(target, plan.ssdp_port), plan.udp_timeout
    )
    if ex.unreachable or ex.replies:
        result.any_response = True
    replies = [r for r in ex.replies if r.startswith(b"HTTP/1.")]
    if not replies:
        return SsdpResult(responded=False)
    headers = parse_ssdp_headers(replies[0])
    ssdp = SsdpResult(responded=True, server_header=clean_text(headers.get("server")))
    location = headers.get("location")
    if location:
        try:
            body = await fetch_location(location, target, policy)
            ssdp.device = parse_device_description(body)
        except LocationRejected as exc:
            ssdp.device_error = str(exc)
        except DeviceParseError:
            ssdp.device_error = "unreadable device description"
    return ssdp
