"""Run every check for one visitor and assemble the report."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

from netcheck.addrpolicy import AddressPolicy, ScanTarget
from netcheck.asn import AsnClasses, AsnDatabase, AsnInfo
from netcheck.dns.tokens import TokenReader, is_valid_token
from netcheck.reputation.abuseipdb import AbuseResult
from netcheck.reputation.greynoise import ReputationResult
from netcheck.reputation.internetdb import HistoryResult
from netcheck.scan.models import ExposureResult
from netcheck.verdict.cards import (
    CANT_CHECK,
    DnsOutcome,
    ExposureOutcome,
    SkipReason,
    attach_isp_help,
    botnet_card,
    classify_resolver,
    dns_card,
    exposure_card,
    history_card,
    mask_ip,
)
from netcheck.verdict.content import IspContent
from netcheck.verdict.model import Report

log = logging.getLogger(__name__)

ScanFn = Callable[[ScanTarget, AddressPolicy], Awaitable[ExposureResult]]


class ReputationChecker(Protocol):
    async def check(self, target: ScanTarget) -> ReputationResult: ...


class AbuseChecker(Protocol):
    async def check(self, target: ScanTarget) -> AbuseResult: ...


class HistoryChecker(Protocol):
    async def check(self, target: ScanTarget) -> HistoryResult: ...


@dataclass
class CheckupDeps:
    asn_db: AsnDatabase
    classes: AsnClasses
    content: IspContent
    reputation: ReputationChecker
    token_reader: TokenReader
    policy: AddressPolicy
    scan: ScanFn
    history: HistoryChecker
    # Optional: only when an AbuseIPDB key is configured.
    abuse: AbuseChecker | None = None
    clock: Callable[[], float] = time.time
    dns_wait: float = 4.0
    dns_poll_interval: float = 0.25
    cant_check: list[str] = field(default_factory=lambda: list(CANT_CHECK))


def new_report_id() -> str:
    return secrets.token_urlsafe(16)  # 128 bits


async def run_checkup(
    deps: CheckupDeps, targets: list[ScanTarget], dns_token: str | None
) -> Report:
    """`targets` must be non-empty, policy-checked, and at most one per IP family."""
    targets = sorted(targets, key=lambda t: t.version)
    asn = {t.version: deps.asn_db.lookup(t.ip) for t in targets}
    primary_asn = next((a for a in asn.values() if a is not None), None)
    isp_slug = deps.classes.isp_slug(primary_asn)
    visitor_asns = {a.asn for a in asn.values() if a is not None}
    # Big ISPs run their DNS servers on sibling networks (e.g. Spectrum's regional
    # ASNs), so any ASN belonging to the visitor's own ISP counts as "your provider".
    if isp_slug != "generic":
        visitor_asns |= {n for n, slug in deps.classes.isp_by_asn.items() if slug == isp_slug}

    v4 = next((t for t in targets if t.version == 4), None)
    rep_target = v4 or targets[0]

    # Each helper catches its own failures, so one broken check can't sink the rest.
    async with asyncio.TaskGroup() as tg:
        rep_t = tg.create_task(_guard(deps.reputation.check(rep_target), "reputation"))
        hist_t = tg.create_task(_guard(deps.history.check(rep_target), "history"))
        abuse_t = (
            tg.create_task(_guard(deps.abuse.check(rep_target), "abuse"))
            if deps.abuse is not None
            else None
        )
        dns_t = tg.create_task(_dns(deps, dns_token, visitor_asns))
        exp_ts = [tg.create_task(_exposure(deps, t, asn[t.version])) for t in targets]

    cards = [
        botnet_card(
            rep_t.result(),
            abuse_t.result() if abuse_t else None,
            abuse_enabled=abuse_t is not None,
            content=deps.content,
            isp_slug=isp_slug,
        ),
        history_card(hist_t.result(), deps.content, isp_slug),
        dns_card(dns_t.result(), deps.classes, deps.content, isp_slug),
        *(exposure_card(t.result(), deps.content, isp_slug) for t in exp_ts),
    ]

    attach_isp_help(cards, deps.content, isp_slug)

    # For a recognised ISP show its friendly name plus the network name; otherwise the
    # network name from the ASN database is the best label we have.
    network_name = primary_asn.name if primary_asn else None
    isp = deps.content.isp(isp_slug)
    isp_name = isp.name
    if isp_slug == "generic" and network_name:
        isp_name, network_name = network_name, None
    return Report(
        id=new_report_id(),
        created=deps.clock(),
        addresses=[mask_ip(t.ip) for t in targets],
        isp_name=isp_name,
        network_name=network_name,
        cards=cards,
        isp_specific=bool(isp.howto),
    )


async def _guard[T](aw: Awaitable[T], name: str) -> T | None:
    try:
        return await aw
    except Exception:
        log.exception("%s check failed", name)
        return None


async def _dns(deps: CheckupDeps, token: str | None, visitor_asns: set[int]) -> DnsOutcome:
    if token is None or not is_valid_token(token):
        return DnsOutcome(token_sent=False)
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + deps.dns_wait
        while True:
            seen = await asyncio.to_thread(deps.token_reader.resolvers, token)
            if seen or loop.time() >= deadline:
                break
            await asyncio.sleep(deps.dns_poll_interval)
        return DnsOutcome(
            token_sent=True,
            resolvers=[
                classify_resolver(ip, deps.asn_db.lookup(ip), visitor_asns, deps.classes)
                for ip in seen
            ],
        )
    except Exception:
        log.exception("DNS check failed")
        return DnsOutcome(token_sent=True, error=True)


async def _exposure(deps: CheckupDeps, target: ScanTarget, info: AsnInfo | None) -> ExposureOutcome:
    cgnat_asn = info is not None and info.asn in deps.classes.cgnat
    if deps.classes.is_hosting(info):
        return ExposureOutcome(target.version, skipped=SkipReason.HOSTING, asn=info)
    try:
        result = await deps.scan(target, deps.policy)
    except Exception:
        log.exception("exposure scan failed")
        return ExposureOutcome(target.version, skipped=SkipReason.ERROR, asn=info)
    return ExposureOutcome(target.version, result=result, asn=info, cgnat_asn=cgnat_asn)
