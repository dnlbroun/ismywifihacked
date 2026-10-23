"""Builds the web app with fake network dependencies. Tests never touch real hosts."""

from __future__ import annotations

import asyncio
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import httpx2
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netcheck.addrpolicy import AddressPolicy, ScanTarget
from netcheck.asn import AsnClasses, AsnDatabase
from netcheck.checkup import CheckupDeps
from netcheck.config import Settings
from netcheck.dns.tokens import TokenReader, TokenWriter
from netcheck.reputation.abuseipdb import Abuse, AbuseResult
from netcheck.reputation.greynoise import Reputation, ReputationResult
from netcheck.reputation.internetdb import History, HistoryResult
from netcheck.results import ResultStore
from netcheck.scan.models import ExposureResult, PortResult, PortState
from netcheck.verdict.content import IspContent
from netcheck.web.app import create_app
from netcheck.web.ratelimit import ClaimStore, ScanRateLimiter

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "example.com"
ORIGIN = f"https://{DOMAIN}"
VPS = ipaddress.IPv4Address("8.9.10.11")
COMCAST_V4 = "24.0.1.2"
COMCAST_V6 = "2001:558::1:2"
CADDY = ("127.0.0.1", 40000)


class Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t


@dataclass
class FakeReputation:
    result: ReputationResult = field(default_factory=lambda: ReputationResult(Reputation.CLEAN))
    error: Exception | None = None
    calls: list[str] = field(default_factory=list)

    async def check(self, target: ScanTarget) -> ReputationResult:
        self.calls.append(str(target.ip))
        if self.error:
            raise self.error
        return self.result


@dataclass
class FakeHistory:
    result: HistoryResult = field(default_factory=lambda: HistoryResult(History.NOTHING_SEEN))
    calls: list[str] = field(default_factory=list)

    async def check(self, target: ScanTarget) -> HistoryResult:
        self.calls.append(str(target.ip))
        return self.result


@dataclass
class FakeAbuse:
    result: AbuseResult = field(default_factory=lambda: AbuseResult(Abuse.NO_REPORTS))
    calls: list[str] = field(default_factory=list)

    async def check(self, target: ScanTarget) -> AbuseResult:
        self.calls.append(str(target.ip))
        return self.result


def quiet_router(version: int) -> ExposureResult:
    """Reachable (a port refused) but nothing open: a clean pass."""
    return ExposureResult(
        ip_version=version,
        ports=[PortResult(22, PortState.CLOSED), PortResult(23, PortState.FILTERED)],
        any_response=True,
    )


@dataclass
class FakeScan:
    results: dict[str, ExposureResult] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    gate: asyncio.Event | None = None
    entered: asyncio.Event = field(default_factory=asyncio.Event)
    error: Exception | None = None

    async def __call__(self, target: ScanTarget, policy: AddressPolicy) -> ExposureResult:
        self.calls.append(str(target.ip))
        self.entered.set()
        if self.gate is not None:
            await self.gate.wait()
        if self.error:
            raise self.error
        return self.results.get(str(target.ip)) or quiet_router(target.version)


@dataclass
class Harness:
    app: FastAPI
    settings: Settings
    scan: FakeScan
    reputation: FakeReputation
    tokens: TokenWriter
    clock: Clock
    results: ResultStore
    claims: ClaimStore
    deps: CheckupDeps
    history: FakeHistory

    def client(self, peer: tuple[str, int] = CADDY) -> TestClient:
        return TestClient(self.app, base_url=ORIGIN, client=peer, follow_redirects=False)

    def async_client(self, peer: tuple[str, int] = CADDY) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=self.app, client=peer)
        return httpx.AsyncClient(transport=transport, base_url=ORIGIN, follow_redirects=False)


def build(
    tmp: Path, *, max_concurrent: int = 4, dns_wait: float = 0.3, scans_per_hour: int = 3
) -> Harness:
    settings = Settings(
        domain=DOMAIN,
        vps_ip=VPS,
        data_dir=tmp,
        content_dir=ROOT / "content",
        max_concurrent_scans=max_concurrent,
        scans_per_hour=scans_per_hour,
    )
    clock = Clock()
    scan = FakeScan()
    reputation = FakeReputation()
    history = FakeHistory()
    tokens = TokenWriter(settings.token_db_path, clock=clock)
    deps = CheckupDeps(
        asn_db=AsnDatabase.load(ROOT / "tests" / "data" / "ip2asn-sample.tsv"),
        classes=AsnClasses.load(settings.content_dir),
        content=IspContent.load(settings.content_dir),
        reputation=reputation,
        token_reader=TokenReader(settings.token_db_path, clock=clock),
        policy=AddressPolicy(settings.own_addresses),
        scan=scan,
        history=history,
        clock=clock,
        dns_wait=dns_wait,
        dns_poll_interval=0.05,
    )
    results = ResultStore(settings.results_db_path, clock=clock)
    claims = ClaimStore(clock=clock)
    app = create_app(
        settings,
        deps=deps,
        results=results,
        limiter=ScanRateLimiter(limit=scans_per_hour, clock=clock),
        claims=claims,
    )
    return Harness(app, settings, scan, reputation, tokens, clock, results, claims, deps, history)


CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


def csrf_from(client: TestClient | httpx.AsyncClient, html: str) -> str:
    m = CSRF_RE.search(html)
    assert m is not None
    return m.group(1)


def scan_headers(ip: str, **extra: str) -> dict[str, str]:
    return {"X-Forwarded-For": ip, "Sec-Fetch-Site": "same-origin", "Origin": "null"} | extra


def run_scan(
    client: TestClient,
    ip: str,
    *,
    data: dict[str, str | list[str]] | None = None,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    csrf: Callable[[str], str] | None = None,
) -> httpx2.Response:
    page = client.get("/", headers={"X-Forwarded-For": ip})
    token = csrf_from(client, page.text)
    body: dict[str, str | list[str]] = {"csrf": csrf(token) if csrf else token}
    body |= data or {}
    return client.post("/scan", data=body, headers=headers or scan_headers(ip), params=params)
