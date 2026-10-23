"""FastAPI application: landing page, scan endpoint, results, DNS-check polling."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import jinja2
from fastapi import FastAPI, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles

from netcheck.addrpolicy import AddressPolicy, RefusalReason, RefusedAddress, ScanTarget
from netcheck.asn import AsnClasses, AsnDatabase
from netcheck.checkup import CheckupDeps, run_checkup
from netcheck.config import Settings
from netcheck.dns.tokens import TokenReader, is_valid_token
from netcheck.reputation.abuseipdb import AbuseIpDbClient
from netcheck.reputation.greynoise import GreyNoiseClient
from netcheck.reputation.internetdb import InternetDbClient
from netcheck.results import ResultStore
from netcheck.scan.runner import ScanPlan, scan_exposure
from netcheck.verdict.cards import CANT_CHECK
from netcheck.verdict.content import Isp, IspContent
from netcheck.web.ratelimit import ClaimStore, ScanRateLimiter
from netcheck.web.security import (
    CSRF_COOKIE,
    CSRF_FIELD,
    ClientIpError,
    SecurityHeadersMiddleware,
    build_csp,
    client_ip,
    csrf_ok,
    new_csrf_token,
    same_origin,
)

log = logging.getLogger(__name__)

HERE = Path(__file__).parent
CHECKUP_TIMEOUT = 25.0
PURGE_INTERVAL = 600.0
STATUS_LABELS = {
    "good": "Looks good",
    "warn": "Worth a look",
    "bad": "Fix this",
    "quiet": "Nothing visible",
    "unknown": "Couldn't check",
}


def make_templates() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(HERE / "templates"),
        autoescape=True,
        undefined=jinja2.StrictUndefined,
    )
    # Nothing we render may bypass escaping: a template using |safe fails to compile.
    del env.filters["safe"]
    env.globals["status_labels"] = STATUS_LABELS
    env.globals["cant_check"] = CANT_CHECK
    return env


class Closeable(Protocol):
    async def aclose(self) -> None: ...


@dataclass
class AppState:
    settings: Settings
    deps: CheckupDeps
    results: ResultStore
    limiter: ScanRateLimiter
    claims: ClaimStore
    slots: asyncio.Semaphore
    templates: jinja2.Environment


def production_deps(settings: Settings) -> tuple[CheckupDeps, list[Closeable]]:
    greynoise = GreyNoiseClient(settings.greynoise_api_key)
    history = InternetDbClient()
    abuse = AbuseIpDbClient(settings.abuseipdb_api_key) if settings.abuseipdb_api_key else None
    plan = ScanPlan(dns_probe_zone=settings.dns_zone)
    deps = CheckupDeps(
        asn_db=AsnDatabase.load(settings.asn_db_path),
        classes=AsnClasses.load(settings.content_dir),
        content=IspContent.load(settings.content_dir),
        reputation=greynoise,
        token_reader=TokenReader(settings.token_db_path),
        policy=AddressPolicy(settings.own_addresses),
        scan=functools.partial(scan_exposure, plan=plan),
        history=history,
        abuse=abuse,
    )
    return deps, [greynoise, history, *([abuse] if abuse else [])]


def create_app(
    settings: Settings,
    *,
    deps: CheckupDeps | None = None,
    results: ResultStore | None = None,
    limiter: ScanRateLimiter | None = None,
    claims: ClaimStore | None = None,
) -> FastAPI:
    holder: dict[str, AppState] = {}

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        closeables: list[Closeable] = []
        if deps is None:
            d, closeables = await asyncio.to_thread(production_deps, settings)
        else:
            d = deps
        holder["s"] = AppState(
            settings=settings,
            deps=d,
            results=ResultStore(settings.results_db_path) if results is None else results,
            limiter=(
                ScanRateLimiter(limit=settings.scans_per_hour) if limiter is None else limiter
            ),
            claims=ClaimStore() if claims is None else claims,
            slots=asyncio.Semaphore(settings.max_concurrent_scans),
            templates=make_templates(),
        )
        holder["s"].templates.globals["supported_isps"] = d.content.supported_names()
        lookups = ["GreyNoise", "Shodan"] + (["AbuseIPDB"] if d.abuse is not None else [])
        holder["s"].templates.globals["lookup_services"] = (
            ", ".join(lookups[:-1]) + " and " + lookups[-1]
        )
        purger = asyncio.create_task(_purge_loop(holder["s"]))
        try:
            yield
        finally:
            purger.cancel()
            for c in closeables:
                await c.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware, csp=build_csp(settings.domain))
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def state() -> AppState:
        return holder["s"]

    def render(name: str, status: int = 200, **ctx: Any) -> HTMLResponse:
        html = state().templates.get_template(name).render(domain=settings.domain, **ctx)
        return HTMLResponse(html, status_code=status, headers={"Cache-Control": "no-store"})

    def visitor_isp(request: Request) -> Isp | None:
        """The visitor's ISP, if we have router how-tos for it. The address is looked
        up in memory only, never stored or logged."""
        try:
            ip = client_ip(request)
        except ClientIpError:
            return None
        deps = state().deps
        isp = deps.content.isp(deps.classes.isp_slug(deps.asn_db.lookup(ip)))
        return isp if isp.howto else None

    def error(status: int, title: str, message: str) -> HTMLResponse:
        return render("error.html", status, title=title, message=message)

    def refused(reason: RefusalReason) -> HTMLResponse:
        if reason is RefusalReason.CGNAT:
            return error(
                200,
                "We can't see your router",
                "Your provider shares one internet address among many customers (carrier-grade "
                "NAT), so your router isn't reachable from the internet and we can't test it. "
                "That's generally good for security, but it isn't a pass.",
            )
        return error(
            400,
            "We can't check this connection",
            "You're connecting from an address we can't scan.",
        )

    @app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        token = request.cookies.get(CSRF_COOKIE) or new_csrf_token()
        resp = render(
            "index.html",
            isp=visitor_isp(request),
            csrf=token,
            dns_zone=settings.dns_zone,
            v4_host=f"v4.{settings.domain}",
            v6_host=f"v6.{settings.domain}",
        )
        resp.set_cookie(CSRF_COOKIE, token, secure=True, httponly=True, samesite="strict", path="/")
        return resp

    @app.api_route("/wifi", methods=["GET", "HEAD"], response_class=HTMLResponse)
    async def wifi_guide(request: Request) -> HTMLResponse:
        return render("wifi.html", isp=visitor_isp(request))

    @app.api_route("/how-it-works", methods=["GET", "HEAD"], response_class=HTMLResponse)
    async def how_it_works() -> HTMLResponse:
        return render("how.html")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        return FileResponse(HERE / "static" / "apple-touch-icon.png", media_type="image/png")

    @app.post("/api/claim")
    async def claim(request: Request) -> JSONResponse:
        # Called cross-origin from our own page on the v4./v6. hosts. It's a CORS
        # "simple request", so the Origin check is what keeps other sites out.
        if request.headers.get("origin") != settings.origin:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cors = {
            "Access-Control-Allow-Origin": settings.origin,
            "Vary": "Origin",
            "Cache-Control": "no-store",
        }
        try:
            target = state().deps.policy.check(client_ip(request))
        except (ClientIpError, RefusedAddress):
            return JSONResponse({"claim": None}, headers=cors)
        return JSONResponse({"claim": state().claims.issue(target)}, headers=cors)

    @app.get("/api/dns/{token}")
    def dns_status(token: str) -> JSONResponse:
        # Only say whether the lookup arrived; which resolver it came from is
        # classified server-side when the report is built.
        if not is_valid_token(token):
            return JSONResponse({"error": "not found"}, status_code=404)
        seen = bool(state().deps.token_reader.resolvers(token))
        return JSONResponse({"seen": seen}, headers={"Cache-Control": "no-store"})

    @app.post("/scan", response_model=None)
    async def scan(request: Request) -> Response:
        s = state()
        if not same_origin(request, settings.origin):
            return error(403, "Request blocked", "Please start the check from our home page.")
        form = await request.form(max_files=0, max_fields=8, max_part_size=1024)
        if not csrf_ok(request, form.get(CSRF_FIELD)):
            return error(
                403,
                "Request blocked",
                "Your session expired. Go back to the home page and try again.",
            )

        # The target is the connecting address. Nothing in the request body, query
        # string or headers (other than our own proxy's) can change it.
        try:
            primary = s.deps.policy.check(client_ip(request))
        except ClientIpError:
            log.error("could not determine client address")
            return error(
                500, "Something went wrong", "We couldn't tell where you're connecting from."
            )
        except RefusedAddress as exc:
            return refused(exc.reason)

        if not s.limiter.allowed(primary.ip):
            return error(
                429,
                "Slow down a little",
                f"You can run {s.limiter.limit} checks per hour. Please try again later.",
            )
        if s.slots.locked():
            return error(
                503,
                "We're busy",
                "Lots of people are running checks right now. Try again in a minute.",
            )
        targets = [primary, *_redeem_claims(s, form.getlist("claim"), primary)]
        for t in targets:
            s.limiter.record(t.ip)

        token = form.get("dns_token")
        dns_token = token if isinstance(token, str) and is_valid_token(token) else None
        async with s.slots:
            try:
                async with asyncio.timeout(CHECKUP_TIMEOUT):
                    report = await run_checkup(s.deps, targets, dns_token)
            except Exception:
                log.exception("checkup failed")
                return error(
                    500,
                    "Something went wrong",
                    "The check didn't finish. Please try again in a few minutes.",
                )
        await asyncio.to_thread(s.results.save, report)
        await asyncio.to_thread(s.results.count_report, report)
        return RedirectResponse(f"/r/{report.id}", status_code=303)

    @app.api_route("/r/{report_id}", methods=["GET", "HEAD"], response_class=HTMLResponse)
    async def result(report_id: str) -> HTMLResponse:
        report = await asyncio.to_thread(state().results.get, report_id)
        if report is None:
            return error(
                404,
                "Result not found",
                "Results are deleted after 24 hours. You can run a new check.",
            )
        return render("result.html", report=report)

    @app.exception_handler(404)
    async def not_found(request: Request, exc: Exception) -> HTMLResponse:
        return error(404, "Page not found", "There's nothing here.")

    return app


def _redeem_claims(s: AppState, raw_claims: list[Any], primary: ScanTarget) -> list[ScanTarget]:
    """Add the visitor's other-family address, proven by a claim from the v4./v6. host."""
    extra: dict[int, ScanTarget] = {}
    for raw in raw_claims[:2]:
        if not isinstance(raw, str) or len(raw) > 64:
            continue
        t = s.claims.redeem(raw)
        if t is None or t.version == primary.version or t.version in extra:
            continue
        if s.deps.policy.is_allowed(t.ip) and s.limiter.allowed(t.ip):
            extra[t.version] = t
    return list(extra.values())


async def _purge_loop(s: AppState) -> None:
    while True:
        await asyncio.sleep(PURGE_INTERVAL)
        try:
            await asyncio.to_thread(s.results.purge)
            s.limiter.purge()
            s.claims.purge()
        except Exception:
            log.exception("purge failed")
