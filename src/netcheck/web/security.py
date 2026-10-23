"""Client IP, CSRF and response-header handling."""

from __future__ import annotations

import hmac
import ipaddress
import secrets

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from netcheck.addrpolicy import IPAddress

# Caddy runs on the same host and is the only thing allowed to set the client IP.
TRUSTED_PROXIES = frozenset({ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")})
CSRF_COOKIE = "__Host-csrf"
CSRF_FIELD = "csrf"


class ClientIpError(Exception):
    pass


def _parse(raw: str) -> IPAddress:
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise ClientIpError("unparseable client address") from None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def client_ip(request: Request) -> IPAddress:
    """The visitor's address, computed only from the connection and our proxy.

    If the TCP peer is our local Caddy, use the rightmost X-Forwarded-For entry (the
    one Caddy itself wrote; Caddy is configured to overwrite the header). Any other
    peer is used directly and every forwarding header is ignored.
    """
    if request.client is None:
        raise ClientIpError("no peer address")
    peer = _parse(request.client.host)
    if peer not in TRUSTED_PROXIES:
        return peer
    xff = request.headers.getlist("x-forwarded-for")
    if not xff:
        raise ClientIpError("proxy did not send X-Forwarded-For")
    return _parse(xff[-1].split(",")[-1])


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_ok(request: Request, form_token: object) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE)
    if not cookie or not isinstance(form_token, str) or len(form_token) > 128:
        return False
    return hmac.compare_digest(cookie.encode(), form_token.encode())


def same_origin(request: Request, origin: str) -> bool:
    """Reject cross-site POSTs using the headers browsers send regardless of referrer policy.

    With Referrer-Policy: no-referrer, browsers send `Origin: null` on same-origin form
    POSTs, so Origin alone can't prove anything. We reject if Sec-Fetch-Site says the
    request is cross-site or if a real Origin names another site. The double-submit
    CSRF token (checked separately) is the control that has to pass every time.
    """
    site = request.headers.get("sec-fetch-site")
    if site is not None and site != "same-origin":
        return False
    sent = request.headers.get("origin")
    return sent is None or sent == "null" or sent == origin


def build_csp(domain: str) -> str:
    return "; ".join(
        [
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self'",
            f"connect-src 'self' https://v4.{domain} https://v6.{domain} https://*.dns.{domain}",
            "form-action 'self'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
        ]
    )


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, csp: str) -> None:
        self.app = app
        self.headers = {
            "Content-Security-Policy": csp,
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-site",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
        }

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for k, v in self.headers.items():
                    headers.setdefault(k, v)
            await send(message)

        await self.app(scope, receive, send_with_headers)
