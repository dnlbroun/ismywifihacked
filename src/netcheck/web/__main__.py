"""Entry point for the web app: `python -m netcheck.web`.

Runs uvicorn with its own proxy-header handling off: the app reads the client
address itself and only trusts X-Forwarded-For from the local Caddy.
"""

from __future__ import annotations

import logging

import uvicorn

from netcheck.config import get_settings
from netcheck.web.app import create_app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    # httpx logs request URLs at INFO, and the GreyNoise URL contains the visitor's IP.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    settings = get_settings()
    uvicorn.run(
        create_app(settings),
        host=settings.web_host,
        port=settings.web_port,
        proxy_headers=False,
        forwarded_allow_ips="",
        server_header=False,
        date_header=False,
        access_log=False,  # access logs would record visitor IPs
        log_level="info",
    )


if __name__ == "__main__":
    main()
