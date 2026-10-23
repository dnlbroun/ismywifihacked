"""Entry point for the DNS server process: `python -m netcheck.dns`."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal

from netcheck.config import get_settings
from netcheck.dns.server import Authority, DnsServer
from netcheck.dns.tokens import TokenWriter

FLUSH_INTERVAL = 0.25
PURGE_INTERVAL = 60.0

log = logging.getLogger("netcheck.dns")


async def _run() -> None:
    settings = get_settings()
    store = TokenWriter(settings.token_db_path)
    authority = Authority(
        zone=settings.dns_zone,
        ns_host=settings.ns_host,
        ipv4=settings.vps_ip,
        ipv6=settings.vps_ipv6,
        on_token=store.record,
    )
    server = DnsServer(authority)
    await server.start(settings.dns_bind, settings.dns_port)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    last_purge = 0.0
    try:
        while not stop.is_set():
            try:
                store.flush()
                if loop.time() - last_purge >= PURGE_INTERVAL:
                    store.purge()
                    server.rrl.sweep()
                    last_purge = loop.time()
            except Exception:
                log.exception("token store maintenance failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), FLUSH_INTERVAL)
    finally:
        await server.close()
        store.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    asyncio.run(_run())


if __name__ == "__main__":
    main()
