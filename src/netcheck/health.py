"""Hourly server health check with ntfy alerts: `python -m netcheck.health`.

Alerts once when a problem appears and once when it clears (state is kept in a
small JSON file), so a long outage doesn't send a notification every hour.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import httpx
from pydantic import SecretStr

from netcheck.addrpolicy import AddressPolicy
from netcheck.reputation.abuseipdb import AbuseIpDbClient

SERVICES = ("netcheck-web", "netcheck-dns", "caddy")
FULL = 0.85
ASN_MAX_AGE_DAYS = 21

Check = Callable[[], str | None]  # returns a problem description, or None if fine


def services() -> str | None:
    down = [
        s
        for s in SERVICES
        if subprocess.run(  # noqa: S603 - fixed arguments
            ["/bin/systemctl", "is-active", "--quiet", s], check=False
        ).returncode
    ]
    return f"service down: {', '.join(down)}" if down else None


def disk() -> str | None:
    usage = shutil.disk_usage("/")
    st = os.statvfs("/")
    inodes = 1 - st.f_ffree / st.f_files if st.f_files else 0.0
    if usage.used / usage.total >= FULL or inodes >= FULL:
        return f"disk {usage.used / usage.total:.0%} full, inodes {inodes:.0%} used"
    return None


def web() -> str | None:
    try:
        r = httpx.get("http://127.0.0.1:8000/", timeout=5)
    except httpx.HTTPError as exc:
        return f"web app not answering ({type(exc).__name__})"
    return None if r.status_code == 200 else f"web app returned HTTP {r.status_code}"


def asn_db(path: Path) -> Check:
    def check() -> str | None:
        if not path.exists():
            return "ASN database missing"
        age = (time.time() - path.stat().st_mtime) / 86400
        return f"ASN database is {age:.0f} days old" if age > ASN_MAX_AGE_DAYS else None

    return check


def abuseipdb(key: str) -> Check:
    def check() -> str | None:
        async def run() -> str | None:
            client = AbuseIpDbClient(SecretStr(key))
            try:
                result = await client.check(AddressPolicy([]).check("1.1.1.1"))
            finally:
                await client.aclose()
            if result.reason in ("auth failed", "rate limited"):
                return f"AbuseIPDB lookups failing ({result.reason})"
            return None

        return asyncio.run(run())

    return check


def run_checks(
    checks: dict[str, Check],
    state_path: Path,
    notify: Callable[[str, str], None],
) -> dict[str, str]:
    """Run the checks, notify about new and cleared problems, return current problems."""
    try:
        previous: dict[str, str] = json.loads(state_path.read_text())
    except (OSError, ValueError):
        previous = {}
    current: dict[str, str] = {}
    for name, check in checks.items():
        try:
            problem = check()
        except Exception as exc:
            problem = f"check crashed ({type(exc).__name__})"
        if problem:
            current[name] = problem

    for name, problem in current.items():
        if name not in previous:
            notify("ismywifihacked.com problem", problem)
    for name in previous.keys() - current.keys():
        notify("ismywifihacked.com recovered", f"{name} is OK again")

    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(current))
    return current


def ntfy(topic: str) -> Callable[[str, str], None]:
    def send(title: str, message: str) -> None:
        httpx.post(
            f"https://ntfy.sh/{topic}", content=message, headers={"Title": title}, timeout=10
        )

    return send


def main() -> None:
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        raise SystemExit("NTFY_TOPIC is not set")
    data_dir = Path(os.environ.get("DATA_DIR", "/var/lib/netcheck"))
    checks: dict[str, Check] = {
        "services": services,
        "disk": disk,
        "web": web,
        "asn_db": asn_db(data_dir / "asn" / "ip2asn-combined.tsv.gz"),
    }
    if key := os.environ.get("ABUSEIPDB_API_KEY"):
        checks["abuseipdb"] = abuseipdb(key)
    problems = run_checks(checks, data_dir / "health" / "state.json", ntfy(topic))
    print(json.dumps(problems) if problems else "ok")


if __name__ == "__main__":
    main()
