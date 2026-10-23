"""Runtime configuration, read from the environment (systemd EnvironmentFile in production)."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_HOSTNAME_RE = re.compile(r"^(?=.{1,200}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    # Public site domain; the DNS check uses the delegated zone dns.<domain>.
    domain: str
    # The VPS's own public addresses: answered by the DNS server and never scanned.
    vps_ip: ipaddress.IPv4Address
    vps_ipv6: ipaddress.IPv6Address | None = None

    greynoise_api_key: SecretStr | None = None
    # AbuseIPDB free-plan key; the abuse-reports check is off without one.
    abuseipdb_api_key: SecretStr | None = None

    data_dir: Path = Path("/var/lib/netcheck")
    asn_db_path: Path = Path("/var/lib/netcheck/asn/ip2asn-combined.tsv.gz")
    content_dir: Path = Path(__file__).resolve().parents[2] / "content"

    # Web app.
    web_host: str = "127.0.0.1"
    web_port: int = 8000
    max_concurrent_scans: int = 4
    scans_per_hour: int = 3

    # Authoritative DNS server (separate process).
    dns_bind: list[str] = ["0.0.0.0", "::"]  # noqa: S104 - public authoritative server
    dns_port: int = 53

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        if not _HOSTNAME_RE.match(v):
            raise ValueError("DOMAIN must be a plain hostname like example.com")
        return v

    @field_validator("vps_ip", "vps_ipv6")
    @classmethod
    def _validate_global(
        cls, v: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        if v is not None and not v.is_global:
            raise ValueError("VPS addresses must be public")
        return v

    @property
    def dns_zone(self) -> str:
        return f"dns.{self.domain}"

    @property
    def ns_host(self) -> str:
        return f"ns1.{self.domain}"

    @property
    def token_db_path(self) -> Path:
        return self.data_dir / "dns" / "tokens.db"

    @property
    def results_db_path(self) -> Path:
        return self.data_dir / "app" / "results.db"

    @property
    def origin(self) -> str:
        return f"https://{self.domain}"

    @property
    def own_addresses(self) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        return (self.vps_ip,) if self.vps_ipv6 is None else (self.vps_ip, self.vps_ipv6)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # required fields come from the environment
