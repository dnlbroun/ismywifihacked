import pytest
from pydantic import ValidationError

from netcheck.config import Settings


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOMAIN", "Example.COM.")
    monkeypatch.setenv("VPS_IP", "8.9.10.11")
    s = Settings()  # type: ignore[call-arg]
    assert s.domain == "example.com"
    assert s.dns_zone == "dns.example.com"
    assert [str(a) for a in s.own_addresses] == ["8.9.10.11"]


@pytest.mark.parametrize(
    "domain", ["", "localhost", "exa mple.com", "http://example.com", "a/b.com"]
)
def test_bad_domain_rejected(monkeypatch: pytest.MonkeyPatch, domain: str) -> None:
    monkeypatch.setenv("DOMAIN", domain)
    monkeypatch.setenv("VPS_IP", "8.9.10.11")
    with pytest.raises(ValidationError):
        Settings()  # type: ignore[call-arg]


def test_private_vps_ip_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOMAIN", "example.com")
    monkeypatch.setenv("VPS_IP", "192.168.1.10")
    with pytest.raises(ValidationError):
        Settings()  # type: ignore[call-arg]
