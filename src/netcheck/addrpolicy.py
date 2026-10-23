"""The single gate deciding which addresses may be scanned.

Every scanner entry point takes a `ScanTarget`, and the only way to obtain one is
`AddressPolicy.check()`. Production code builds the policy with `allow_loopback=False`;
tests pass `allow_loopback=True` explicitly so they can scan local listeners. There is
deliberately no environment variable or setting that turns loopback on.
"""

from __future__ import annotations

import enum
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

CGNAT_NET = ipaddress.IPv4Network("100.64.0.0/10")

# Explicit deny list on top of `is_global`, so behaviour doesn't depend on the exact
# Python patch release's idea of "global".
_DENY_NETS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local, includes cloud metadata 169.254.169.254
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",  # IPv4-mapped (we unwrap these before checking)
        "64:ff9b::/96",  # NAT64: can embed a private IPv4 address
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",  # Teredo
        "2001:db8::/32",
        "2002::/16",  # 6to4: can embed a private IPv4 address
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
)


class RefusalReason(enum.Enum):
    INVALID = "invalid"
    CGNAT = "cgnat"
    NOT_PUBLIC = "not_public"
    OWN_ADDRESS = "own_address"


class RefusedAddress(Exception):
    def __init__(self, reason: RefusalReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


_POLICY_KEY = object()


@dataclass(frozen=True)
class ScanTarget:
    """An address that passed the policy. Construct only via `AddressPolicy.check()`."""

    ip: IPAddress
    _key: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._key is not _POLICY_KEY:
            raise TypeError("ScanTarget must come from AddressPolicy.check()")

    @property
    def version(self) -> int:
        return self.ip.version


def parse_ip(raw: str) -> IPAddress:
    """Parse an IP literal strictly: no hostnames, zone IDs, or whitespace.

    IPv4-mapped IPv6 addresses are unwrapped to their IPv4 form.
    """
    if not raw or raw != raw.strip() or "%" in raw:
        raise RefusedAddress(RefusalReason.INVALID)
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        raise RefusedAddress(RefusalReason.INVALID) from None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


class AddressPolicy:
    def __init__(self, own_addresses: Iterable[IPAddress], *, allow_loopback: bool = False) -> None:
        self._own = frozenset(own_addresses)
        self._allow_loopback = allow_loopback

    def check(self, raw: str | IPAddress) -> ScanTarget:
        ip = parse_ip(raw) if isinstance(raw, str) else parse_ip(str(raw))
        if ip in self._own:
            raise RefusedAddress(RefusalReason.OWN_ADDRESS)
        if self._allow_loopback and ip.is_loopback:
            return ScanTarget(ip, _POLICY_KEY)
        if ip in CGNAT_NET:
            raise RefusedAddress(RefusalReason.CGNAT)
        if not ip.is_global or any(ip in net for net in _DENY_NETS if net.version == ip.version):
            raise RefusedAddress(RefusalReason.NOT_PUBLIC)
        return ScanTarget(ip, _POLICY_KEY)

    def is_allowed(self, raw: str | IPAddress) -> bool:
        try:
            self.check(raw)
        except RefusedAddress:
            return False
        return True
