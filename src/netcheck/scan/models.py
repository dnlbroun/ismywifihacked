"""Scan result types. Every string that came off the network has been through
`clean_text()` and is still untrusted: templates must escape it."""

from __future__ import annotations

import enum
import unicodedata
from dataclasses import dataclass, field

MAX_FIELD_LEN = 128


def clean_text(value: str | bytes | None, limit: int = MAX_FIELD_LEN) -> str | None:
    """Normalise an untrusted network string: decode, drop control characters, truncate."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    out = "".join(
        " " if ch in "\t\r\n" else ch
        for ch in value
        if ch in "\t\r\n" or unicodedata.category(ch)[0] != "C"
    )
    out = " ".join(out.split())[:limit]
    return out or None


class PortState(enum.Enum):
    OPEN = "open"
    CLOSED = "closed"  # connection refused: host reachable, nothing listening
    FILTERED = "filtered"  # no answer


@dataclass
class PortResult:
    port: int
    state: PortState
    server_header: str | None = None
    tls_subject: str | None = None
    tls_issuer: str | None = None


@dataclass
class DeviceInfo:
    manufacturer: str | None = None
    model: str | None = None
    firmware: str | None = None


@dataclass
class SsdpResult:
    responded: bool = False
    server_header: str | None = None
    device: DeviceInfo | None = None
    # Why we couldn't read the device description, if we tried and failed.
    device_error: str | None = None


@dataclass
class NatPmpResult:
    responded: bool = False


@dataclass
class DnsResolverResult:
    responded: bool = False  # something answered DNS on port 53
    recursion: bool = False  # ...and it looked up an outside name for us (open resolver)


@dataclass
class ExposureResult:
    ip_version: int
    ports: list[PortResult] = field(default_factory=list)
    ssdp: SsdpResult | None = None
    natpmp: NatPmpResult | None = None
    dns: DnsResolverResult | None = None
    # Any sign the address is reachable at all: an open/refused TCP port, a UDP
    # reply, or an ICMP unreachable from the target.
    any_response: bool = False
    # False if the time budget ran out before every probe finished.
    complete: bool = True

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state is PortState.OPEN]
