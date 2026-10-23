"""Offline IP -> ASN lookup from the iptoasn.com combined TSV (public domain, PDDL).

File format, one range per line, tab-separated:
    range_start  range_end  as_number  country_code  as_description
AS 0 means "not routed". Both IPv4 and IPv6 ranges appear in the combined file.
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import logging
from array import array
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

import yaml

from netcheck.addrpolicy import IPAddress

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class AsnInfo:
    asn: int
    country: str
    name: str


class AsnDatabase:
    def __init__(self, rows: Iterable[tuple[IPAddress, IPAddress, int, str, str]]) -> None:
        # IPv4 ranges fit in unsigned 64-bit arrays; IPv6 needs Python ints.
        v4: list[tuple[int, int, int]] = []
        v6: list[tuple[int, int, int]] = []
        self._info: dict[int, AsnInfo] = {}
        for start, end, asn, country, name in rows:
            if asn == 0 or start.version != end.version or int(end) < int(start):
                continue
            (v4 if start.version == 4 else v6).append((int(start), int(end), asn))
            if asn not in self._info:
                self._info[asn] = AsnInfo(asn, country[:8], name[:200])
        v4.sort()
        v6.sort()
        self._v4_start = array("Q", (r[0] for r in v4))
        self._v4_end = array("Q", (r[1] for r in v4))
        self._v4_asn = array("L", (r[2] for r in v4))
        self._v6_start = [r[0] for r in v6]
        self._v6_end = [r[1] for r in v6]
        self._v6_asn = array("L", (r[2] for r in v6))

    @classmethod
    def load(cls, path: Path) -> AsnDatabase:
        db = cls(_read_tsv(path))
        log.info(
            "loaded ASN database: %d IPv4 + %d IPv6 ranges", len(db._v4_start), len(db._v6_start)
        )
        return db

    def __len__(self) -> int:
        return len(self._v4_start) + len(self._v6_start)

    def lookup(self, ip: IPAddress) -> AsnInfo | None:
        if ip.version == 4:
            starts, ends, asns = self._v4_start, self._v4_end, self._v4_asn
            i = bisect.bisect_right(starts, int(ip)) - 1
        else:
            i = bisect.bisect_right(self._v6_start, int(ip)) - 1
            starts, ends, asns = self._v6_start, self._v6_end, self._v6_asn  # type: ignore[assignment]
        if i < 0 or int(ip) > ends[i]:
            return None
        return self._info.get(asns[i])


def _read_tsv(path: Path) -> Iterator[tuple[IPAddress, IPAddress, int, str, str]]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 5:
                continue
            try:
                start = ipaddress.ip_address(parts[0])
                end = ipaddress.ip_address(parts[1])
                asn = int(parts[2])
            except ValueError:
                log.debug("skipping malformed ASN row %d", lineno)
                continue
            yield start, end, asn, parts[3], parts[4]


@dataclass(frozen=True)
class AsnClasses:
    """Curated ASN groupings used by the verdict logic (content/asn_classes.yaml)."""

    cgnat: frozenset[int]
    public_resolvers: dict[int, str]
    doh_providers: frozenset[int]
    hosting: frozenset[int]
    hosting_keywords: tuple[str, ...]
    isp_by_asn: dict[int, str]

    @classmethod
    def load(cls, content_dir: Path) -> AsnClasses:
        data = yaml.safe_load((content_dir / "asn_classes.yaml").read_text(encoding="utf-8"))
        isp_by_asn: dict[int, str] = {}
        for isp_file in sorted((content_dir / "isps").glob("*.yaml")):
            isp = yaml.safe_load(isp_file.read_text(encoding="utf-8"))
            for asn in isp.get("asns") or []:
                isp_by_asn[int(asn)] = isp_file.stem
        return cls(
            cgnat=frozenset(int(a) for a in data["cgnat_asns"]),
            public_resolvers={int(k): str(v) for k, v in data["public_resolver_asns"].items()},
            doh_providers=frozenset(int(a) for a in data["browser_doh_asns"]),
            hosting=frozenset(int(a) for a in data["hosting_asns"]),
            hosting_keywords=tuple(str(k).lower() for k in data["hosting_name_keywords"]),
            isp_by_asn=isp_by_asn,
        )

    def is_hosting(self, info: AsnInfo | None) -> bool:
        if info is None:
            return False
        if info.asn in self.hosting:
            return True
        name = info.name.lower()
        return any(k in name for k in self.hosting_keywords)

    def isp_slug(self, info: AsnInfo | None) -> str:
        if info is None:
            return "generic"
        return self.isp_by_asn.get(info.asn, "generic")
