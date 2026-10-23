"""The report shown on the results page. Stored as JSON for 24h.

`headline` and `steps` are text we wrote. `facts` may contain strings that came off
the network (banners, certificate names, ASN names): templates escape everything,
and nothing here is ever marked safe.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Status(enum.StrEnum):
    GOOD = "good"
    WARN = "warn"
    BAD = "bad"
    # We were kept out, which is usually what a protected network looks like.
    # Reassuring, but still never presented as a pass.
    QUIET = "quiet"
    UNKNOWN = "unknown"  # couldn't check: never presented as a pass


_RANK = {Status.GOOD: 0, Status.QUIET: 1, Status.UNKNOWN: 2, Status.WARN: 3, Status.BAD: 4}


@dataclass
class Card:
    key: str
    title: str
    status: Status
    headline: str
    facts: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    note: str | None = None
    label: str | None = None  # overrides the default status label on the pill
    fix_keys: list[str] = field(default_factory=list)  # which generic fixes apply
    isp_help: list[str] = field(default_factory=list)  # "On your <ISP> router:" steps
    isp_name: str | None = None


@dataclass
class Report:
    id: str
    created: float
    addresses: list[str]  # masked, e.g. "203.0.113.x"
    isp_name: str
    network_name: str | None
    cards: list[Card]

    @property
    def overall(self) -> Status:
        return max((c.status for c in self.cards), key=_RANK.__getitem__, default=Status.UNKNOWN)

    @property
    def overall_headline(self) -> str:
        statuses = {c.status for c in self.cards}
        if Status.BAD in statuses:
            return "We found problems you should fix."
        if Status.WARN in statuses:
            return "Nothing urgent, but a few things are worth a look."
        if Status.UNKNOWN in statuses or not statuses:
            return "We didn't find problems, but some checks didn't work (see below)."
        if Status.QUIET in statuses:
            return (
                "We didn't find anything wrong. Your network kept us out, which is "
                "usually a good sign."
            )
        return "Everything we could check looks good."

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Report:
        cards = [Card(**(c | {"status": Status(c["status"])})) for c in data["cards"]]
        return cls(**(data | {"cards": cards}))
