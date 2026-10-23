"""Fix-step content from content/isps/*.yaml, with generic.yaml as the fallback."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Isp:
    slug: str
    name: str
    steps: dict[str, list[str]]


class IspContent:
    def __init__(self, isps: dict[str, Isp]) -> None:
        if "generic" not in isps:
            raise ValueError("content/isps/generic.yaml is required")
        self._isps = isps
        self.generic = isps["generic"]
        missing = [k for isp in isps.values() for k in isp.steps if k not in self.generic.steps]
        if missing:
            raise ValueError(f"ISP steps without a generic fallback: {sorted(set(missing))}")

    @classmethod
    def load(cls, content_dir: Path) -> IspContent:
        isps: dict[str, Isp] = {}
        for f in sorted((content_dir / "isps").glob("*.yaml")):
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            steps = {str(k): [str(s) for s in v] for k, v in (data.get("steps") or {}).items() if v}
            isps[f.stem] = Isp(slug=f.stem, name=str(data["name"]), steps=steps)
        return cls(isps)

    def isp(self, slug: str) -> Isp:
        return self._isps.get(slug, self.generic)

    def steps(self, slug: str, key: str) -> list[str]:
        isp = self.isp(slug)
        return isp.steps.get(key) or self.generic.steps.get(key, [])
