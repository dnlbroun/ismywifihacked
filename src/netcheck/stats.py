"""Print daily result counts: `python -m netcheck.stats [days]`.

On the server, run it as the app user so SQLite files keep the right owner:
    sudo -u netcheck-web /opt/netcheck/app/.venv/bin/python -m netcheck.stats
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict
from pathlib import Path

from netcheck.results import ResultStore


def main() -> None:
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 14
    data_dir = Path(os.environ.get("DATA_DIR", "/var/lib/netcheck"))
    store = ResultStore(data_dir / "app" / "results.db")
    by_day: dict[str, dict[str, int]] = defaultdict(dict)
    for day, metric, n in store.daily_counts(days):
        by_day[day][metric] = n
    for day, metrics in sorted(by_day.items()):
        scans = metrics.pop("scans", 0)
        print(f"{day}  scans={scans}")
        for metric, n in sorted(metrics.items()):
            pct = f"{100 * n / scans:5.1f}%" if scans else ""
            print(f"    {metric:<28} {n:>6} {pct}")


if __name__ == "__main__":
    main()
