"""What the tools say about the lab right now. Runs INSIDE the client container.

    python /app/lab/check.py route            # route_history for the server
    python /app/lab/check.py avail            # availability, last hour
    python /app/lab/check.py change           # detect_change, every probe type, lab windows
    python /app/lab/check.py all

The lab runs at seconds, not minutes, so the windows are lab-sized: the per-hop table
compares the last 90 s against everything before it, and detect_change the same. Nothing
about the tools is changed for the lab; only the arguments are.
"""
from __future__ import annotations

import sys

sys.path.insert(0, "/app")

import net_memory                                                   # noqa: E402

SERVER = "10.0.4.10"
RECENT_H = 90 / 3600.0


def route() -> str:
    return net_memory.route_history(SERVER, days=1, recent_hours=RECENT_H)


def avail() -> str:
    return net_memory.availability(hours=1.0)


def change() -> str:
    return net_memory.detect_change(SERVER, "all", recent_hours=RECENT_H, baseline_days=1)


def main() -> int:
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    parts = {"route": route, "avail": avail, "change": change}
    for k, fn in parts.items():
        if what in (k, "all"):
            print(f"### {k}\n{fn()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
