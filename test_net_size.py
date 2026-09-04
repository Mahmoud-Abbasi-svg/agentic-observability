"""Does the sizer propose intervals that are actually safe?

    python test_net_size.py

The dangerous failure here is not a bad recommendation, it is a CONFIDENT one. The sizer writes
the collector's config, so a wrong answer degrades the monitor silently and permanently.

The specific mistake this suite exists to prevent was made on the first real run: the sizer
proposed slowing gateway reachability from 61 s to 732 s, because a metric that sits constantly
at 1.0 trivially "resolves 2%". That number is the grid floor on a degenerate signal, and
acting on it would have made a twelve-minute outage invisible - the single most basic thing the
monitor is for.

So the load-bearing test is not "does it optimise" but "does it refuse to apply the resolution
argument to a metric where resolution is not the question".

Writes only to a throwaway database.
"""
from __future__ import annotations

import math
import os
import random
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netsize_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_alert                                                     # noqa: E402
import net_size                                                      # noqa: E402
import net_store                                                     # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()["net_id"]
INTERVAL = 60


def build(target: str, metric: str, values: list[float], interval: int = INTERVAL) -> None:
    now = int(time.time())
    n = len(values)
    CONN.execute("DELETE FROM sample WHERE target=? AND metric=?", (target, metric))
    CONN.executemany(
        "INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) VALUES (?,?,?,?,?)",
        [(now - (n - i) * interval, target, metric, float(v), NET)
         for i, v in enumerate(values)])
    CONN.commit()


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def main() -> int:
    rng = random.Random(3)
    n = 900
    goal, hours, days = 0.10, 1.0, 7.0

    # A host that has never once failed - the exact shape that fooled the first version.
    build("always-up", "reachable", [1.0] * n)
    # A very quiet latency path: resolution is far better than needed, so backing off is right.
    build("quiet", "rtt_avg_ms", [20.0 * (1 + rng.gauss(0, 0.005)) for _ in range(n)])
    # A path no rate can rescue. The drift period must be LONGER than any window the history
    # can supply, otherwise a wide enough window averages the drift away and speeding up
    # genuinely is the right answer - which is what a first version of this case got wrong:
    # its 37-sample period fitted six times into the search's widest window.
    build("wild", "rtt_avg_ms",
          [20.0 * (1 + 0.4 * math.sin(i / 300.0) + rng.gauss(0, 0.02)) for i in range(n)])
    # Availability checked far too slowly to notice an outage in time.
    build("slow-http", "ok_2xx", [1.0] * 300, interval=600)

    ok = True
    res = {(r["target"], r["metric"]): r
           for r in [net_size.assess_signal(t, m, goal, hours, days)
                     for t, m in [("always-up", "reachable"), ("quiet", "rtt_avg_ms"),
                                  ("wild", "rtt_avg_ms"), ("slow-http", "ok_2xx")]]}

    a = res[("always-up", "reachable")]
    ok &= check("a never-failing host is NOT slowed on resolution grounds",
                a["family"] == "availability" and (a["suggest"] is None
                                                   or a["suggest"] <= 300),
                f"action={a['action']} suggest={a['suggest']} - {a['detail'][:60]}")
    ok &= check("availability sizing quotes detection time, not a noise floor",
                "availability" in a["detail"] and a["mde"] is None)

    s = res[("slow-http", "ok_2xx")]
    ok &= check("availability checked too slowly is sped up",
                s["action"] == "SPEED UP" and s["suggest"] is not None
                and s["suggest"] < 600,
                f"600s -> {s['suggest']}s")

    q = res[("quiet", "rtt_avg_ms")]
    ok &= check("an over-sampled quiet path backs off",
                q["action"] == "BACK OFF" and q["suggest"] > INTERVAL,
                f"{INTERVAL}s -> {q['suggest']:.0f}s, mde {q['mde'] * 100:.0f}%")
    ok &= check("backing off is stated as measured, not extrapolated",
                "thinning" in q["detail"])

    w = res[("wild", "rtt_avg_ms")]
    ok &= check("a path no rate can fix is reported UNACHIEVABLE, not sped up",
                w["action"] == "UNACHIEVABLE" and w["suggest"] is None,
                f"mde {w['mde'] * 100:.0f}%")

    # Any speed-up must carry the caveat, because it is the one branch that is not measured.
    speedups = [r for r in res.values()
                if r["action"] == "SPEED UP" and r["family"] == "continuous"]
    labelled = all("EXTRAPOLATED" in r["detail"] for r in speedups)
    ok &= check("every continuous speed-up is labelled EXTRAPOLATED",
                labelled, f"{len(speedups)} case(s)")

    # The config writer must take the SHORTEST interval any of a target's metrics needs; one
    # probe produces them all, so the most demanding metric governs.
    cfg = {"targets": [{"name": "t", "kind": "ping", "host": "quiet", "interval_s": 60}]}
    results = [{"target": "quiet", "suggest": 600.0},
               {"target": "quiet", "suggest": 120.0}]
    path = os.path.join(os.path.dirname(DB), "monitor.json")
    with open(path, "w", encoding="utf-8") as f:
        import json
        json.dump(cfg, f)
    net_size.apply_to_config(results, cfg, path)
    ok &= check("a target takes its most demanding metric's interval",
                cfg["targets"][0]["interval_s"] == 120,
                f"got {cfg['targets'][0]['interval_s']}s from suggestions 600s and 120s")

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
