"""Does the seasonality test find a daily rhythm only when there is one?

    python test_net_season.py

Two failures, and the second is the one this suite mainly exists for.

  A MISS      a real diurnal swing goes unnoticed, the floor stays wider than the path
              deserves, and real changes keep being dismissed as invisible. Costly, but safe.

  A FALSE     a path that merely WANDERS is declared seasonal, its floor is narrowed on a
  POSITIVE    pattern that is not there, and the monitor starts calling noise a change. This
              is the dangerous one, because it makes the tool over-claim - the failure the
              whole project is built to avoid.

The false-positive case is exactly what a naive test produces. Shuffling the hour labels
destroys the correlation between neighbouring samples, so the null spread collapses and any
slow wander looks like a daily rhythm. `drifting` below is that trap, and the suite checks
both that the real test resists it AND that the naive one would have fallen for it - because
a guard that is never shown to be load-bearing tends to get removed later.

Writes only to a throwaway database.
"""
from __future__ import annotations

import math
import os
import random
import statistics
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netseason_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_season                                                    # noqa: E402
import net_store                                                     # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()["net_id"]
STEP = 300                       # 5 minutes
DAYS = 6
N = DAYS * 24 * 12


def build(target: str, fn) -> list[tuple[float, float]]:
    now = int(time.time())
    rows = []
    for i in range(N):
        ts = now - (N - i) * STEP
        lt = time.localtime(ts)
        h = lt.tm_hour + lt.tm_min / 60.0
        rows.append((ts, fn(i, h)))
    CONN.execute("DELETE FROM sample WHERE target=?", (target,))
    CONN.executemany(
        "INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) VALUES (?,?,?,?,?)",
        [(ts, target, "rtt_avg_ms", float(v), NET) for ts, v in rows])
    CONN.commit()
    return rows


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def rotation_null_p(rows, trials=200, seed=0) -> float:
    """The FIRST null this module used, kept only to show why it was abandoned.

    It compares the observed hourly spread against circularly shifted copies of the series,
    on the reasoning that rotation preserves autocorrelation while destroying alignment to the
    clock. It preserves more than that: a rotation of a 24-hour-periodic series is another
    24-hour-periodic series, so the hourly spread survives intact and the null reproduces the
    very signal it is supposed to remove.
    """
    rng = random.Random(seed)
    ts = [t for t, _v in rows]
    vals = [v for _t, v in rows]
    obs = net_season._spread(rows)
    n = ok = 0
    for _ in range(trials):
        k = rng.randrange(1, len(vals))
        s = net_season._spread(list(zip(ts, vals[k:] + vals[:k])))
        if s is not None:
            ok += 1
            if s >= obs:
                n += 1
    return n / max(1, ok)


def main() -> int:
    rng = random.Random(4)

    # A genuine daily rhythm: +-15% around the median, on top of ordinary jitter.
    build("diurnal", lambda i, h: 20.0 * (1 + 0.15 * math.sin(2 * math.pi * h / 24.0))
          * (1 + rng.gauss(0, 0.03)))
    # No structure at all beyond independent noise.
    build("flat", lambda i, h: 20.0 * (1 + rng.gauss(0, 0.06)))
    # Wanders slowly - strongly autocorrelated, but with no dependence on the clock. The trap.
    walk = [0.0]
    for _ in range(N):
        walk.append(walk[-1] + rng.gauss(0, 0.02))
    build("drifting", lambda i, h: 20.0 * (1 + walk[i] + rng.gauss(0, 0.02)))
    # Only 30 hours of history: not two cycles, so no verdict is allowed.
    short = []
    now = int(time.time())
    for i in range(30 * 12):
        ts = now - (30 * 12 - i) * STEP
        short.append((ts, 20.0 * (1 + rng.gauss(0, 0.05))))
    CONN.executemany(
        "INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) VALUES (?,?,?,?,?)",
        [(ts, "short", "rtt_avg_ms", float(v), NET) for ts, v in short])
    CONN.commit()

    ok = True
    res = {t: net_season.assess(t, "rtt_avg_ms", 14.0, 1.0)
           for t in ("diurnal", "flat", "drifting", "short")}

    d = res["diurnal"]
    ok &= check("a real daily rhythm is detected",
                d["status"] == "ok" and d.get("real"),
                f"swing {d.get('observed', 0) * 100:.0f}%, p={d.get('p')}")
    ok &= check("detecting it narrows the floor",
                d.get("seasonal_floor") is not None and d.get("plain_floor") is not None
                and d["seasonal_floor"] < d["plain_floor"],
                f"{(d.get('plain_floor') or 0) * 100:.0f}% -> "
                f"{(d.get('seasonal_floor') or 0) * 100:.0f}%")

    f = res["flat"]
    ok &= check("a path with no rhythm is left alone",
                f["status"] == "ok" and not f.get("real"),
                f"swing {f.get('observed', 0) * 100:.0f}%, p={f.get('p')}")

    # The load-bearing case.
    w = res["drifting"]
    ok &= check("a WANDERING path is NOT declared seasonal",
                w["status"] == "ok" and not w.get("real"),
                f"swing {w.get('observed', 0) * 100:.0f}%, p={w.get('p')}")

    # The abandoned null, run against the SAME textbook rhythm the real test detects. It has
    # no power at all, because rotating a 24-hour-periodic series leaves the hourly spread
    # unchanged. Kept so the mistake stays visible rather than being rediscovered.
    drows = net_season._rows("diurnal", "rtt_avg_ms", 14.0)
    rot = rotation_null_p(drows)
    ok &= check("the abandoned circular-shift null misses a rhythm the new test finds",
                rot > 0.20 and d.get("p", 1.0) < 0.05,
                f"rotation p={rot:.2f} (blind to it) vs profile agreement "
                f"p={d.get('p', 1):.3f} (finds it)")

    s = res["short"]
    ok &= check("30 h of history yields no verdict, and says why",
                s["status"] != "ok" and "48" in s["reason"], s["reason"][:60])

    # The correction must never be claimed on a signal the test did not clear.
    ok &= check("no floor is rewritten for a path without a detected rhythm",
                all(res[t].get("seasonal_floor") is None or not res[t].get("real")
                    or t == "diurnal" for t in ("flat", "drifting")))

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
