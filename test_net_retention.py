"""What does the tool still know after raw samples are deleted?

    python test_net_retention.py

Raw samples live for net_store.RAW_RETENTION_DAYS and are then rolled into hourly rows kept
for a year. Until this suite existed, nothing read those rows: `baseline`, `detect_change`,
`can_detect`, the seasonality test and the sizer all queried `sample` alone. So the day the
first prune ran, the tool would have answered

    "No history for '1.1.1.1' on this network in the last 90 days"

with ninety days of it summarised in the same file. That is a false statement about its own
knowledge, and it is the same class of error as reporting a change that did not happen.

Two properties are asserted here, and they pull in opposite directions on purpose.

  REMEMBER    a question about the pre-horizon period must be answered from the rolled-up
              rows, not denied. Forgetting silently is the failure this suite was written for.

  DO NOT      no floor, no change verdict and no sizing may be computed from those rows. An
  OVER-CLAIM  hourly mean of ~12 samples varies far less than the samples do, so a placebo
              floor calibrated on them comes out too narrow and the tool would announce it
              could resolve shifts it cannot see. The last check measures that gap rather than
              asserting it: it computes the floor both ways and requires the aggregate one to
              be visibly, quantifiably narrower.

Writes only to a throwaway database.
"""
from __future__ import annotations

import os
import random
import statistics
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netretain_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_memory                                                    # noqa: E402
import net_size                                                      # noqa: E402
import net_store                                                     # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()["net_id"]
STEP = 300                                    # 5 minutes
RAW_DAYS = net_store.RAW_RETENTION_DAYS
TARGET = "1.1.1.1"
METRIC = "rtt_avg_ms"


def check(name: str, ok, detail: str = "") -> bool:
    # bool(), not the value: callers pass expressions like `a and b and c`, which
    # yield the last truthy operand rather than True. Suites accumulate with
    # `ok &= check(...)`, and `True & 6` is 0 - so every check printed PASS while the
    # suite reported failure. It can only raise a false alarm, never hide a real one,
    # but a suite that cries wolf gets ignored like any other.
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def build() -> None:
    """40 days of history: the oldest 26 will be pruned, the newest 14 will survive as raw."""
    rng = random.Random(11)
    now = int(time.time()) // 3600 * 3600
    rows = []
    for i in range(40 * 24 * 12):
        ts = now - (40 * 24 * 12 - i) * STEP
        rows.append((ts, 20.0 * (1 + rng.gauss(0, 0.08))))
    CONN.executemany(
        "INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) VALUES (?,?,?,?,?)",
        [(ts, TARGET, METRIC, float(v), NET) for ts, v in rows])
    CONN.commit()


def main() -> int:
    build()
    before = CONN.execute("SELECT COUNT(*) FROM sample").fetchone()[0]

    # Everything below the horizon must be visible as raw BEFORE the prune, so that any
    # difference afterwards is caused by the prune and not by a window that was always short.
    pre = net_memory.baseline(TARGET, METRIC, days=40)
    ok = check("before pruning, 40 days of raw history is reported",
               "spanning" in pre and "rolled up" not in pre,
               pre.splitlines()[0][-46:])

    res = net_store.aggregate_and_prune(CONN)
    after = CONN.execute("SELECT COUNT(*) FROM sample").fetchone()[0]
    hourly = CONN.execute("SELECT COUNT(*) FROM sample_hourly").fetchone()[0]
    ok &= check("pruning drops old raw rows and keeps hourly ones",
                res["raw_rows_dropped"] > 0 and after < before and hourly > 0,
                f"{before} -> {after} raw, {hourly} hourly")

    # ---------------------------------------------------------------- REMEMBER
    b40 = net_memory.baseline(TARGET, METRIC, days=40)
    ok &= check("a 40-day question still reports the pre-horizon period",
                "rolled up" in b40 and f"older than {RAW_DAYS:g} days" in b40,
                [l.strip() for l in b40.splitlines() if "rolled up" in l][0][:64])
    ok &= check("and says the older figures are summaries, not measurements",
                "hourly summaries, not measurements" in b40)
    ok &= check("a 14-day question is unchanged - no rolled-up rows inside the raw window",
                "rolled up" not in net_memory.baseline(TARGET, METRIC, days=RAW_DAYS))

    # The exact false statement this suite exists to prevent. A target whose raw samples have
    # all expired must not be reported as unknown.
    CONN.execute("DELETE FROM sample WHERE target=?", (TARGET,))
    CONN.commit()
    gone = net_memory.baseline(TARGET, METRIC, days=40)
    ok &= check("with every raw sample expired it does NOT claim to have no history",
                "No history" not in gone and "rolled up" in gone,
                gone.splitlines()[0][:60])
    ok &= check("listing targets mentions the ones that survive only as summaries",
                f"Older than {RAW_DAYS:g} days" in net_memory.baseline(days=40))

    # ------------------------------------------------------------- DO NOT OVER-CLAIM
    dc = net_memory.detect_change(TARGET, METRIC, baseline_days=40)
    ok &= check("change detection refuses, and distinguishes expiry from never having data",
                "hourly summaries" in dc and "cannot be used to test for a change" in dc,
                dc.split(". ")[0][:58])

    build()                                     # restore raw samples for the horizon checks
    cd = net_memory.can_detect(TARGET, METRIC, shift_pct=10.0, baseline_days=40)
    ok &= check("can_detect states its horizon instead of silently shortening the window",
                "HORIZON" in cd and f"used the last {RAW_DAYS:g} days" in cd)
    ok &= check("can_detect asked inside the horizon says nothing about it",
                "HORIZON" not in net_memory.can_detect(TARGET, METRIC, baseline_days=7))
    ok &= check("the sizer caps its own window rather than trusting the argument",
                len(net_size._series(TARGET, METRIC, 40)[0])
                == len(net_size._series(TARGET, METRIC, RAW_DAYS)[0]))

    # Why the split is not merely tidy: measure the over-claim it prevents. Same data, floor
    # computed from raw samples and from hourly means of those same samples.
    rows, _net = net_memory._rows(TARGET, RAW_DAYS, METRIC)
    raw_vals = [float(v) for _ts, _m, v in rows]
    by_hour: dict[int, list[float]] = {}
    for ts, _m, v in rows:
        by_hour.setdefault(int(ts) // 3600, []).append(float(v))
    hourly_vals = [statistics.mean(v) for _h, v in sorted(by_hour.items())]
    k = 12
    raw_mde, _c, _n, _r = net_memory._mde_for_window(raw_vals, k)
    agg_mde, _c2, _n2, _r2 = net_memory._mde_for_window(hourly_vals, k)
    ok &= check("a floor calibrated on hourly means WOULD have been narrower than the truth",
                raw_mde is not None and agg_mde is not None and agg_mde < raw_mde,
                f"raw {raw_mde and raw_mde * 100:.0f}% vs aggregated "
                f"{agg_mde and agg_mde * 100:.0f}% - the gap is the over-claim avoided")

    # The rename, checked on a database that already had the old names.
    old = os.path.join(tempfile.mkdtemp(prefix="netold_"), "old.db")
    import sqlite3
    c2 = sqlite3.connect(old)
    c2.execute("CREATE TABLE sample_hourly (hour INTEGER, target TEXT, metric TEXT, "
               "net_id TEXT, median REAL, p05 REAL, p95 REAL, n INTEGER)")
    c2.execute("INSERT INTO sample_hourly VALUES (3600,'x','m','net',1.5,1.0,2.0,7)")
    c2.commit()
    c2.close()
    c3 = net_store.connect(old)
    cols = [r[1] for r in c3.execute("PRAGMA table_info(sample_hourly)")]
    row = c3.execute("SELECT mean, lo, hi, n FROM sample_hourly").fetchone()
    ok &= check("an existing database is migrated to the honest column names, data intact",
                "median" not in cols and "mean" in cols and row == (1.5, 1.0, 2.0, 7),
                ", ".join(cols[4:]))

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
