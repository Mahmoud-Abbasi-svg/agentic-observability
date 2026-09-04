"""Look inside the monitor's database without writing SQL - or with it, if you want to.

    python net_db.py                          what tables exist and how big they are
    python net_db.py tables                   same
    python net_db.py recent                   the last 20 measurements
    python net_db.py recent 1.1.1.1           ...for one target
    python net_db.py targets                  every target, metric, count and time span
    python net_db.py series 1.1.1.1 rtt_avg_ms       the raw numbers, newest last
    python net_db.py hours 1.1.1.1 rtt_avg_ms        median per hour - the shape of a day
    python net_db.py nets                     networks seen, and how much data each has
    python net_db.py sql "SELECT ..."         anything else

Read-only by construction: the connection is opened in SQLite's read-only mode, so nothing
here can corrupt the store while the collector is writing to it.
"""
from __future__ import annotations

import os
import sqlite3
import statistics
import sys
import time

import net_store

DB = net_store.DB_PATH


def conn() -> sqlite3.Connection:
    if not os.path.exists(DB):
        raise SystemExit(f"no database yet at {DB} - run: python net_collect.py --once")
    # file: URI with mode=ro - a typo in a query cannot damage months of history
    return sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=10)


def ts(v) -> str:
    return time.strftime("%m-%d %H:%M:%S", time.localtime(v)) if v else "-"


def table(rows: list[tuple], headers: list[str]) -> None:
    if not rows:
        print("(no rows)")
        return
    cols = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    print("  ".join(str(h).ljust(w) for h, w in zip(headers, cols)))
    print("  ".join("-" * w for w in cols))
    for r in rows:
        print("  ".join(str(v).ljust(w) for v, w in zip(r, cols)))


def cmd_tables(c) -> None:
    print(f"{DB}  ({os.path.getsize(DB) / 1e6:.2f} MB)\n")
    names = [r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    rows = []
    for n in names:
        cnt = c.execute(f"SELECT COUNT(*) FROM {n}").fetchone()[0]
        cols = ", ".join(r[1] for r in c.execute(f"PRAGMA table_info({n})"))
        rows.append((n, cnt, cols[:70]))
    table(rows, ["table", "rows", "columns"])


def cmd_recent(c, target: str = "", n: int = 20) -> None:
    q = "SELECT ts, target, metric, value, net_id FROM sample"
    p: list = []
    if target:
        q += " WHERE target=?"
        p.append(target)
    rows = list(c.execute(q + " ORDER BY ts DESC LIMIT ?", p + [n]))
    table([(ts(t), tg, m, round(v, 2), nid[:8]) for t, tg, m, v, nid in rows],
          ["when", "target", "metric", "value", "net"])


def cmd_targets(c) -> None:
    rows = list(c.execute(
        "SELECT target, metric, COUNT(*), MIN(ts), MAX(ts), net_id FROM sample "
        "GROUP BY target, metric, net_id ORDER BY target, metric"))
    table([(tg, m, n, f"{(hi - lo) / 3600:.1f}", ts(hi), nid[:8])
           for tg, m, n, lo, hi, nid in rows],
          ["target", "metric", "n", "span_h", "latest", "net"])


def cmd_series(c, target: str, metric: str, n: int = 60) -> None:
    rows = list(c.execute(
        "SELECT ts, value FROM sample WHERE target=? AND metric=? ORDER BY ts DESC LIMIT ?",
        (target, metric, n)))[::-1]
    if not rows:
        raise SystemExit(f"no samples for {target}/{metric}")
    vals = [v for _t, v in rows]
    print(f"{target}/{metric}  n={len(vals)}  min={min(vals):.2f}  "
          f"median={statistics.median(vals):.2f}  max={max(vals):.2f}\n")
    # A crude sparkline beats a column of numbers for spotting where something moved.
    lo, hi = min(vals), max(vals)
    bars = " .:-=+*#%@"
    for t, v in rows:
        k = 0 if hi == lo else int((v - lo) / (hi - lo) * (len(bars) - 1))
        print(f"{ts(t)}  {v:8.2f}  {bars[k] * (k + 1)}")


def cmd_hours(c, target: str, metric: str) -> None:
    """Median per hour - the view that shows whether a path has a daily rhythm."""
    rows = list(c.execute(
        "SELECT (ts/3600)*3600 AS h, value FROM sample WHERE target=? AND metric=? "
        "ORDER BY h", (target, metric)))
    if not rows:
        raise SystemExit(f"no samples for {target}/{metric}")
    by_hour: dict[int, list[float]] = {}
    for h, v in rows:
        by_hour.setdefault(h, []).append(v)
    meds = {h: statistics.median(v) for h, v in by_hour.items()}
    lo, hi = min(meds.values()), max(meds.values())
    bars = " .:-=+*#%@"
    print(f"{target}/{metric}  {len(by_hour)} hours  range {lo:.2f} - {hi:.2f}\n")
    for h in sorted(meds):
        v, n = meds[h], len(by_hour[h])
        k = 0 if hi == lo else int((v - lo) / (hi - lo) * (len(bars) - 1))
        print(f"{time.strftime('%m-%d %Hh', time.localtime(h))}  {v:8.2f}  n={n:<4} "
              f"{bars[k] * (k + 1)}")


def cmd_nets(c) -> None:
    rows = list(c.execute(
        "SELECT n.net_id, n.label, n.gateway, n.gw_mac, n.subnet, n.first_seen, n.last_seen, "
        "(SELECT COUNT(*) FROM sample s WHERE s.net_id=n.net_id) FROM net n"))
    table([(nid[:8], lab, gw or "-", (mac or "-")[:17], sub or "-", ts(fs), ts(ls), cnt)
           for nid, lab, gw, mac, sub, fs, ls, cnt in rows],
          ["net", "label", "gateway", "gw_mac", "subnet", "first", "last", "samples"])


def main() -> int:
    a = sys.argv[1:]
    c = conn()
    what = a[0] if a else "tables"
    if what == "tables":
        cmd_tables(c)
    elif what == "recent":
        cmd_recent(c, a[1] if len(a) > 1 else "")
    elif what == "targets":
        cmd_targets(c)
    elif what == "series":
        cmd_series(c, a[1], a[2] if len(a) > 2 else "rtt_avg_ms")
    elif what == "hours":
        cmd_hours(c, a[1], a[2] if len(a) > 2 else "rtt_avg_ms")
    elif what == "nets":
        cmd_nets(c)
    elif what == "sql":
        cur = c.execute(a[1])
        table(list(cur), [d[0] for d in cur.description])
    else:
        print(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
