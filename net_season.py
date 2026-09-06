"""Is this path's noise really noise, or is some of it just the time of day?

    python net_season.py                    every target, measured
    python net_season.py --days 14
    python net_season.py --target 1.1.1.1 --metric rtt_avg_ms

THE PROBLEM, WHICH THE TOOL ALREADY ADMITS TO

Every `can_detect` answer ends with a confession:

    COVERAGE: history spans 26 h and so contains no full day-night cycle. Normal daily
    variation is not yet in the noise model, so both floors above may be optimistic.

And once there IS more than a day of history, the opposite error appears and nothing warns
about it. The noise floor is calibrated by comparing windows against the median of ALL the
history, so a Tuesday-15:00 window is scored against a baseline containing Sunday 03:00. If
the path is busier by day, that diurnal swing is counted as noise, the floor comes out wider
than the path deserves, and real changes are dismissed as invisible.

The floor is then wrong in the SAFE direction - it under-claims - which is why nothing has
ever caught it. Under-claiming still costs: it is the difference between "I cannot see a 20%
change here" and "I can see 8% if I compare like with like".

MEASURED, NOT ASSUMED

Seasonality is not switched on because monitoring tools usually have it. It is tested for on
each signal, and where there is no detectable time-of-day effect nothing changes and the
report says so. A path with no diurnal pattern should not pay for the machinery, and claiming
a correction that the data does not support would be the same overreach this project exists
to avoid.

THE TEST IS REPEATABILITY, NOT SIZE

A path that wanders produces a large hourly swing without having any daily rhythm at all, so
the size of the swing decides nothing. What separates the two is whether the shape of the day
REPEATS: the history is split in half, an hourly profile built for each half and normalised by
that half's own median (so a drifting level cannot pose as shape), and the two profiles are
rank-correlated. A real rhythm has the same busy hours in both halves; a random walk does not
reproduce whatever shape it happened to wander into.

The null needs no simulation - rotating one profile against the other by 1..23 hours
enumerates every alternative alignment exactly.

A FIRST VERSION OF THIS TEST HAD NO POWER, AND THE REASON IS WORTH KEEPING

It compared the observed hourly spread against a circularly shifted copy of the series,
reasoning that a rotation preserves autocorrelation while destroying alignment to the clock.
It preserves rather more than that: rotating a series whose period IS 24 h yields another
series with the same 24 h period, moving only the phase and leaving the peak-to-trough of the
hourly medians untouched. The null reproduced exactly the signal it was meant to remove, and
a textbook sine wave scored p = 0.68. `test_net_season.py` still runs that null against a
known rhythm, so the failure stays visible instead of being rediscovered.
"""
from __future__ import annotations

import argparse
import math
import random
import statistics
import time
from typing import Optional

import net_memory
import net_store

MIN_SPAN_H = 48.0           # two full cycles: one is a coincidence, not a pattern
MIN_PER_HOUR = 5            # an hour represented by fewer samples is not an estimate
MIN_HOURS_COVERED = 12      # half the clock, or the profile is a few hours pretending to be a day
TRIALS = 300


def _rows(target: str, metric: str, days: float) -> list[tuple[float, float]]:
    rows, _net = net_memory._rows(target, days, metric)
    return [(float(ts), float(v)) for ts, _m, v in rows]


def _hour(ts: float) -> int:
    return time.localtime(ts).tm_hour


def hourly_profile(rows: list[tuple[float, float]]) -> dict[int, tuple[float, int]]:
    """hour of day -> (median, n), keeping only hours with enough samples to mean anything."""
    buckets: dict[int, list[float]] = {}
    for ts, v in rows:
        buckets.setdefault(_hour(ts), []).append(v)
    return {h: (statistics.median(vs), len(vs))
            for h, vs in sorted(buckets.items()) if len(vs) >= MIN_PER_HOUR}


def _spread(rows: list[tuple[float, float]]) -> Optional[float]:
    """Peak-to-trough of the hourly medians, relative to the overall median."""
    prof = hourly_profile(rows)
    if len(prof) < MIN_HOURS_COVERED:
        return None
    meds = [m for m, _n in prof.values()]
    centre = statistics.median([v for _ts, v in rows])
    if abs(centre) < 1e-9:
        return None
    return (max(meds) - min(meds)) / abs(centre)


def _rank(xs: list[float]) -> list[float]:
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    r = [0.0] * len(xs)
    for pos, i in enumerate(order):
        r[i] = float(pos)
    return r


def _spearman(a: list[float], b: list[float]) -> Optional[float]:
    if len(a) < 6:
        return None
    ra, rb = _rank(a), _rank(b)
    ma, mb = statistics.fmean(ra), statistics.fmean(rb)
    num = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    da = math.sqrt(sum((x - ma) ** 2 for x in ra))
    db = math.sqrt(sum((y - mb) ** 2 for y in rb))
    return num / (da * db) if da > 0 and db > 0 else None


def diurnal_test(rows: list[tuple[float, float]], trials: int = TRIALS,
                 seed: int = 0) -> dict:
    """Is the shape of the day REPRODUCIBLE, rather than merely present?

    A first version asked a different question - is the hourly spread larger than a circularly
    shifted copy of the series would give - and it had no power whatsoever. Rotating a series
    whose period IS 24 h produces another series with the same 24 h period: only the phase
    moves, and the peak-to-trough of the hourly medians is untouched. The null therefore
    reproduced the exact signal it was supposed to destroy, and a textbook sine wave scored
    p = 0.68. Recorded because the mistake is not obvious and the test looked reasonable.

    What separates a daily rhythm from a slow wander is not size, it is REPEATABILITY. So the
    history is split in half by time, an hourly profile is built for each half - each
    normalised by its own median, so a drifting level cannot masquerade as shape - and the two
    profiles are compared by rank correlation.

    A real rhythm has the same busy and quiet hours in both halves, so the correlation is high.
    A random walk has whatever shape it happened to wander into, and the second half does not
    reproduce it.

    The null needs no simulation: rotating one profile against the other by 1..23 hours gives
    every alternative alignment exactly. Under the null of no shared phase, the observed
    correlation is just one of those 24 arrangements.
    """
    out = dict(status="insufficient", reason="", observed=None, p=None,
               null_p95=None, span_h=0.0, n=len(rows), hours=0)
    if len(rows) < 40:
        out["reason"] = f"only {len(rows)} samples"
        return out
    rows = sorted(rows)
    span = (rows[-1][0] - rows[0][0]) / 3600.0
    out["span_h"] = span
    if span < MIN_SPAN_H:
        out["reason"] = (f"history spans {span:.1f} h; needs {MIN_SPAN_H:.0f} h so that a "
                         f"daily pattern can be distinguished from a single day's drift")
        return out

    mid = len(rows) // 2
    pa, pb = hourly_profile(rows[:mid]), hourly_profile(rows[mid:])
    shared = sorted(set(pa) & set(pb))
    out["hours"] = len(shared)
    if len(shared) < MIN_HOURS_COVERED:
        out["reason"] = (f"only {len(shared)} hour(s) of the day have {MIN_PER_HOUR}+ samples "
                         f"in BOTH halves of the history; needs {MIN_HOURS_COVERED}")
        return out

    # Normalise each half by its own median: the question is whether the SHAPE repeats, and a
    # path that simply got slower overall must not answer it.
    ca = statistics.median([v for _t, v in rows[:mid]]) or 1.0
    cb = statistics.median([v for _t, v in rows[mid:]]) or 1.0
    a = [pa[h][0] / ca for h in shared]
    b = [pb[h][0] / cb for h in shared]

    observed = _spearman(a, b)
    if observed is None:
        out["reason"] = "too few shared hours to correlate"
        return out

    nulls = []
    for off in range(1, len(shared)):
        rot = b[off:] + b[:off]
        s = _spearman(a, rot)
        if s is not None:
            nulls.append(s)
    if not nulls:
        out["reason"] = "could not build a null distribution"
        return out

    p = (1 + sum(1 for x in nulls if x >= observed)) / (1 + len(nulls))
    nulls.sort()
    prof = hourly_profile(rows)
    swing = _spread(rows)
    out.update(status="ok", observed=swing, agreement=observed, p=p,
               null_p95=nulls[min(int(0.95 * len(nulls)), len(nulls) - 1)],
               real=(p < 0.05 and observed > 0), profile=prof)
    return out


def floors(rows: list[tuple[float, float]], k: int) -> tuple[Optional[float], Optional[float]]:
    """(floor as computed today, floor when each window is scored against its own hour).

    The only change is the reference point. Windows stay contiguous, so the autocorrelation
    that makes this calibration honest is untouched; what is removed is the part of a window's
    deviation that is explained by which hour it happens to sit in.
    """
    vals = [v for _ts, v in sorted(rows)]
    plain, _crit, _n, _rel = net_memory._mde_for_window(vals, k)

    prof = hourly_profile(rows)
    if len(prof) < MIN_HOURS_COVERED:
        return plain, None
    srt = sorted(rows)
    centre = statistics.median(vals)
    if abs(centre) < 1e-9:
        return plain, None

    devs = []
    for s in range(0, max(1, len(srt) - k + 1)):
        w = srt[s:s + k]
        if len(w) < k:
            continue
        m = statistics.median([v for _t, v in w])
        # The hour this window belongs to, and that hour's own normal.
        h = _hour(w[len(w) // 2][0])
        ref = prof.get(h, (centre, 0))[0]
        if abs(ref) < 1e-9:
            ref = centre
        devs.append((m - ref) / abs(ref))
    if len(devs) < net_memory.MIN_PLACEBO_WINDOWS:
        return plain, None

    absd = sorted(abs(d) for d in devs)
    crit = absd[min(int(0.95 * len(absd)), len(absd) - 1)]
    for d in net_memory._MDE_GRID:
        if sum(1 for x in devs if abs(x + d) > crit) / len(devs) >= 0.80:
            return plain, d
    return plain, None


def assess(target: str, metric: str, days: float, recent_hours: float) -> dict:
    rows = _rows(target, metric, days)
    r = dict(target=target, metric=metric, n=len(rows))
    t = diurnal_test(rows)
    r.update(t)
    if t["status"] != "ok":
        return r

    interval = 0.0
    if len(rows) > 3:
        srt = sorted(t for t, _v in rows)
        gaps = [b - a for a, b in zip(srt, srt[1:]) if b > a]
        interval = statistics.median(gaps) if gaps else 0.0
    k = max(5, int(round(recent_hours * 3600 / interval))) if interval > 0 else 30
    k = min(k, max(5, len(rows) // 4))
    r["k"] = k
    r["plain_floor"], r["seasonal_floor"] = floors(rows, k)
    return r


def format_row(r: dict) -> str:
    tgt = f"{r['target'][:20]:<21}{r['metric'][:16]:<17}"
    if r["status"] != "ok":
        return f"{tgt}{'-':>9}{'-':>9}  not yet: {r['reason']}"
    eff = f"{(r['observed'] or 0) * 100:.0f}%"
    if not r.get("real"):
        return (f"{tgt}{eff:>9}{'-':>9}  no repeatable daily shape "
                f"(agreement {r.get('agreement', 0):+.2f}, p={r['p']:.2f}); nothing changed")
    p, s = r.get("plain_floor"), r.get("seasonal_floor")
    if p is None or s is None:
        return (f"{tgt}{eff:>9}{'-':>9}  real (p={r['p']:.3f}) but the floor could not be "
                f"recomputed")
    verdict = (f"floor {p * 100:.0f}% -> {s * 100:.0f}% comparing like with like"
               if s < p else
               f"floor unchanged at {p * 100:.0f}%; the swing is not what limits this path")
    return f"{tgt}{eff:>9}{('p=%.3f' % r['p']):>9}  {verdict}"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Test each signal for a time-of-day effect, and correct the floor only "
                    "where one is real.")
    ap.add_argument("--days", type=float, default=7.0)
    ap.add_argument("--recent-hours", type=float, default=1.0)
    ap.add_argument("--target", default="")
    ap.add_argument("--metric", default="")
    a = ap.parse_args()

    net = net_store.network_identity()
    conn = net_memory.conn()
    pairs = [(t, m) for t, m in conn.execute(
        "SELECT DISTINCT target, metric FROM sample WHERE net_id=? AND ts>=?",
        (net["net_id"], int(time.time() - a.days * 86400)))
        if (not a.target or t == a.target) and (not a.metric or m == a.metric)]
    pairs = [(t, m) for t, m in pairs if m in {"rtt_avg_ms", "handshake_avg_ms", "query_ms",
                                               "response_ms", "connect_ms", "loss_pct"}]
    if not pairs:
        print("no signals to test")
        return 0

    print(f"time-of-day effect on network {net['label']!r}, last {a.days:g} days\n")
    print(f"{'target':<21}{'metric':<17}{'swing':>9}{'p':>9}  effect on the noise floor")
    print("-" * 104)
    for t, m in sorted(pairs):
        print(format_row(assess(t, m, a.days, a.recent_hours)))

    print("\nThe swing is the peak-to-trough of the hourly medians, and it decides nothing on "
          "its own:\na wandering path produces a large swing with no rhythm at all. What is "
          "tested is whether\nthe shape REPEATS - the history is split in half, an hourly "
          "profile built for each and\nnormalised by that half's own median, and the two "
          "rank-correlated against a null that\nenumerates every other hourly alignment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
