"""Does the alerting do what it claims - fire on real shifts, stay silent on noise?

Run:  python test_net_alert.py

Real history on this machine is hours old, so the interesting cases cannot be observed yet.
They are constructed instead, with the right answer known because the shift is injected:

  quiet-big     a stable path, +50% shift   -> MUST alert, and only after k confirmations
  quiet-tiny    a stable path, +1% shift    -> statistically REAL on a path this stable, and
                                               still MUST NOT alert: nobody wants waking for a
                                               0.1 ms move
  noisy-mid     a drifting path, +10% shift -> a FIXED 10% threshold would fire here; this
                                               must not, because the path moves that much
                                               on its own
  tiny-abs      2.4 ms -> 1.8 ms, quantised -> -25%, and one clock tick. MUST NOT alert
  improved      40 ms -> 24 ms              -> real, large, and MUST NOT page: nobody is woken
                                               because the network got faster
  immature      12 samples over 20 min      -> MUST stay UNKNOWN whatever the data says

The two middle cases are the design, from both ends. noisy-mid is a shift big enough to matter
that the path cannot resolve. quiet-tiny is a shift the path resolves easily that is too small
to matter. A monitor needs both tests, and almost none have either.

The test runs against a throwaway database, never the real one.
"""
from __future__ import annotations

import math
import os
import random
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netalert_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB          # must be set before net_store is imported

import net_alert          # noqa: E402
import net_memory         # noqa: E402
import net_store          # noqa: E402

STEP = 60.0               # one sample per minute
PASSES = 4                # evaluation passes; k=3 so an alert should land on the third


def build(conn, net_id: str, now: float) -> None:
    """Nine hours of history per path, the last hour carrying the injected shift."""
    rng = random.Random(7)
    start = now - 9 * 3600
    rows = []

    def emit(target, ts, value):
        rows.append((int(ts), target, "rtt_avg_ms", float(value), net_id))

    t = start
    i = 0
    while t <= now:
        recent = t > now - 3600
        # quiet: 10 ms, 2% jitter, no structure
        q = 10.0 * (1 + rng.gauss(0, 0.02))
        emit("quiet-big", t, q * (1.5 if recent else 1.0))
        emit("quiet-tiny", t, q * (1.01 if recent else 1.0))
        # noisy: a slow drift of +-25% - not iid jitter. Contiguous windows of it wander far
        # from the overall median, which is exactly why the noise floor here is high and why
        # drawing RANDOM samples for the null would understate it.
        drift = 1 + 0.25 * math.sin(i / 47.0) + 0.05 * math.sin(i / 7.3)
        n = 20.0 * drift * (1 + rng.gauss(0, 0.01))
        emit("noisy-mid", t, n * (1.10 if recent else 1.0))
        t += STEP
        i += 1

    # immature: twelve samples over twenty minutes, with a blatant shift it must ignore
    for j in range(12):
        emit("immature", now - 20 * 60 + j * 100, 10.0 if j < 6 else 30.0)

    # tiny-abs: the live gateway case. A -25% shift that is 2.4 ms -> 1.8 ms, on a path whose
    # values are quantised to 0.2 ms because ping reports whole milliseconds. Statistically
    # real, operationally meaningless: one clock tick.
    t, i = start, 0
    while t <= now:
        recent = t > now - 3600
        q = round((2.4 if not recent else 1.8) + rng.gauss(0, 0.35) * 0.6, 1)
        emit("tiny-abs", t, max(0.2, round(q * 5) / 5.0))
        # improved: a large, real, unambiguous DROP in latency - the network got better
        emit("improved", t, 40.0 * (1 + rng.gauss(0, 0.02)) * (0.6 if recent else 1.0))
        t += STEP
        i += 1

    # sparse-base: a dense recent window against a THIN baseline. This is the shape that
    # produced a false alarm on live data: the placebo windows nearly coincide, so their spread
    # collapses to zero and any shift clears the "floor". It must refuse, not alert.
    for j in range(25):                                   # 25 baseline samples over 9 h
        emit("sparse-base", now - 9 * 3600 + j * 1200, 10.0 * (1 + rng.gauss(0, 0.03)))
    for j in range(30):                                   # 30 in the last hour, shifted 40%
        emit("sparse-base", now - 3600 + j * 110, 14.0 * (1 + rng.gauss(0, 0.03)))

    conn.executemany("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                     "VALUES (?,?,?,?,?)", rows)
    conn.executemany("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) "
                     "VALUES (?,?,?,?)",
                     [(int(start + k * STEP), net_id, 4, 0)
                      for k in range(int(9 * 3600 / STEP) + 1)])
    conn.commit()
    print(f"built {len(rows)} samples across 4 paths, 9 h ending now")


def check(name: str, ok, detail: str = "") -> bool:
    # bool(), not the value: callers pass expressions like `a and b and c`, which
    # yield the last truthy operand rather than True. Suites accumulate with
    # `ok &= check(...)`, and `True & 6` is 0 - so every check printed PASS while the
    # suite reported failure. It can only raise a false alarm, never hide a real one,
    # but a suite that cries wolf gets ignored like any other.
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def main() -> int:
    conn = net_store.connect()
    net = net_store.network_identity()
    now = time.time()
    build(conn, net["net_id"], now)

    # What the statistics say before any state machine is involved.
    print("\nassessments")
    seen = {}
    for target in ("quiet-big", "quiet-tiny", "noisy-mid"):
        r = net_memory.assess(target, "rtt_avg_ms", net_alert.RECENT_HOURS,
                              net_alert.BASELINE_DAYS, now=now)
        seen[target] = r
        mde = "none" if r["mde"] is None else f"{r['mde'] * 100:.0f}%"
        print(f"  {target:<12} shift {r['shift'] * 100:+6.1f}%   "
              f"floor {r['noise_floor'] * 100:5.1f}%   mde {mde:<5}"
              f"   exceeds={r['exceeds']}")

    # Four passes. Nothing new is measured between them, so every pass sees the same evidence;
    # what changes is only how many times it has been confirmed.
    print("\nstate over 4 passes (k=3)")
    history: dict[str, list[str]] = {}
    fired: dict[str, int] = {}
    for p in range(PASSES):
        rows = net_alert.evaluate(conn, now=now + p, verbose=False)
        for r in rows:
            history.setdefault(r["target"], []).append(r["state"])
            if r["note"] == "FIRED":
                fired[r["target"]] = p + 1
    for target, states in sorted(history.items()):
        print(f"  {target:<12} {' -> '.join(states)}")

    print("\nchecks")
    ok = True
    ok &= check("quiet-big alerts", history["quiet-big"][-1] == "ALERTING")
    ok &= check("quiet-big waits for k=3", fired.get("quiet-big") == 3,
                f"fired on pass {fired.get('quiet-big')}")
    ok &= check("quiet-big silent on passes 1-2",
                history["quiet-big"][:2] == ["SUSPECT", "SUSPECT"])
    ok &= check("quiet-tiny IS statistically real", seen["quiet-tiny"]["exceeds"],
                f"shift {seen['quiet-tiny']['shift'] * 100:+.1f}% vs floor "
                f"{seen['quiet-tiny']['noise_floor'] * 100:.1f}% - the detector is right")
    ok &= check("quiet-tiny still never alerts", "ALERTING" not in history["quiet-tiny"],
                f"under the {net_alert.MIN_PRACTICAL_SHIFT * 100:.0f}% relevance bar")
    ok &= check("noisy-mid never alerts on a 10% shift",
                "ALERTING" not in history["noisy-mid"],
                f"floor is {seen['noisy-mid']['noise_floor'] * 100:.1f}% - a fixed 10% "
                f"threshold would have fired")
    ok &= check("noisy floor exceeds quiet floor",
                seen["noisy-mid"]["noise_floor"] > seen["quiet-big"]["noise_floor"] * 3,
                f"{seen['noisy-mid']['noise_floor'] * 100:.1f}% vs "
                f"{seen['quiet-big']['noise_floor'] * 100:.1f}%")
    ok &= check("immature stays UNKNOWN", set(history["immature"]) == {"UNKNOWN"})

    sp = net_memory.assess("sparse-base", "rtt_avg_ms", net_alert.RECENT_HOURS,
                           net_alert.BASELINE_DAYS, now=now)
    ok &= check("thin baseline refuses instead of alerting",
                sp["status"] == "insufficient" and "ALERTING" not in history["sparse-base"],
                "a 40% shift, correctly not called - too few placebo windows")

    ta = net_memory.assess("tiny-abs", "rtt_avg_ms", net_alert.RECENT_HOURS,
                           net_alert.BASELINE_DAYS, now=now)
    ok &= check("sub-millisecond shift never alerts",
                "ALERTING" not in history["tiny-abs"],
                f"{ta['shift'] * 100:+.0f}% is only "
                f"{ta['recent_median'] - ta['baseline_median']:+.2g} ms")

    im = net_memory.assess("improved", "rtt_avg_ms", net_alert.RECENT_HOURS,
                           net_alert.BASELINE_DAYS, now=now)
    ok &= check("improvement is detected as a real change", im["exceeds"],
                f"{im['shift'] * 100:+.0f}% - the detector stays direction-blind")
    ok &= check("improvement is never paged", "ALERTING" not in history["improved"],
                "nobody is woken because the network got faster")

    # The pure transition function, independent of any data.
    print("\nstate machine")
    s, k = "OK", 0
    seq, events = [], []
    for e in (True, True, False, True, True, True, False, False, False):
        s, k, ev = net_alert.step(s, k, e)
        seq.append(s)
        events.append(ev)
    ok &= check("flapping does not fire",
                seq[:3] == ["SUSPECT", "SUSPECT", "OK"], " -> ".join(seq[:3]))
    ok &= check("fires on the third consecutive", events[5] == "FIRED")
    ok &= check("clears on the third consecutive recovery", events[8] == "CLEARED")
    ok &= check("does not clear early", events[6] is None and events[7] is None)

    # A gap in measurement is not an outage.
    conn.execute("DELETE FROM heartbeat WHERE ts >= ?", (int(now - 3600),))
    conn.commit()
    ok &= check("no heartbeats means no evaluation",
                net_alert.evaluate(conn, now=now + 99, verbose=False) == [])

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    conn.close()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
