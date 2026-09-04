"""Validate detect_change against shifts of KNOWN size.

A statistical function cannot be checked by looking at its output on real data, because on
real data nobody knows the right answer. So: build a synthetic history whose noise level is
chosen, inject a shift whose size is chosen, and check the verdict against what it should be.

Two failure modes matter and they pull in opposite directions:
  a shift of 0% called REAL      -> false alarm; the agent invents incidents
  a large shift called NOT REAL  -> blind; the agent misses real degradation

The interesting cases are in between, and the honest answer there is "cannot tell" - which is
what the minimum-detectable-shift line exists to say.

Writes only to a throwaway database; your real net_monitor.db is untouched.

    python test_detect_change.py
"""
import os
import random
import sys
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netchange_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB          # must be set before net_store is imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import net_memory                                                    # noqa: E402
import net_store                                                     # noqa: E402

CONN = net_store.connect()
NET_ID = net_store.network_identity()["net_id"]


def build(base_n=40, recent_n=6, mult=1.0, noise=0.05, spacing_s=3600, heavy=True, seed=1):
    """Hourly history: base_n quiet samples, then recent_n scaled by `mult`."""
    rng = random.Random(seed)
    now = int(time.time())
    rows, total = [], base_n + recent_n
    for i in range(total):
        ts = now - (total - i) * spacing_s
        if i >= base_n:                       # recent samples land inside the last 2 h
            ts = now - (total - i) * 600
        v = 14.0 * (1 + rng.gauss(0, noise))
        if heavy and rng.random() < 0.06:     # occasional real-world latency spike
            v *= rng.uniform(1.4, 2.2)
        if i >= base_n:
            v *= mult
        rows.append((ts, "T", "rtt_avg_ms", round(v, 2), NET_ID))
    CONN.execute("DELETE FROM sample WHERE target='T'")
    CONN.executemany("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                     "VALUES (?,?,?,?,?)", rows)
    CONN.commit()


def verdict_of(text: str) -> str:
    if "EXCEEDS" in text:
        return "REAL"
    if "NOT distinguishable" in text:
        return "not called"
    return "refused"


CASES = [
    (1.00, 0.05, "not called", "no shift - calling this REAL is a false alarm"),
    (1.00, 0.15, "not called", "no shift, noisier path"),
    (1.02, 0.05, "not called", "2% under 5% noise - should be invisible"),
    (1.10, 0.05, "either", "10% vs 5% noise - borderline by design"),
    (1.50, 0.05, "REAL", "50% - must be caught"),
    (2.00, 0.05, "REAL", "100% - must be caught"),
    (2.00, 0.30, "either", "100% but very noisy path"),
    (0.50, 0.05, "REAL", "halved - improvement is still a change"),
]


def main() -> int:
    print(f"{'true shift':>11}{'noise':>8}{'verdict':>13}   expected")
    print("-" * 62)
    fails = 0
    for mult, noise, expect, why in CASES:
        build(mult=mult, noise=noise)
        out = net_memory.detect_change("T", "rtt_avg_ms", recent_hours=2, baseline_days=30)
        got = verdict_of(out)
        ok = (expect == "either") or (got == expect)
        fails += (not ok)
        print(f"{(mult - 1) * 100:>+10.0f}%{noise * 100:>7.0f}%{got:>13}   "
              f"{'ok ' if ok else 'FAIL'} {why}")

    for label, mult in [("50% shift on a 5% path", 1.50), ("no shift at all", 1.00)]:
        print(f"\n--- full output, {label} ---")
        build(mult=mult, noise=0.05)
        print(net_memory.detect_change("T", "rtt_avg_ms", recent_hours=2, baseline_days=30))

    print(f"\n{fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
