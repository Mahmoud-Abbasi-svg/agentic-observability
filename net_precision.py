"""How precise are this agent's own instruments, on this path, right now?

    python net_precision.py 1.1.1.1            profile the instruments against one host
    python net_precision.py 10.50.16.1 5       ...with 5 trials each

The agent already knows when it cannot resolve a change. This is the other half: WHICH of its
instruments could, if any. Without it every refusal ends in a guess - "try tcp_latency, it's
probably finer" - which is advice the agent has never actually checked.

So it checks. Each candidate instrument is run several times against the same host in the same
minute, and its resolution is read off the results the same way net_memory reads it off stored
history: the smallest gap between distinct observed values IS the instrument's step size. A
configured precision table would be a claim about the tools; this is a measurement of them.

TWO THINGS THIS REPORTS THAT A NAIVE COMPARISON WOULD MISS

Step size is not the same as usable resolution. An instrument can report to four decimals and
still be useless if its readings scatter by 30% between identical runs. Both are measured, and
the limit is whichever is worse.

The instruments do not measure the same quantity. ICMP round-trip time and TCP handshake time
differ by the server's accept path and any middlebox in between, so tcp_latency is not a
drop-in replacement for ping - it is a different, finer measurement of a related thing. That is
stated rather than glossed, because silently swapping one for the other would change what the
baseline means without changing its name.

COST: this runs real measurements, several per instrument. Expect tens of seconds. It is worth
it when a resolution question is actually blocking an answer, and wasteful otherwise.
"""
from __future__ import annotations

import statistics
import sys
import time
from typing import Callable, Optional

import net_memory
import net_tools

# (label, how to run it, which metric it yields, what it actually measures)
CANDIDATES: list[tuple[str, Callable[[str], str], str, str]] = [
    ("ping count=5", lambda h: net_tools.ping(h, count=5), "rtt_avg_ms",
     "ICMP round trip, averaged over 5 whole-millisecond replies"),
    ("ping count=20", lambda h: net_tools.ping(h, count=20), "rtt_avg_ms",
     "ICMP round trip, averaged over 20 replies - finer steps, 4x the time"),
    ("tcp_latency 443", lambda h: net_tools.tcp_latency(h, 443, 5), "handshake_avg_ms",
     "TCP handshake to port 443 - fractional milliseconds, but includes the server's "
     "accept path, so it is NOT the same quantity as ICMP RTT"),
]


def _profile_one(label: str, run: Callable[[str], str], metric: str, host: str,
                 trials: int) -> dict:
    vals: list[float] = []
    t0 = time.time()
    errs = 0
    for _ in range(trials):
        try:
            out = run(host)
        except Exception:
            errs += 1
            continue
        v = net_memory.extract_metrics(
            "ping" if metric.startswith("rtt") else "tcp_latency", out).get(metric)
        if v is not None:
            vals.append(float(v))
    elapsed = time.time() - t0

    r = {"label": label, "metric": metric, "n": len(vals), "errors": errs,
         "seconds": elapsed, "median": None, "quantum": None, "rel_quantum": None,
         "spread": None, "floor": None}
    if len(vals) < 3:
        return r
    med = statistics.median(vals)
    q = net_memory._quantum(vals)
    r["median"] = med
    r["quantum"] = q
    if abs(med) > 1e-9:
        r["rel_quantum"] = q / abs(med)
        # Run-to-run scatter, as a fraction of the median. An instrument that reports fine
        # steps but scatters widely cannot resolve anything smaller than its own scatter.
        sd = statistics.pstdev(vals)
        r["spread"] = sd / abs(med)
        r["floor"] = max(r["rel_quantum"], r["spread"])
    return r


def instrument_options(host: str, shift_pct: float = 10.0, trials: int = 5) -> str:
    """Measure this agent's own instruments against a host, and report which of them could
    resolve a change of the size asked about.

    Use this when can_detect says the INSTRUMENT is the binding limit, or when an operator
    needs a resolution the current measurement cannot deliver. It answers "what would work",
    which is the question that follows every "I cannot see that".

    It runs real measurements and takes tens of seconds, so call it deliberately rather than
    as a matter of routine.

    Args:
        host: Host or IP to profile against, e.g. "10.50.16.1".
        shift_pct: The change size that needs to be resolvable, in percent.
        trials: Repeats per instrument. More is steadier and slower.
    """
    want = abs(shift_pct) / 100.0
    rows = [_profile_one(lbl, fn, met, host, trials) for lbl, fn, met, _d in CANDIDATES]
    desc = {lbl: d for lbl, _f, _m, d in CANDIDATES}

    out = [f"instrument precision against {host}, {trials} trials each, "
           f"target resolution {shift_pct:g}%",
           f"{'instrument':<18}{'metric':<18}{'median':>9}{'step':>9}"
           f"{'scatter':>9}{'floor':>8}  verdict"]
    usable = []
    for r in rows:
        if r["floor"] is None:
            out.append(f"{r['label']:<18}{r['metric']:<18}"
                       f"{'no usable readings':>35}"
                       + (f"   ({r['errors']} errors)" if r["errors"] else ""))
            continue
        ok = r["floor"] <= want
        usable.append((r["floor"], r)) if ok else None
        out.append(f"{r['label']:<18}{r['metric']:<18}{r['median']:>9.2f}"
                   f"{r['rel_quantum'] * 100:>8.1f}%{r['spread'] * 100:>8.1f}%"
                   f"{r['floor'] * 100:>7.1f}%  "
                   f"{'CAN resolve ' + format(shift_pct, 'g') + '%' if ok else 'cannot'}"
                   f"   ({r['seconds']:.0f}s)")

    out.append("")
    if usable:
        best = min(usable)[1]
        out.append(f"BEST: {best['label']} - floor {best['floor'] * 100:.1f}%, which covers "
                   f"the {shift_pct:g}% asked for.")
        out.append(f"  what it measures: {desc[best['label']]}")
        if best["label"].startswith("tcp_latency"):
            out.append("  CAUTION: this is not the same quantity as ICMP RTT. Switching "
                       "instruments changes what the number means, so a baseline built with "
                       "one cannot be compared against the other. Start a fresh baseline.")
    else:
        out.append(f"NONE of these instruments can resolve {shift_pct:g}% on this path.")
        worst = min((r["floor"], r) for r in rows if r["floor"] is not None)[1] \
            if any(r["floor"] is not None for r in rows) else None
        if worst:
            out.append(f"  The closest is {worst['label']} at {worst['floor'] * 100:.1f}%, and "
                       f"its limit is "
                       + ("run-to-run scatter, not step size - the PATH is too variable, and a "
                          "finer instrument will not help."
                          if worst["spread"] >= worst["rel_quantum"] else
                          "its step size, so a finer instrument would help."))
    return "\n".join(out)


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        raise SystemExit(0)
    print(instrument_options(a[0], float(a[1]) if len(a) > 1 else 10.0,
                             int(a[2]) if len(a) > 2 else 5))
