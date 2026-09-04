"""Size the sampling to the question, instead of leaving an interval a human typed once.

    python net_size.py                 what each target's interval should be, and why
    python net_size.py --goal 5        ...to resolve 5% shifts instead of the default 10%
    python net_size.py --apply         rewrite monitor.json (backs up the old one first)

THE IDEA

Every monitor takes its sampling rate from a human who guessed. But the rate determines what
the monitor can RESOLVE, and net_memory already computes that number per signal - the minimum
detectable shift. So the loop can be closed: given a stated goal ("tell me about 10% changes"),
each target's interval can be set to the rate that actually meets it, and the targets where no
rate would suffice can be named rather than silently missed.

Three outcomes per signal, and the third is the one no monitor reports today:

    SPEED UP      resolution is worse than the goal; sample more often
    BACK OFF      resolution is far better than the goal; sample less and save the budget
    UNACHIEVABLE  no interval meets the goal on this path - say so instead of pretending

AN ASYMMETRY THAT MATTERS, AND IS EASY TO GET WRONG

Backing off is EXACT. A 120 s series is the 60 s series with every second sample dropped, so
the noise floor at the longer interval can be computed directly from data already collected -
no assumption at all.

Speeding up is an EXTRAPOLATION, and an optimistic one. There is no data at the finer interval,
so the estimate assumes samples taken twice as often are as informative as the ones we have.
They are not: measurements closer together in time are more correlated, so the effective sample
size grows more slowly than the count does. Every speed-up recommendation is therefore a lower
bound on the interval needed, and is labelled as such rather than quoted as a result.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import time
from typing import Optional

import net_alert
import net_collect
import net_memory
import net_store

# Sampling has a cost - CPU, battery, and traffic that is itself measurable from outside.
# These bound what the sizer may propose in either direction.
MIN_INTERVAL_S, MAX_INTERVAL_S = 10.0, 3600.0
THIN_FACTORS = (2, 3, 4, 6, 8, 12, 24)

# Availability metrics are NOT sized by resolution, and treating them as if they were is a
# serious mistake this sizer made on its first run: it proposed slowing gateway reachability
# from 61 s to 732 s, because a metric that is constant at 1.0 trivially "resolves 2%".
#
# That number is the grid floor on a degenerate signal, not a measurement of anything. And the
# question for an availability signal is not "how small a shift can I see" - it is "how long
# until I notice the host stopped answering". That is a LATENCY requirement, and it points the
# opposite way: it sets a ceiling on the interval rather than licensing a longer one.
AVAILABILITY_METRICS = {"reachable", "ok_2xx", "success_rate", "loss_pct", "open"}
DEFAULT_DETECT_WITHIN_S = 300.0


def _series(target: str, metric: str, days: float) -> tuple[list[float], float]:
    """Values and the measured sampling interval, read from the data rather than the config -
    the config says what was asked for, the data says what happened."""
    rows, _net = net_memory._rows(target, days, metric)
    if len(rows) < 3:
        return [], 0.0
    gaps = [b[0] - a[0] for a, b in zip(rows, rows[1:]) if b[0] > a[0]]
    return [float(v) for _ts, _m, v in rows], (statistics.median(gaps) if gaps else 0.0)


def _mde_at(values: list[float], k: int) -> Optional[float]:
    if k < 5 or k > len(values) // 2:
        return None
    mde, _crit, _n, _rel = net_memory._mde_for_window(values, k)
    return mde


def assess_signal(target: str, metric: str, goal: float, recent_hours: float,
                  baseline_days: float, detect_within: float = DEFAULT_DETECT_WITHIN_S) -> dict:
    values, interval = _series(target, metric, baseline_days)
    r = {"target": target, "metric": metric, "n": len(values), "interval": interval,
         "action": "no data", "detail": "", "suggest": None, "mde": None,
         "family": "availability" if metric in AVAILABILITY_METRICS else "continuous"}
    if len(values) < 40 or interval <= 0:
        r["detail"] = f"only {len(values)} samples; too little to size anything"
        return r

    if metric in AVAILABILITY_METRICS:
        # Latency, not resolution. The evaluator needs CONFIRMATIONS consecutive samples before
        # it will act, so the interval has to fit that many into the time you are willing to
        # wait. Nothing about the noise floor enters here.
        need = detect_within / max(1, net_alert.CONFIRMATIONS)
        if interval > need * 1.2:
            r.update(action="SPEED UP", suggest=max(MIN_INTERVAL_S, need),
                     detail=f"availability: {net_alert.CONFIRMATIONS} confirmations at "
                            f"{interval:.0f}s take {interval * net_alert.CONFIRMATIONS:.0f}s "
                            f"to fire, longer than the {detect_within:.0f}s you want")
        elif interval < need * 0.5:
            r.update(action="BACK OFF", suggest=min(MAX_INTERVAL_S, need),
                     detail=f"availability: {interval:.0f}s detects far faster than the "
                            f"{detect_within:.0f}s asked for; {need:.0f}s still meets it")
        else:
            r.update(action="KEEP",
                     detail=f"availability: fires in ~{interval * net_alert.CONFIRMATIONS:.0f}s, "
                            f"within the {detect_within:.0f}s target")
        return r

    k_now = max(1, int(round(recent_hours * 3600 / interval)))
    mde_now = _mde_at(values, k_now)
    r["mde"] = mde_now
    if mde_now is None:
        r["action"] = "unknown"
        r["detail"] = f"cannot calibrate a {k_now}-sample window from {len(values)} samples"
        return r

    if mde_now <= goal:
        # BACK OFF - and this branch is exact, because a longer interval is just this series
        # thinned. Find the longest interval whose thinned series still meets the goal.
        best = None
        for f in THIN_FACTORS:
            if interval * f > MAX_INTERVAL_S:
                break
            thinned = values[::f]
            k = max(1, int(round(recent_hours * 3600 / (interval * f))))
            m = _mde_at(thinned, k)
            if m is not None and m <= goal:
                best = (interval * f, m, f)
        if best:
            r.update(action="BACK OFF", suggest=best[0],
                     detail=f"resolves {mde_now * 100:.0f}% at {interval:.0f}s; still "
                            f"resolves {best[1] * 100:.0f}% at {best[0]:.0f}s "
                            f"(measured by thinning, not extrapolated)")
        else:
            r.update(action="KEEP",
                     detail=f"resolves {mde_now * 100:.0f}%, meets the {goal * 100:.0f}% goal; "
                            f"any longer interval would not")
        return r

    # SPEED UP - extrapolated. Search larger windows in the data we have for one that would
    # reach the goal, then convert that window back into an interval.
    k_need = None
    k = k_now
    while k * 2 <= len(values) // 2:
        k *= 2
        m = _mde_at(values, k)
        if m is not None and m <= goal:
            k_need = k
            break
    if k_need:
        want_interval = max(MIN_INTERVAL_S, recent_hours * 3600 / k_need)
        if want_interval < interval:
            r.update(action="SPEED UP", suggest=want_interval,
                     detail=f"resolves {mde_now * 100:.0f}% at {interval:.0f}s, needs "
                            f"{goal * 100:.0f}%; about {k_need} samples per window would do "
                            f"it -> {want_interval:.0f}s. EXTRAPOLATED: denser samples are "
                            f"more correlated, so treat this as a lower bound")
        else:
            r.update(action="KEEP", detail=f"resolves {mde_now * 100:.0f}%; a longer window "
                                           f"at the same interval already reaches the goal")
        return r

    r.update(action="UNACHIEVABLE",
             detail=f"resolves {mde_now * 100:.0f}% and no window this history supports "
                    f"reaches {goal * 100:.0f}%")
    return r


def explain_unachievable(target: str, metric: str, goal: float) -> str:
    """When no rate helps, say which of the two reasons it is - they have opposite remedies."""
    text = net_memory.can_detect(target, metric, goal * 100)
    for line in text.splitlines():
        if "BINDING LIMIT" in line:
            if "INSTRUMENT" in line:
                return "the instrument cannot express it; sampling faster will never help"
            return "the path's own variability; more data may help eventually, rate will not"
    return "reason undetermined"


def recommend(goal: float, recent_hours: float, baseline_days: float, config_path: str,
              detect_within: float = DEFAULT_DETECT_WITHIN_S) -> tuple[list[dict], dict]:
    cfg = net_collect.load_config(config_path)
    net = net_store.network_identity()
    conn = net_memory.conn()

    # Which metrics a target actually alerts on, so the sizing serves the alerting rather than
    # optimising a number nobody watches.
    rows = list(conn.execute(
        "SELECT DISTINCT target, metric FROM sample WHERE net_id=? AND ts>=?",
        (net["net_id"], int(time.time() - baseline_days * 86400))))
    pairs = [(t, m) for t, m in rows if m in net_alert.ALERT_METRICS]

    out = [assess_signal(t, m, goal, recent_hours, baseline_days, detect_within)
           for t, m in sorted(pairs)]
    return out, cfg


def apply_to_config(results: list[dict], cfg: dict, path: str) -> str:
    """Rewrite the intervals. A target's interval is set by its most demanding metric - the one
    needing the shortest interval - because one probe produces all of them."""
    want: dict[str, float] = {}
    for r in results:
        if r["suggest"]:
            want[r["target"]] = min(want.get(r["target"], 1e9), r["suggest"])

    changed = []
    for t in cfg["targets"]:
        host = t["host"]
        if host == "auto":
            host = net_store.network_identity().get("gateway") or ""
        if host in want:
            new = int(round(want[host]))
            new = max(MIN_INTERVAL_S, min(MAX_INTERVAL_S, new))
            if new != t.get("interval_s"):
                changed.append((t["name"], t.get("interval_s"), new))
                t["interval_s"] = new
    if not changed:
        return "no interval needed changing"

    backup = path + f".bak.{int(time.time())}"
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    lines = [f"  {n:<16} {old}s -> {new}s" for n, old, new in changed]
    return (f"rewrote {path} ({len(changed)} target(s)); previous saved to "
            f"{os.path.basename(backup)}\n" + "\n".join(lines)
            + "\n  restart the collector for these to take effect")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Set each target's sampling interval from the resolution you need.")
    ap.add_argument("--goal", type=float,
                    default=net_alert.MIN_PRACTICAL_SHIFT * 100,
                    help="shift size to resolve, in percent")
    ap.add_argument("--recent-hours", type=float, default=net_alert.RECENT_HOURS)
    ap.add_argument("--detect-within", type=float, default=DEFAULT_DETECT_WITHIN_S,
                    help="seconds within which an outage must be noticed (availability "
                         "metrics are sized by this, not by resolution)")
    ap.add_argument("--days", type=float, default=net_alert.BASELINE_DAYS)
    ap.add_argument("--config", default=net_collect.CONFIG_PATH)
    ap.add_argument("--apply", action="store_true", help="rewrite monitor.json")
    a = ap.parse_args()

    goal = a.goal / 100.0
    net = net_store.network_identity()
    print(f"sizing for a {a.goal:g}% resolution goal on network {net['label']!r}, "
          f"{a.recent_hours:g} h comparison window\n")
    results, cfg = recommend(goal, a.recent_hours, a.days, a.config, a.detect_within)

    print(f"{'target':<22}{'metric':<18}{'now':>7}{'mde':>7}  {'action':<13}detail")
    print("-" * 110)
    for r in sorted(results, key=lambda x: (x["action"], x["target"])):
        mde = f"{r['mde'] * 100:.0f}%" if r["mde"] is not None else "-"
        iv = f"{r['interval']:.0f}s" if r["interval"] else "-"
        print(f"{r['target'][:21]:<22}{r['metric'][:17]:<18}{iv:>7}{mde:>7}  "
              f"{r['action']:<13}{r['detail']}")

    unach = [r for r in results if r["action"] == "UNACHIEVABLE"]
    if unach:
        print("\nSignals no sampling rate can fix - the part a monitor normally hides:")
        for r in unach:
            print(f"  {r['target']}/{r['metric']}: {explain_unachievable(r['target'], r['metric'], goal)}")

    if a.apply:
        print("\n" + apply_to_config(results, cfg, a.config))
    else:
        n = sum(1 for r in results if r["suggest"])
        print(f"\n{n} signal(s) would change interval. Re-run with --apply to write them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
