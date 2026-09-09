"""Every DOWN run in 28 days of Atlas ping from 200 probes to four root servers, cut exactly
as net_memory._runs cuts them. Answers prereg_atlas_runs.md: G1 gap, G2 page rate, G3 all-four.
Reads the cached u2_28d.json only. No network."""
import json, os, sys, statistics
from collections import Counter, defaultdict

HERE = os.environ.get("ATLAS_DATA", os.path.dirname(os.path.abspath(__file__)))  # dir holding u2_28d.json
D = json.load(open(os.path.join(HERE, "u2_28d.json")))
STEP = D["step_s"]
GAP = max(4 * STEP, 300.0)
DAYS = (D["stop"] - D["start"]) / 86400
MSMS = D["msms"]

MIN_PROBES, MIN_S = 3, 300.0                    # the shipped rule


def runs(series):
    """series: [[ts, avg, jitter, loss], ...] sorted. Yields (n, dur_s, start_ts, open)."""
    out, cur = [], None                          # cur = [start, n, last_ts]
    prev_ts = None
    for ts, _avg, _jit, loss in series:
        down = loss is not None and loss >= 1.0
        if prev_ts is not None and ts - prev_ts > GAP:
            if cur:
                out.append((cur[1], cur[1] * STEP, cur[0], True)); cur = None
        if down:
            cur = [ts, 1, ts] if cur is None else [cur[0], cur[1] + 1, ts]
        elif cur:
            out.append((cur[1], ts - cur[0], cur[0], False)); cur = None
        prev_ts = ts
    if cur:
        out.append((cur[1], cur[1] * STEP, cur[0], True))
    return out


all_runs = []                                    # (msm, probe, n, dur, start, open)
per_probe_band = defaultdict(int)                # probes with a 2-sample run
per_probe_page = defaultdict(int)                # runs >= rule, per probe
probe_days = 0.0
n_series = 0
for m, byp in D["data"].items():
    for p, ser in byp.items():
        if len(ser) < 100:
            continue
        n_series += 1
        probe_days += len(ser) * STEP / 86400
        for n, dur, st, op in runs(ser):
            all_runs.append((m, p, n, dur, st, op))
            if n == 2:
                per_probe_band[p] += 1
            if n >= MIN_PROBES and dur >= MIN_S:
                per_probe_page[p] += 1

probes = {p for _m, byp in D["data"].items() for p in byp if len(byp[p]) >= 100}
print(f"data: {len(probes)} probes, {n_series} series, {DAYS:.0f} d @ {STEP}s, "
      f"{probe_days:.0f} series-days")
print(f"down runs total: {len(all_runs)}")

hist = Counter(r[2] for r in all_runs)
print("\nrun length in samples (1 sample = 4 min):")
for n in sorted(hist):
    if n <= 12 or hist[n] > 3:
        print(f"  n={n:3d} ({n * STEP / 60:5.0f} min)  {hist[n]:6d}"
              + ("   <- flap" if n == 1 else "   <- BAND (2 samples, 8 min)" if n == 2
                 else "   <- rule fires" if n == MIN_PROBES else ""))
big = [r for r in all_runs if r[2] > 12]
print(f"  n>12: {len(big)} runs, longest {max((r[2] for r in all_runs), default=0)} samples")

# G1
band_probes = {p for p in per_probe_band}
frac = len(band_probes) / len(probes)
print(f"\nG1  probes with ANY 2-sample run on ANY target: {len(band_probes)}/{len(probes)} "
      f"= {frac:.1%}   (pre-registered bar: < 5%)  -> "
      f"{'GENERALISES' if frac < 0.05 else 'BAND POPULATED - N must come from history'}")
# how concentrated: are band runs from a few probes?
top = Counter(per_probe_band).most_common(5)
print(f"    2-sample runs total {sum(per_probe_band.values())}; top probes {top}")

# G2
pages = sum(per_probe_page.values())
rate = pages / probe_days if probe_days else 0
# per PROBE-day, not series-day: an operator watches one probe (four targets)
probe_day_total = probe_days / max(1, n_series / len(probes))
print(f"\nG2  runs that would page (>= {MIN_PROBES} samples, >= {MIN_S / 60:.0f} min): {pages}"
      f"  over {probe_day_total:.0f} probe-days  = {pages / probe_day_total:.3f} pages/probe-day"
      f"   (bar: <= 0.1)")
print(f"    probes that would page at least once in {DAYS:.0f} d: "
      f"{len(per_probe_page)}/{len(probes)};  median pages among those: "
      f"{statistics.median(per_probe_page.values()) if per_probe_page else 0}")
openish = sum(1 for r in all_runs if r[5] and r[2] >= MIN_PROBES)
print(f"    of the paging runs, {openish} end in a GAP (probe went silent) - outage likely "
      f"longer than counted")

# G3
key = defaultdict(set)                           # (probe, start-bucket) -> msms
for m, p, n, dur, st, op in all_runs:
    if n >= MIN_PROBES:
        key[(p, st // (2 * STEP))].add(m)
if key:
    c = Counter(len(v) for v in key.values())
    tot = sum(c.values())
    print(f"\nG3  paging runs by how many of the 4 targets shared them (same probe, same start):")
    for k in sorted(c):
        print(f"    {k} target(s): {c[k]:4d}  ({c[k] / tot:.0%})"
              + ("   <- probe-side, all four" if k == 4 else "   <- path-side, one" if k == 1 else ""))

# what the OLD rule would have needed: any run >= 15 samples (17 min on my data)?
print(f"\nfor scale: runs >= 15 samples (an hour): {sum(1 for r in all_runs if r[2] >= 15)}; "
      f"1-sample flaps: {hist[1]} ({hist[1] / max(1, len(all_runs)):.0%} of all runs)")
