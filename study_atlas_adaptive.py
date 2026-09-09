"""EXPLORATORY, not pre-registered. G1 failed; the pre-registered consequence is "N from the
target's own history". Before recommending that as the next build, test it here out of sample:
  - calibrate per (probe, target) on days 1-14: N = longest run seen + 1 (floor 3 samples)
  - evaluate on days 15-28: how many runs page under adaptive N vs the fixed rule
Also descriptive: page rate vs a fixed N, and band concentration without the top-5 probes.
No gate is moved by this file; it decides what to build next, not whether the shipped rule
passed (it did not)."""
import json, os, statistics
from collections import Counter, defaultdict

HERE = os.environ.get("ATLAS_DATA", os.path.dirname(os.path.abspath(__file__)))  # dir holding u2_28d.json
D = json.load(open(os.path.join(HERE, "u2_28d.json")))
STEP = D["step_s"]; GAP = max(4 * STEP, 300.0)
MID = D["start"] + (D["stop"] - D["start"]) / 2


def runs(series):
    out, cur, prev = [], None, None
    for ts, _a, _j, loss in series:
        down = loss is not None and loss >= 1.0
        if prev is not None and ts - prev > GAP and cur:
            out.append((cur[1], cur[0], True)); cur = None
        if down:
            cur = [ts, 1] if cur is None else [cur[0], cur[1] + 1]
        elif cur:
            out.append((cur[1], cur[0], False)); cur = None
        prev = ts
    if cur:
        out.append((cur[1], cur[0], True))
    return out


series = {(m, p): s for m, byp in D["data"].items() for p, s in byp.items() if len(s) >= 100}
probes = {p for _m, p in series}
half_days = (D["stop"] - MID) / 86400
probe_days_2 = len(probes) * half_days

# ---------------------------------------------------------------- page rate vs fixed N (2nd half)
second = {k: [r for r in runs(s) if r[1] >= MID] for k, s in series.items()}
print(f"second half: {len(probes)} probes x {half_days:.0f} d = {probe_days_2:.0f} probe-days")
print("\npage rate vs FIXED N (samples), second half only:")
for N in (2, 3, 4, 5, 6, 8, 10, 15):
    pages = sum(1 for rs in second.values() for n, _s, _o in rs if n >= N)
    print(f"  N={N:2d} ({N * STEP / 60:3.0f} min)  {pages:5d} pages  "
          f"{pages / probe_days_2:.3f}/probe-day  probes paging: "
          f"{len({k[1] for k, rs in second.items() if any(n >= N for n, _s, _o in rs)})}")

# ---------------------------------------------------------------- adaptive N, calibrated on 1st half
first = {k: [r for r in runs(s) if r[1] < MID] for k, s in series.items()}
pages_ad, pages_fx, N_hist = 0, 0, Counter()
paged_probes_ad, paged_probes_fx = set(), set()
for k in series:
    longest = max((n for n, _s, _o in first[k]), default=0)
    N = max(3, longest + 1)                       # never below the shipped floor
    N_hist[N] += 1
    for n, _s, _o in second[k]:
        if n >= N:
            pages_ad += 1; paged_probes_ad.add(k[1])
        if n >= 3:
            pages_fx += 1; paged_probes_fx.add(k[1])
print(f"\nADAPTIVE N = longest run in days 1-14 + 1 (floor 3), evaluated on days 15-28:")
print(f"  fixed N=3 : {pages_fx:5d} pages  {pages_fx / probe_days_2:.3f}/probe-day  "
      f"probes {len(paged_probes_fx)}")
print(f"  adaptive  : {pages_ad:5d} pages  {pages_ad / probe_days_2:.3f}/probe-day  "
      f"probes {len(paged_probes_ad)}   (bar was 0.1)")
print("  N chosen (samples): " + ", ".join(f"{n}:{c}" for n, c in sorted(N_hist.items())[:12]))
# what adaptive N silences: are those long runs (real) or short (flaps)?
sil = Counter()
for k in series:
    longest = max((n for n, _s, _o in first[k]), default=0); N = max(3, longest + 1)
    for n, _s, _o in second[k]:
        if 3 <= n < N:
            sil[n] += 1
print("  runs the fixed rule pages that adaptive silences, by length: "
      + ", ".join(f"{n}:{c}" for n, c in sorted(sil.items())[:10]))
print(f"  of which >= 15 samples (an hour): {sum(c for n, c in sil.items() if n >= 15)}")

# ---------------------------------------------------------------- band concentration
band = Counter()
for k, s in series.items():
    for n, _st, _o in runs(s):
        if n == 2:
            band[k[1]] += 1
top5 = {p for p, _ in band.most_common(5)}
rest = {p for p in band if p not in top5}
print(f"\nband (2-sample runs): {len(band)} probes; without the top-5 chronic ones: "
      f"{len(rest)}/{len(probes) - 5} = {len(rest) / (len(probes) - 5):.1%}  (bar 5%)")
