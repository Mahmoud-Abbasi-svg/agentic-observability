# Do the reachability thresholds hold on networks that are not this one?

**No.** Pre-registered, run the same afternoon the rule shipped, on 28 days of RIPE Atlas data
from 200 probes. The gate failed by a factor of eight. The constants stand as shipped and the
gate is not moved; what changes is what the rule is allowed to claim.

## The rule under test

`net_alert` rule 6, commit `4a492ca`: `reachable` exceeds when its current failure run is
ongoing, at least 3 probes and at least 5 minutes long. The thresholds were read off this
machine's own store — every DOWN run of `reachable` in 14 days on two networks: flaps were
1–3 probes and under a minute, outages 15+ probes and 17+ minutes, nothing between. Five
minutes sat in that gap with margin on both sides.

The gap rested on 43 runs. That is the whole finding.

## Data

RIPE Atlas built-in ping (3 packets per cycle) to k, f, m and a-root, 240 s cadence, 28 days
ending 2026-09-02, 200 probes in 126 countries capped at six per country. Already cached from
earlier work; nothing fetched, zero credits. 728 series with ≥ 100 samples, 5,422 series-days.

A sample is DOWN when all three packets are lost. Runs are cut exactly as `net_memory._runs`
cuts them, gap threshold `max(4 × cadence, 300 s)`, so a probe that went silent is a GAP, not
a run. At 240 s the rule's probe condition binds: three samples is twelve minutes. The
ambiguous band is therefore runs of exactly two samples, eight minutes: a real loss of
service, short of the rule.

## Pre-registered claims and results

| claim | bar, fixed in advance | result | verdict |
|---|---|---|---|
| G1 the gap generalises | < 5% of probes have any 2-sample run | **40.0%** (80 of 200) | **fails** |
| G2 page rate under the rule | ≤ 0.1 per probe-day | **0.174** | **fails** |
| G3 paging runs shared by all four targets | none; sanity check | 7% all-four, 84% one-target | reported |

The run-length distribution, all 14,136 runs:

```
n=1   4 min   11,868   84% of all runs
n=2   8 min    1,273
n=3  12 min      400   <- rule fires
n=4  16 min      151
n=5  20 min       84
...decaying smoothly; 175 runs of an hour or more; longest 7,125 samples
```

There is no gap. It decays geometrically from one sample onward. The 2-sample band is not
a few chronic probes either: removing the five worst leaves 38.5% of the rest.

G3 says most runs the rule would page are single-target — one root server's anycast
instance unreachable from that probe while the other three answer. That is a real loss of
reachability to that target, and it is also the majority of the fatigue.

## The pre-registered consequence, tested before being recommended

"N must come from the target's own history." Exploratory, not a gate: calibrate N per series
as the longest run in days 1–14 plus one (floor 3), evaluate on days 15–28.

| rule | pages / probe-day, days 15–28 | probes paging |
|---|---|---|
| fixed N = 3 (as shipped) | 0.141 | 48 |
| adaptive N | 0.043 | 40 |

Adaptive N passes the fatigue bar. It does so by silencing 259 runs the fixed rule pages,
and **19 of them are an hour or more**, on series whose first fortnight already held a long
outage. That is the placebo floor's failure mode — a history that contains outages swallows
the next one — reappearing inside the fix for it. It is not a recommendation.

For scale only, the page rate against a fixed N in the second half: N=4 gives 0.064, N=5
gives 0.044. **Those numbers are not to be used to set N.** They were read off the evaluation
half; choosing one would be tuning on the test set, and this document exists because that
is how the first number was chosen.

## What the rule may now claim

It separates this machine's flaps from this machine's outages on the two networks it has
seen, and it fires on the outage the floor missed. It is not a rule for other networks, and
`README.md` says so beside it.

## What this cannot say

- Anything about 60 s cadence. Atlas has no 60 s data; every threshold here was exercised at
  240 s, where "three probes" means twelve minutes.
- Anything about mobile or satellite links. The panel carries no connection-type tags and
  Atlas hosts skew toward people with good connectivity.
- Anything about the collector or the identity code. This exercised the judge, not the
  measurement.

## The design decision, not made here

Two honest directions, neither a constant:

1. **Correlate across targets before paging.** The outage this rule was built for was every
   host down together; G3 shows single-target runs are 84% of what would page. Page on
   all-watched-hosts-down (which `availability._all_down` already computes) and demote a
   single target's loss to a notice. This cuts fatigue without touching N and without
   silencing long outages.
2. **A fresh pre-registration for any new N**, on data not used here: a different probe
   panel or a later window, with the bar set before the pull.

Scripts: `study_atlas_runs.py`, `study_atlas_adaptive.py`. They read the cached pull from
`ATLAS_DATA`; the 263 MB cache is not in the repo.
