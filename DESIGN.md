# Design sketch — a noise-aware network monitor

**Status:** v1 is built and running. This document was written *before* implementation
deliberately, because the expensive mistakes here are architectural rather than syntactic, and
it is kept unedited below that line so the design can be compared against what was actually
built.

| piece | state |
|---|---|
| collector, `net_id` tagging, heartbeats, retention | `net_collect.py`, `net_store.py` |
| evaluator, state machine, notifier | `net_alert.py` |
| console + logfile + webhook | done; `alert_log` table keeps every fire and clear |
| `monitor status` | `net_alert.py --status`, `--log` |
| TOML config | JSON instead (`monitor.json`) — `tomllib` needs 3.11, this runs on 3.10 |

**Two things this design did not anticipate**, both found by building it:

1. **Detectable ≠ worth reporting.** A stable enough path makes a 0.9% shift statistically
   undeniable. Alerting on it is how a noise-aware monitor reinvents alert fatigue from the
   other end. Added `MIN_PRACTICAL_SHIFT` — a relevance bar, distinct from the detection rule,
   and the number a human is meant to choose. Its comparison against the MDE is what surfaces
   an under-instrumented path, which is v2's whole premise arriving early.

2. **The noise floor can be computed from too few placebo windows.** When the recent window is
   nearly as large as the baseline, the windows overlap almost completely, their spread
   collapses to ~0%, and every shift clears it. This produced a false alarm on the first live
   evaluation. The alert format is what exposed it — the evidence line said "95th pct of 5
   placebo windows" — which is an argument for that format beyond readability.

---

## What this is

A monitor that watches a handful of network paths continuously and alerts when something has
**genuinely changed** — where "genuinely" means the shift exceeds what that path's own history
shows it does on its own.

## What it is not

A general metrics platform. Prometheus, Zabbix, Grafana and Datadog exist, are mature, and are
better funded. Building a generic latency collector means building a worse Prometheus, and
nobody would have a reason to use it.

## The one claim it rests on

> Adaptive baselining is not new — Datadog, Dynatrace and ManageEngine OpManager all ship it,
> and a static threshold that fires on a 12% rise whether the path swings 20% or is stable to
> 2% is a solved problem in commercial tooling. What those tools do **not** report is the
> **floor**: how small a change this path could have revealed at all. So an operator cannot
> distinguish *"nothing happened"* from *"nothing I could have seen happened"*, and a quiet
> dashboard is read as evidence of health when it may only be evidence of a blunt instrument.

This monitor alerts on a shift measured against the path's **own** variability, quotes the
minimum detectable effect next to every verdict, and says so when it cannot tell. `detect_change` in `net_memory.py` already does this and is validated
against injected shifts of known size (0% never called real; 50% and 100% always caught; 2%
on a 5%-noise path correctly reported as invisible).

Everything else in this document is plumbing around that one idea. If the plumbing gets
interesting, the project has lost its way.

---

## Architecture

```
   ┌────────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐
   │ collector  │───▶│  store   │───▶│ evaluator │───▶│ notifier │
   │ (dumb,     │    │ (sqlite) │    │ (stats)   │    │          │
   │  periodic) │    └──────────┘    └───────────┘    └──────────┘
   └────────────┘          │                │
                           │                ▼
                           │         ┌─────────────┐
                           └────────▶│   agent     │  ← on demand only
                                     │ (explains)  │
                                     └─────────────┘
```

### The most important decision: the LLM is not in the measurement loop

The collector and evaluator are **deterministic code**. No model call runs on the sampling
path. Three reasons, in order of how much they matter:

1. **Cost.** A model call per target per interval is unbounded spend for work that arithmetic
   does correctly.
2. **Latency.** A 60-second sampling interval cannot accommodate a 60-second reasoning step.
3. **Reproducibility.** An alert that fires or doesn't depending on sampling temperature is
   not an alert, it is a rumour. Detection must be a pure function of the data.

The agent is called for exactly two things, both off the hot path:

- **Explaining an alert** — "latency to X rose 40%; investigate and tell me why". This is the
  existing agent, unchanged, given a specific question. This is where it earns its place: the
  evaluator can say *that* something changed, never *why*.
- **Reviewing configuration** (v2 — see Self-sizing below).

---

## Data model

SQLite, not JSONL. The current append-only file is fine for a session and wrong for something
that runs for months: no indexes, no retention, rewritten wholesale to delete anything.

```sql
CREATE TABLE sample (
    ts        INTEGER NOT NULL,   -- unix seconds, wall clock
    target    TEXT    NOT NULL,   -- "1.1.1.1", "https://example.com"
    metric    TEXT    NOT NULL,   -- "rtt_avg_ms", "query_ms", "reachable"
    value     REAL    NOT NULL,
    net_id    TEXT    NOT NULL,   -- which network this was measured from (see below)
    PRIMARY KEY (target, metric, ts)
);
CREATE INDEX sample_lookup ON sample (target, metric, net_id, ts);

CREATE TABLE alert_state (
    target    TEXT, metric TEXT, net_id TEXT,
    state     TEXT,               -- OK | SUSPECT | ALERTING | RECOVERING
    since     INTEGER,
    last_shift REAL,
    PRIMARY KEY (target, metric, net_id)
);
```

```sql
CREATE TABLE path (                -- the route, as one traceroute saw it
    ts        REAL    NOT NULL,
    target    TEXT    NOT NULL,
    net_id    TEXT    NOT NULL,
    sig       TEXT    NOT NULL,   -- hop addresses in order, '*' for a silent hop
    hops      TEXT    NOT NULL,   -- JSON [[addr, [rtt_ms, ...]], ...]
    reached   INTEGER NOT NULL,
    PRIMARY KEY (target, ts)
);
```

A path is stored as a sequence rather than reduced to a number, because the question it
exists for — did the *route* change, or did the same route get slower? — cannot be asked of
a number. Its retention differs from a sample's: beyond the raw window a trace that repeats
the one before it says nothing new, so only the traces where the route *differed* from its
predecessor survive. Every change point, for a year, at a few hundred bytes each; per-hop
latencies for 14 days.

**Retention, decided up front rather than when the disk fills:** raw samples for 14 days,
hourly aggregates (mean, min, max, count) for 12 months, raw discarded after aggregation.
At one sample/minute across 10 targets that is ~200k rows raw — trivial — and the aggregate
table grows at ~90k rows/year. Bounded by construction.

Those aggregate columns were named `median`, `p05`, `p95` while the rollup stored `AVG`,
`MIN`, `MAX`. Nothing had read the table yet, so the wrong names had never been quoted —
they would have been, the first time an answer said "the p95 last month was". Renamed while
the table was still empty, with a best-effort migration for any database that already exists.

**Reading across the horizon is deliberately asymmetric**, and this is the part that took a
bug to get right. Every reader — `baseline`, `detect_change`, `can_detect`, the seasonality
test, the sizer — queried the raw table alone, so the day the first prune ran the tool would
have answered *"No history for 1.1.1.1 in the last 90 days"* with ninety days of it
summarised in the same file. Saying "I have no record" when the record exists is the same
class of error as claiming a change that did not happen.

The fix is not simply "read the aggregates too":

| | pre-horizon rows | why |
|---|---|---|
| `baseline` — *what did this path look like?* | **used**, labelled as summaries | the question is about the past, and hourly means answer it at lower resolution |
| floors — `can_detect`, `detect_change`, seasonality, sizing | **refused**, horizon stated | an hourly mean of ~12 samples varies far less than the samples do |

Measured rather than asserted, in `test_net_retention.py`: on identical data the floor comes
out at **10%** from raw samples and **2%** from hourly means of those same samples. A tool
that read the aggregates for its floors would announce five times the resolution it has —
which is precisely the over-claim the rest of this design exists to prevent. So the floors
stop at 14 days and say so, rather than silently returning a shorter window than was asked
for.

---

## `net_id`: the design point that is easy to miss and expensive to skip

**A laptop moves between networks, and a baseline from one is meaningless on another.**

This machine already demonstrates the problem: it carries DNS servers (`192.168.88.1`,
`203.0.113.x`) left over from other networks, which are unreachable here. If the monitor
pooled measurements across networks, moving from home to campus would register as a
catastrophic latency regression, and every genuine alert would be buried in the noise of
having walked to a different building.

So every sample is tagged with a network identity, and **baselines never cross a `net_id`
boundary**:

```
net_id = hash(default gateway MAC, local subnet, SSID if wireless)
```

Gateway MAC is the discriminator that matters — SSID collides ("eduroam" everywhere), and
subnets repeat (`192.168.1.0/24` in every home).

Consequences to accept, not work around:
- Arriving on a new network means no baseline. The correct behaviour is to **say so and
  collect**, not to alert on everything.
- A path may be healthy on one network and broken on another; both are true simultaneously.
- Roaming mid-measurement produces a sample belonging to neither. Tag with the `net_id` at the
  *start* and drop the sample if it changed during collection.

---

## Alerting

### The decision rule

Per (target, metric, net_id), on each evaluation:

1. Require a minimum history — at least ~30 samples spanning ≥ 6 h on this `net_id`.
   Below that, the state is **UNKNOWN**, and UNKNOWN never alerts. Collecting is not failing.
2. Run `detect_change(recent_hours=1, baseline_days=7)`.
3. If the shift does not exceed the noise floor → **OK**. This is the branch that does the
   work: it is where a static-threshold monitor would have fired and this one does not.
4. If it does exceed → advance the state machine below.

### State machine — because a single bad sample is not an incident

```
OK ──(shift exceeds floor)──▶ SUSPECT ──(k=3 consecutive)──▶ ALERTING
 ▲                               │                               │
 └────(back within floor)────────┴──────(recovered, k=3)─────────┘
```

`k = 3` consecutive confirming evaluations before an alert fires, and 3 before it clears.
Hysteresis is not optional: without it, a metric sitting on the boundary flaps, and a flapping
alert trains people to ignore alerts faster than a false one does.

### What an alert says

An alert that says "latency high" is a static-threshold alert wearing better clothes. This one
carries the evidence that justified it:

```
ALERT  1.1.1.1 / rtt_avg_ms   on net "office-wifi"
  baseline median : 13.1 ms   (7 d, 412 samples)
  now             : 24.6 ms   (last 1 h, 12 samples)
  shift           : +88%
  noise floor     : +6.2%     (95th pct of 380 placebo windows)
  confirmed       : 3 consecutive evaluations over 18 min
  smallest shift this history could resolve: 8%
```

The last line is what distinguishes it. It states the instrument's resolution alongside the
reading, so a reader can tell a decisive result from a marginal one without trusting the tool.

### Gaps are not outages

A laptop that slept for 8 hours did not experience an 8-hour outage. Distinguish:

- **no sample** (we did not measure — sleep, process stopped) → gap, never an alert
- **failed sample** (we measured, nothing answered) → `reachable = 0`, a real signal

The collector records an explicit heartbeat each cycle, so absence of samples is
distinguishable from absence of connectivity after the fact. Without this, every laptop lid
close generates an incident.

---

## Configuration

TOML, one file, no UI:

```toml
[[target]]
name     = "cloudflare-dns"
kind     = "ping"
host     = "1.1.1.1"
interval = "60s"
alert_on = ["rtt_avg_ms", "reachable"]

[[target]]
name     = "gateway"
kind     = "ping"
host     = "auto"          # resolved from the routing table per net_id
interval = "60s"

[notify]
console = true
webhook = "http://localhost:9000/hook"   # optional
```

`host = "auto"` matters: the gateway's address differs per network, so hardcoding one is the
bug already present in `net_seed.py`, which pins this machine's `10.50.16.1`.

**v1 notification is console + logfile + optional webhook.** Not email, not Slack, not push.
A webhook delegates that problem to tools that already solve it.

---

## Operational realities

These are the things that make the difference between a demo and a tool, and none of them are
interesting:

| problem | handling |
|---|---|
| laptop sleeps | heartbeat rows; gaps ≠ outages |
| network changes | `net_id` tagging; baselines never cross |
| process restarts | state in SQLite, not memory; resume from last sample |
| clock jumps | store wall clock, compute intervals from monotonic where possible |
| disk growth | retention policy above, enforced by a nightly aggregation pass |
| target dies permanently | after 7 days of `reachable = 0`, stop alerting and mark stale |
| the monitor itself breaks | log to file, exit non-zero, do not fail silently |

---

## Scope: v1

Deliberately small. Everything here reuses code that exists and is tested.

- collector wrapping the existing `net_tools` probes on a schedule
- SQLite store with `net_id` tagging and retention
- evaluator using the existing, validated `detect_change`
- state machine with hysteresis
- console + logfile + webhook notification
- `monitor status` showing per-target state and baseline maturity

**Explicitly not in v1:** a web UI, distributed collectors, multi-host aggregation,
alert routing rules, anomaly detection beyond change detection.

---

## v2 — the part that is actually novel

Everything above is *good engineering* applied to a known problem. This is the part with a
research claim in it, and it falls out of the architecture rather than being bolted on.

A monitor must decide **what to measure and how often**. Every existing tool takes that from a
human: someone types `interval = 60s` and never revisits it. But the sampling rate determines
what the monitor can *resolve* — and `detect_change` already reports that number as the
minimum detectable shift.

So the agent can close the loop:

> "You asked to be told about 10% regressions on this path. At the current sampling rate I can
> only resolve 22% shifts here, because this path is noisy. To meet your stated goal I need to
> sample every 20 s instead of every 60 s. On this other path I can resolve 3% shifts, so I am
> over-measuring and will back off to save budget."

That is **self-sizing measurement**: the instrument configures itself from a stated resolution
requirement plus the measured noise of each signal. No commercial monitor does this; they
sample everything at a fixed human-chosen interval and discover their blind spots only when
they miss something.

It is also the research idea from this project's other thread, with the monitor as its
testbed — the tool and the paper stop being separate efforts.

**Before building it, one literature check is owed:** optimal experimental design, sequential
analysis, active learning and adaptive sampling have addressed "how much to measure" for
sixty years without agents. The novelty is likely narrower than it first appears — plausibly
*"driven by a natural-language goal, with no formal model of the system"* rather than the
sizing itself. That check is cheap and should happen before the code, not after.

---

## Risks

| risk | severity | mitigation |
|---|---|---|
| crowded market — this is "another monitor" | high | lead with noise-aware alerting; it is the only reason to switch |
| the noise floor is wrong on some path shape | medium | it is validated on synthetic shifts; validate on real recorded incidents too |
| unattended reliability is boring and unbounded | medium | keep v1 scope small; the table above is the whole list |
| self-sizing is less novel than it looks | medium | do the literature check first |
| the agent gets pulled into the hot path "just for this one thing" | high | treat it as an invariant, not a preference |

---

## The first thing to build

The collector and store with `net_id` tagging — not the alerting.

Alerting cannot be tested without history, history cannot be gathered without a collector, and
`net_id` cannot be retrofitted once data exists without invalidating every baseline collected
before it. Everything downstream is cheap once the data is being recorded correctly; getting
it wrong is the one mistake here that costs a rewrite.
