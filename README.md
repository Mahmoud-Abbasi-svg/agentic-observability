# Network Observability Agent + Monitor

Two things that share one store of measurements.

**The agent** answers a network question in plain language, deciding which measurements to run
against this machine's network and reporting what it found.

```powershell
python net_agent.py "why is github.com slow from here?"
python net_agent.py -v "is my DNS working properly?"  # -v shows each tool call and result
python net_agent.py                                   # interactive; keeps context
```

**The monitor** watches a handful of paths continuously and alerts when something has genuinely
changed — where "genuinely" means the shift exceeds what that path's own history shows it does
on its own. It contains no model call at all.

```powershell
.\install_tasks.ps1                  # run both at every logon (do this once)
python net_alert.py --status         # state per signal
python net_alert.py --log            # what fired, and the evidence for it
python net_db.py                     # look inside the store, read-only
```

**Install it as a scheduled task, not by hand.** Running `python net_collect.py` in a window
works until the machine sleeps, restarts, or you sign out — and then the gap is invisible until
someone asks why there is no data. This was learned the obvious way: an overnight run was set
up by launching both processes detached, the machine was shut down for the night, and seventeen
hours of nothing were collected. A monitor that stops when you log off is not a monitor.

They are useful separately and better together: a measurement the agent takes while answering a
question also feeds the monitor's baselines, and an alert the monitor fires is a question the
agent can be asked to explain.

**No API key needed.** By default it drives the `claude` CLI already installed and logged in
on this machine, so there is no separate credential and no extra cost. If `ANTHROPIC_API_KEY`
is set it uses the Anthropic SDK with native tool use instead. Force either with
`--backend cli` / `--backend sdk`.

| backend | tool calling | needs |
|---|---|---|
| `cli` (default) | model emits JSON, the script parses and executes | the `claude` CLI, already installed |
| `sdk` | native tool use via the SDK's tool runner — more robust | `ANTHROPIC_API_KEY`, billed separately |

The CLI backend trades a little robustness for costing nothing: a malformed JSON reply costs a
retry rather than being impossible by construction. In practice it completes a seven-measurement
diagnosis without a retry.

## Files

| file | what it is |
|---|---|
| `net_tools.py` | the eight diagnostic tools. Importable and runnable on its own — `python net_tools.py` exercises each one |
| `net_store.py` | SQLite store, retention policy, and the network identity (`net_id`) |
| `net_memory.py` | `baseline`, `detect_change`, `can_detect`, `coverage`, and the `assess` statistics behind them |
| `net_precision.py` | `instrument_options` — measures the agent's own instruments to find which could resolve a given change |
| `net_season.py` | tests each signal for a repeatable daily rhythm, and narrows the floor only where one is real |
| `net_size.py` | sets each target's sampling interval from the resolution you need — `python net_size.py [--apply]` |
| `net_verify.py` | checks the agent's claims of change against each path's noise floor, in code rather than by prompt |
| `net_agent.py` | the agent: system prompt, tool wiring, CLI |
| `net_collect.py` | the collector — measures on a schedule, no model call, ever |
| `net_ingest.py` | passive alternative: reads Modbus/TCP response times out of a pcap, for networks you must not probe |
| `net_alert.py` | the evaluator, alert state machine and notifier |
| `net_eval.py` | scores the agent on scenarios with known answers — `python net_eval.py [-r 3]` |
| `test_detect_change.py` | validates the change-detection statistics against injected shifts |
| `test_net_alert.py` | validates the alerting against constructed histories |
| `test_can_detect.py` | validates that the *reason* a change is unresolvable is named correctly |
| `test_net_season.py` | validates that a wandering path is not mistaken for a seasonal one |
| `test_net_size.py` | validates that the sizer never slows an availability check on resolution grounds |
| `test_net_verify.py` | validates that unsupportable claims are caught *and* that plain readings are not |
| `test_net_ingest.py` | validates pcap parsing against a capture whose response times are known by construction |
| `test_net_eval.py` | validates that the eval's deterministic scoring does not fire on correct answers |
| `net_monitor.db` | the store (created on first run; override with `NET_MONITOR_DB`) |
| `monitor.json` | which targets to collect, how often, optional webhook |

## Memory

Every successful measurement is written to `net_monitor.db`, and the `baseline` tool reads it
back. This is what separates an observability agent from a diagnostic one: without history it
can report *"14.4 ms to 1.1.1.1"* but cannot answer the question an operator actually has,
which is **"is that normal?"**. The store improves on its own the more the agent is used.

The agent and the collector write to the **same table**. Two stores would have meant two
disagreeing notions of "normal" for the same host, and an alert the agent would then deny.

### `net_id` — the design point that is easy to miss and expensive to skip

**A laptop moves between networks, and a baseline from one is meaningless on another.** Every
sample is tagged with a network identity, and baselines never cross that boundary:

```
net_id = hash(gateway MAC, local subnet, SSID if wireless)
```

The gateway MAC is the discriminator that actually works — SSIDs collide (`eduroam` is
everywhere) and subnets repeat (`192.168.1.0/24` is in every home). Without this, walking from
home to the office registers as a catastrophic regression and buries every real signal
underneath it. It **cannot be retrofitted**: samples collected without it can never be assigned
to a network after the fact.

Three design points carry most of the value:

**Failures never enter as latencies.** A 5 s timeout is recorded as `reachable: 0.0`, not as a
5000 ms measurement — otherwise a single outage would poison every baseline containing it.

**`baseline` reports sample count and time span alongside every statistic**, and warns when
they cannot support a claim. Fifty samples taken inside one minute describe that minute, not a
norm — no diurnal cycle, no peak-hour congestion, no link flap. The system prompt tells the
agent to read that warning, and it does: asked *"is my latency to 1.1.1.1 normal?"* against a
2-minute-old store, it answered

> *"today's number matches the one previous snapshot I have — I cannot honestly say this is
> normal for your link, because nothing in the record establishes what normal looks like
> across a day"*

and recommended hourly sampling to fix it. A baseline that quietly returns a median over a
40-second burst would have produced a confident, useless "yes".

## Change detection

`baseline` answers *"what is normal?"*. `detect_change` answers the question that follows:
**"has something changed, and is the change real?"**

A percentage on its own decides nothing. *"Latency is up 12%"* is noise on a path that swings
20% between hours and an incident on one stable to 2%. So the tool measures that path's own
noise floor from its history — taking windows from quiet periods, where by construction
nothing happened, and seeing how far their medians stray — then reports the shift against it:

```
  baseline median : 14.02
  recent median   : 21.18
  shift           : +51.1%
  noise floor     : windows of 6 in the quiet history move up to 3.1%
                    (95th pct of 35 placebo windows)
  VERDICT: the shift EXCEEDS what this path's own noise produces (p=0.000). Treat it as real.
  Smallest shift this history could resolve: about 5% (at 80% power).
```

That last line is the one that earns its place. When a change is too small to call, the tool
says so **and** says what size of change it could have resolved — so "I can't tell" comes with
the reason and the remedy, instead of a verdict the data cannot support.

Two implementation notes:

**Placebo windows are contiguous, not random subsets.** Measurements adjacent in time are
correlated; drawing random subsets breaks that correlation and makes the null look tighter
than reality, understating how large a shift has to be to count. This is the same error a
textbook standard error makes on autocorrelated network data, and it is worth several-fold on
real paths.

**Validated against injected shifts of known size**, since on real data nobody knows the right
answer. A 0% shift is never called real (p=0.54, no invented incidents); 50% and 100% shifts
are always caught; a 2% shift on a 5%-noise path is correctly reported as invisible rather
than guessed at. Both failure directions are tested, because they trade off against each
other.

## Knowing when the instrument isn't good enough

`detect_change` answers *"did it change?"*. `can_detect` answers the question that has to come
first: **"could I have seen it if it had?"**

This matters because **"no change detected" means two completely different things** — nothing
happened, or something happened that this setup could never have seen. Reporting the first when
the truth is the second is the worst error the agent can make, because it sounds like an
all-clear.

`can_detect(target, metric, shift_pct)` checks three separate limits and names the one that
binds, because **each has a different remedy and they do not substitute for one another**:

| limit | cause | remedy |
|---|---|---|
| **INSTRUMENT** | the measurement cannot express a change that small | a finer instrument — *more sampling will never help* |
| **STATISTICS** | the path's own variability swamps it at this window size | more samples, and it says how many |
| **COVERAGE** | the history spans no full day-night cycle | wait |

The instrument floor is read **off the data itself** rather than configured. `ping` reports
whole milliseconds and the tool averages `count` of them, so the values land on a 1/count ms
lattice — and the smallest gap between distinct observed values *is* that lattice spacing. A
configured number would be a claim about the tool; this is an observation of it.

Real output, on this machine's gateway:

```
10.50.16.1/rtt_avg_ms: could I detect a 10% change?
  instrument floor : steps of 0.1 on a median of 2 -> nothing below 5.0% is expressible
  statistical floor: 75% at 80% power (483 placebo windows of 60, noise floor 40.0%)
  BINDING LIMIT    : STATISTICS, at 75.0%
  VERDICT: NO. A 'no change' result here would mean 'invisible', NOT 'nothing happened'.
  REMEDY: more history. Even widening the window as far as this record allows does not
          reach 10% on this path - its own variability is too large. The instrument is
          not the limit; the path is.
```

Asked *"has latency to my gateway got 10% worse?"*, the agent now answers:

> *"I can't tell you — and that's a real finding, not a dodge... The binding limit is
> STATISTICS, not the instrument: the ping resolution floor is about 5%, so the instrument is
> fine — the path itself is too variable... a 'no change' verdict here would mean 'invisible',
> not 'nothing happened'. I won't hand you that as an all-clear."*

**Tested on the reason, not just the refusal** (`test_can_detect.py`). Refusing is only useful
if the cause is right: an agent that confuses the two sends an operator to collect a week of
data that cannot possibly answer their question, or to swap instruments when the one they have
is fine. Three paths are constructed where the binding limit is known by construction, plus
checks that an instrument-bound path is *never* told to collect more samples.

### `instrument_options` — what *would* work

Saying "I can't resolve that" is only half an answer. `instrument_options` runs each of the
agent's own instruments several times against the host and reads their resolution off the
results, so the follow-up advice is measured rather than guessed.

It reports two numbers per instrument, and **the usable resolution is the worse of them**:

```
instrument        metric               median     step  scatter   floor  verdict
ping count=5      rtt_avg_ms             1.40    28.6%    40.9%   40.9%  cannot
ping count=20     rtt_avg_ms             3.05     3.3%    36.5%   36.5%  cannot
tcp_latency 443   handshake_avg_ms       4.85     4.1%    54.3%   54.3%  cannot

NONE of these instruments can resolve 10% on this path.
  The closest is ping count=20 at 36.5%, and its limit is run-to-run scatter, not step
  size - the PATH is too variable, and a finer instrument will not help.
```

A tool can report four decimals and still be useless if its readings scatter 40% between
identical runs. Here `ping count=20` improves the *step* eightfold (28.6% → 3.3%) and changes
nothing, because scatter binds — which independently confirms what `can_detect` concluded from
stored history by a completely different route.

It also refuses to pretend the instruments are interchangeable: ICMP round-trip time and TCP
handshake time differ by the server's accept path, so switching means **starting a new
baseline**, and it says so rather than silently changing what a number means.

### `coverage` — knowing when it wasn't looking

An absence of data is not an absence of problems. Asked *"was there a problem last night?"*, an
agent with a 16-hour hole in its record will happily answer from the data on either side, with
the same confidence as a fully observed period. That is the easiest way for this agent to be
confidently wrong.

The collector writes a heartbeat every cycle whether or not a probe succeeded, so gaps are
identifiable after the fact. Real output:

```
measurement coverage on network 'office-wifi', last 48 h
  659 cycles, roughly every 1.0 min
  covered 19% of the period
  3 gap(s) where NOTHING was measured:
    03 Sep 16:17 -> 04 Sep 09:18  (17.0 h)
  Do not describe these periods as quiet or healthy. They were not observed.
```

And the agent's answer to that question now opens:

> *"I can't tell you, and that is the honest finding — last night was not measured... Anyone
> telling you the night looked quiet is reading data from either side of a gap."*

## The monitor

```
 collector  ──▶  store  ──▶  evaluator  ──▶  notifier
  (dumb,        (sqlite)      (stats)       console / log
  periodic)         │                        / webhook
                    ▼
                  agent  ◀── on demand only, to explain an alert
```

### The LLM is not in the measurement loop

The collector and evaluator are deterministic code. No model call runs on the sampling path.
Three reasons, in order of how much they matter:

1. **Cost.** A model call per target per interval is unbounded spend for work arithmetic does
   correctly.
2. **Latency.** A 60-second sampling interval cannot accommodate a 60-second reasoning step.
3. **Reproducibility.** An alert that fires or not depending on sampling temperature is not an
   alert, it is a rumour.

The agent is called for exactly one thing, off the hot path: **explaining an alert the
evaluator already decided to fire**. The evaluator can say *that* something changed, never
*why*.

### Four rules, each for a specific way monitors fail

| rule | the failure it prevents |
|---|---|
| nothing immature ever alerts (30 samples over 6 h) | a monitor that shouts an hour after installation gets turned off |
| the threshold is the path's own noise | a fixed threshold cannot be right for a path that swings 20% *and* one stable to 2% |
| k = 3 confirmations to fire, 3 to clear | a signal on the boundary flaps, and flapping alerts train people to ignore alerts faster than false ones do |
| no collector heartbeats → no evaluation | a closed laptop lid is not an outage |

The heartbeat rule needs the store to distinguish **"we did not measure"** (asleep, stopped)
from **"we measured and nothing answered"**. The collector writes one every cycle whether or
not any probe succeeded, so a gap is identifiable after the fact.

### Detectable is not the same as worth telling you about

The test suite found this, and it is a real gap rather than a bug. On a path stable enough, a
**+0.9% shift is statistically undeniable** — noise floor 0.4%. The detector was right and the
alert would have been useless.

So a shift must clear **two** bars: beyond the path's own noise (statistics), and at least
`MIN_PRACTICAL_SHIFT`, default 10% (relevance). That second number is the one a human is
supposed to choose, because only a human knows what matters to them.

The comparison it enables is the interesting part. `MIN_PRACTICAL_SHIFT` is the shift you asked
to hear about; the MDE is the smallest shift the path can actually resolve. When the MDE is
larger, the monitor is **under-instrumented for its own stated goal** and says so:

```
1.1.1.1   rtt_avg_ms   OK   +4.2%   9.1%   can only resolve 22%, goal is 10%
```

That line is a silent miss made visible. It is also the hook for the next version: a monitor
that reads it can size its own sampling to meet the goal, instead of leaving an interval a
human typed once and never revisited.

### An alert carries the evidence that justified it

An alert that says "latency high" is a static-threshold alert wearing better clothes.

```
ALERT  1.1.1.1 / rtt_avg_ms   on net 'office-wifi'
  baseline median : 14.40   (7 d, 412 samples)
  now             : 16.60   (last 1 h, 23 samples)
  shift           : +15.3%
  noise floor     : 6.2%   (95th pct of 380 placebo windows)
  confirmed       : 3 consecutive evaluations over 18 min
  smallest shift this history could resolve: 8%   (you asked about 10%)
```

**This format caught a bug in the tool itself on its first live alert.** The real one read
`noise floor: 0.0% (95th pct of 5 placebo windows)`. Five windows is not a distribution — with
27 baseline samples and a 23-sample recent window there are only 5 contiguous positions and
they overlap almost entirely, so the floor collapsed to zero and *any* shift cleared it. The
guard was `len(devs) < 5` and it passed by one; it is now `MIN_PLACEBO_WINDOWS = 20`, and the
refusal states what is missing and how much history would fix it.

A monitor that had printed "latency up 15%" would have taught its operator to trust a number
that meant nothing. Reporting the instrument's resolution alongside the reading is what made
the defect visible in the output rather than in the alert count six months later.

### Validated against constructed histories

Real history takes days to accumulate, so the interesting cases are injected, where the right
answer is known by construction. `python test_net_alert.py` — 13 checks:

| path | injected | required behaviour |
|---|---|---|
| stable, +50% | a genuine incident | alerts, and **only on the third** confirmation |
| stable, +1% | real but trivial | never alerts — under the relevance bar |
| drifting ±25%, +10% | a shift the path cannot resolve | never alerts; **a fixed 10% threshold would have fired** |
| 12 samples / 20 min | a blatant shift, no history | stays `UNKNOWN` |
| thin baseline, dense recent | the degenerate case above | refuses, does not alert |

The two middle rows are the design from both ends: a shift big enough to matter that the path
cannot resolve, and a shift the path resolves easily that is too small to matter. A monitor
needs both tests and almost none have either.

## Working from a capture instead of probing

`net_collect.py` measures by sending traffic. On an industrial or otherwise sensitive network
that is often forbidden and sometimes unsafe — a control loop with a cyclic budget does not
want extra packets in it, and ICMP is frequently disabled on the switches anyway. Industrial
monitoring is passive: a SPAN port, a TAP, or a stored capture.

```
python net_ingest.py clean.pcap --db ics.db
```

Modbus/TCP carries a transaction identifier in its MBAP header and the server echoes it, so
pairing request to response gives a genuine response time per transaction. Nothing downstream
changes: `net_memory`, `net_alert`, `net_size` and `net_verify` only ever see
`(ts, target, metric, value)` and do not care whether a number came from a probe this machine
sent or from a conversation it merely watched.

On a two-server capture it separates the causes correctly:

```
10.0.0.90:1  steps of 0.0999 on a median of 4     BINDING LIMIT: INSTRUMENT at 2.5%
             -> a finer instrument; more samples will not help
10.0.0.91:1  noise floor 4.1%, median 12.1        BINDING LIMIT: STATISTICS at 10.0%
             -> widen the window: 636 samples instead of 159
```

The `0.0999` step is the **capture clock's own resolution**, read off the data by `_quantum`.
That is the reason to use a real capture rather than a simulator: a simulated noise floor is
whatever you programmed it to be, so measuring it measures your random number generator.

**Two things it does deliberately, and states rather than hides.**

*It writes under the capture's own network identity, never the live one.* Baselines are
per-network so one path's normal is never compared against another's, and a factory capture
must not contaminate the baseline for your office Wi-Fi. Set `NET_REPLAY_ID` to that identity
and every tool adopts it:

```
set NET_MONITOR_DB=ics.db
set NET_REPLAY_ID=fb435ebecc3e
python net_size.py --goal 5
```

*It shifts the timestamps so the capture ends "now".* Every analysis function asks for the
last N days against the current clock, so a 2016 capture would otherwise be silently invisible
to all of them. Only the epoch offset moves — intervals, gaps and ordering are preserved
exactly — and the capture date goes into the network label so a replay can never be mistaken
for live measurement. `--no-shift` keeps the real times, and then the tools find nothing,
which is why it is not the default.

**Captures need shorter windows than live monitoring.** A 30-minute capture cannot fill the
2-hour default comparison window; it yields one placebo window and the honest answer is
`UNKNOWN`. Pass `--recent-hours 0.05` or similar and it calibrates properly.

### On a real capture

[Lemay's CSET'16 Modbus dataset](https://github.com/antoine-lemay/Modbus_dataset), 6-RTU
polling, 58,325 packets over 59 minutes, captured February 2015. Every request paired to its
response — 1071 transactions per RTU, six RTUs, none unmatched.

```
192.168.1.101:1   1071 samples over 1.0 h, median 0.78 ms
  instrument floor : steps of 0.000238 ms on a median of 0.78  ->  0.0%
  statistical floor: 10% at 80% power (967 placebo windows of 105, noise floor 8.6%)
  BINDING LIMIT    : STATISTICS, at 10.0%

  a 5% change  -> NO.  "no change" here would mean invisible, not absent
  a 20% change -> YES. "no change" here is real evidence of no change
```

Worth noting which way round that is. On the laptop, `ping` reports whole milliseconds and the
**instrument** binds. On a capture the clock is microsecond-resolution, so the instrument floor
is effectively zero and the **path's own variance** binds instead. Passive observation gives
better resolution than active probing, not worse.

**The first real capture also exposed a silent data loss in the store.** The sample table's
primary key is `(target, metric, ts)` and `ts` was truncated to whole seconds, so measurements
taken within the same second overwrote one another — `INSERT OR REPLACE` reporting success
every time. These RTUs are polled in bursts of three transactions inside one second, every ten
seconds, so exactly two thirds of the data vanished on the way in, and a noise floor was then
computed confidently on the third that survived. The live collector polls at 60 s and had never
met it. Timestamps now keep microsecond precision, and the ingester counts what is *in the
table* rather than what it handed over, warning if the two differ.

`--bin S` aggregates to one median per S seconds for very dense captures. It also destroys the
instrument quantum, so the reported step afterwards describes the binning rather than the
capture.

## Seasonality: is the noise really noise, or just the time of day?

Every `can_detect` answer already ends with a confession — *"history contains no full
day-night cycle, so both floors above may be optimistic."* Once there **is** more than a day
of history the opposite error appears and nothing warns about it: a Tuesday-15:00 window gets
scored against a baseline containing Sunday 03:00, so any daily swing is counted as noise and
the floor comes out wider than the path deserves.

```
python net_season.py
```

**Measured, not assumed.** Seasonality is not switched on because monitoring tools have it.
Each signal is tested, and a path with no repeatable rhythm pays nothing and is told so:

```
10.50.16.1  rtt_avg_ms   swing 34%  p=0.008   floor 75% -> 22% comparing like with like
1.1.1.1     rtt_avg_ms   swing  6%  p=0.29    no repeatable daily shape; nothing changed
```

**The test is repeatability, not size.** A wandering path produces a large hourly swing with
no rhythm at all, so size decides nothing. The history is split in half, an hourly profile
built for each and normalised by that half's own median — so a drifting *level* cannot pose as
*shape* — and the two are rank-correlated. A real rhythm has the same busy hours in both
halves. The null needs no simulation: rotating one profile against the other by 1–23 hours
enumerates every alternative alignment exactly.

**A first version of this test had no power, and the reason is kept in the code.** It compared
the hourly spread against a circularly shifted copy of the series, on the reasoning that
rotation preserves autocorrelation while destroying alignment to the clock. It preserves more
than that — rotating a series whose period *is* 24 h gives another series with the same 24 h
period, moving only the phase and leaving the hourly spread untouched. The null reproduced the
signal it was meant to remove, and a textbook sine wave scored **p = 0.68**.
`test_net_season.py` still runs that null against a known rhythm (p = 0.85, blind to it)
alongside the real one (p = 0.042), so the failure stays visible rather than being
rediscovered.

## Self-sizing: setting the sampling rate from the resolution you need

```powershell
python net_size.py              # what each interval should be, and why
python net_size.py --goal 5     # to resolve 5% shifts instead of 10%
python net_size.py --apply      # rewrite monitor.json (backs up the old one)
```

Every monitor takes its sampling rate from a human who guessed once and never revisited it. But
the rate determines what can be **resolved**, and that number is already computed per signal. So
the loop closes: given a stated goal, each interval is set to the rate that meets it — and the
signals where **no rate would** get named instead of silently missed.

```
1.1.1.1     rtt_avg_ms         61s   20%  SPEED UP      needs ~118 samples/window -> 31s
                                                        EXTRAPOLATED: treat as a lower bound
1.1.1.1     query_ms          301s  150%  UNACHIEVABLE  no window reaches 10%
10.50.16.1  rtt_avg_ms         61s   75%  UNACHIEVABLE  no window reaches 10%
1.1.1.1     reachable          61s     -  KEEP          availability: fires in ~183s
```

**Backing off is exact; speeding up is an extrapolation.** A 120 s series is the 60 s series
with every second sample dropped, so the noise floor at a *longer* interval is computed directly
from data already held — no assumption. There is no data at a *finer* interval, and samples
closer in time are more correlated, so the effective sample size grows more slowly than the
count. Every speed-up is therefore a **lower bound**, and is labelled rather than quoted.

### The mistake this made on its first real run

It proposed slowing gateway reachability from **61 s to 732 s**, on the grounds that the metric
"resolves 2%".

That number is the grid floor on a signal that sits constantly at 1.0 — a measurement of
nothing. And applying it would have made a twelve-minute outage invisible, which is the most
basic thing the monitor is for.

**Availability metrics are not a resolution question at all.** "How small a shift can I see" is
meaningless for a host that has never failed; the real question is "how long until I notice it
stopped answering", which is a *latency* requirement and points the opposite way — it puts a
**ceiling** on the interval rather than licensing a longer one. `reachable`, `ok_2xx`,
`loss_pct`, `success_rate` and `open` are now sized by `--detect-within` and the confirmation
count, and the noise floor never enters. `test_net_size.py` exists mainly to keep it that way.
listener, or writes to the network beyond the probe itself. An agent that can only observe
cannot break what it is diagnosing.

| tool | answers |
|---|---|
| `local_network` | what is this machine's own config? interfaces, addresses, gateway, DNS servers |
| `dns_lookup` | does the name resolve, how fast, and via which server |
| `ping` | ICMP round-trip time and loss |
| `tcp_latency` | handshake latency in pure Python — works where ICMP is filtered |
| `check_port` | is one specific TCP port accepting connections |
| `http_check` | does the server actually *serve*, or just answer TCP |
| `traceroute` | where along the path does latency appear |

## Verifying the agent's own answers

The system prompt asks the model never to let *"I couldn't see it"* read as *"it didn't
happen"*. Asking is not enforcing. Nothing in a prompt prevents a fluent, specific, confident
claim that the gateway latency rose 12% — on a path whose smallest detectable shift is 50%.

So the check moved out of the prompt and into code. Every answer is re-examined against the
same statistics the monitor alerts on, and the report is **appended, never substituted** —
editing the model's words would hide the disagreement, and the disagreement is the point.

```
$ python net_verify.py "Latency to 10.50.16.1 rose 12% overnight, while 1.1.1.1
                        stayed flat at 13.8 ms. The handshake to 1.1.1.1 increased by 30%."

VERIFIER: 2 claim(s) of change checked against the noise floor (3 number(s) seen in total)
  !!  'rose 12%'           UNSUPPORTABLE   10.50.16.1/rtt_avg_ms resolves no better than 50%;
                                           a 12% claim is below the floor and could not have
                                           been seen whatever window was used
  !!  'increased by 30%'   UNSUPPORTABLE   1.1.1.1/handshake_avg_ms resolves no better than 50%
  2 claim(s) BELOW the floor. The instrument could not have seen a change that small,
  so the answer asserts more than the measurements support.
```

It runs automatically inside `net_agent.py`; `--no-verify` turns it off.

**The distinction it turns on.** `13.8 ms` in that example was *not* flagged, and must not be:

| | |
|---|---|
| `RTT to 1.1.1.1 is 13.8 ms` | a **reading**. The instrument reported it. Not checked. |
| `RTT to 1.1.1.1 rose 4%` | an **inference** about a difference between two windows. The noise floor governs whether it could have been seen at all. Checked. |

Flagging readings would put a warning on every honest answer, and warnings that fire on
correct output get ignored — which would quietly restore the failure this is meant to prevent.

**Why the claim is compared to the floor and not to a recomputed shift.** The agent may be
talking about a window this module cannot know (*"overnight"*, *"since the meeting"*).
Recomputing a shift over some default window would manufacture disagreements that are
artefacts of window choice.

**And the floor is taken across windows, not from one.** The floor *does* move with the
comparison window, so checking a single window and concluding "no window could have seen this"
is the same overclaim this project exists to prevent. `best_floor` tries 1, 2, 6, 12 and 24
hours and keeps the **smallest** — the reading most favourable to the agent. Being generous is
deliberate: it means every surviving flag is one the agent genuinely cannot defend.

### What the first real answer exposed

Both bugs below were found by running it on live agent output, not by the test suite, and both
are now covered by tests.

**It missed everything.** The agent wrote `a −20% shift` and `median 2.00 → 1.60 ms`; the
verifier reported *"no claims of change found (22 numbers, all read as measurements)"*. The
minus sign was **U+2212**, not ASCII `-`, so `[+-]` could never match it, and arrow transitions
were not a recognised form at all. Typographic characters are now normalised, and `X → Y`,
`from X to Y` and `20–40%` ranges are all read as claims — while `13:27 → 16:26` is not, since
clock times take exactly the same shape.

**Its wording was the real failure.** *"All read as measurements"* asserted the answer had been
examined and cleared, when in fact nothing had matched. An empty result is a statement about
the patterns, not about the answer, and it now says so.

**It then overclaimed in the opposite direction.** With the parsing fixed, it flagged a −40%
claim using a 75% floor from its 2 h default — while the agent had correctly measured 35% over
6 h. Hence `best_floor`. On the same text it now flags one borderline claim instead of five.

**It does not claim to read English completely.** Claims are found with regular expressions and
some phrasings will be missed. A verifier that quietly misses claims is worse than none,
because it turns *unchecked* into *looks checked* — so every report prints how many numbers it
saw against how many it could attribute, and unattributable claims are listed as
`UNKNOWN TARGET` rather than passed. If the verifier itself throws, the answer is marked
**UNCHECKED** instead of being returned bare.

`python test_net_verify.py` — 13 checks, covering both failure directions.

## Evaluation

`python net_eval.py` scores the agent on scenarios whose correct answer is known *by
construction* — RFC-reserved addresses and a reachable host with a closed port, so nothing on
the machine has to change.

Scoring is split, because prose is hard to grade and tool choice is not. **Deterministic**
checks ask which tool it reached for and whether it uttered a forbidden claim (regexes like
`\bhost is (down|unreachable)\b`); an agent that never calls `check_port` on the closed-port
scenario has established nothing, whatever its answer says. **Judged** checks grade the
verdict against a written expectation in a separate model call.

Results over two independent passes, 10 scenarios each:

| metric | result |
|---|---|
| overall correct | **1.00** (20/20) |
| invented a fault | **0.00** — the one that matters |
| used a discriminating tool | 1.00 |
| forbidden claims | 0/20 |
| strayed off scope | 0.60 |
| tool calls per question | median 6–8, max 17 |

The categories matter more than the headline. **CLEAN** scenarios — two false premises, a
healthy site, loopback — test whether it invents problems on working systems, which is the
failure that makes a diagnostic agent worse than none. **CALIBRATION** scenarios have no
determinable answer from this vantage point; the correct response is to say so.

Two honest caveats. **20 runs at 100% still admits a true error rate near 15%** (upper 95%
bound ≈ 0.17) — two clean passes are encouraging, not proof. And the scenarios are the
author's, so they test what he thought to test.

### A change that did not work

The 0.60 off-scope rate prompted adding a stopping rule to the system prompt (point 5: stop
when the question is answered; an undecidable question is answered once the boundary is
established; out-of-scope findings get one line, not an investigation).

**It made no measurable difference.** Off-scope stayed at 0.60, `undecidable` still took 17
calls, and although the median fell from 8 to 6 the *total* calls rose from 76 to 79 — the
median moved because noise redistributed, not because anything improved. At one run per
scenario the experiment cannot resolve an effect this size, and reading the median as a win
would have been exactly the error the harness exists to catch.

The rule is kept because it is sensible guidance and costs nothing, **not** because it was
shown to help. Verbosity costs latency, not correctness: accuracy is unchanged, and the agent
still answers a trivial question (`is 127.0.0.1 reachable?`) in one call.

## How it approaches a question

The system prompt encodes a diagnostic order rather than letting the model improvise:

1. **Baseline first.** For any broad symptom, check local config — a missing gateway or an
   unreachable resolver explains every downstream failure at once.
2. **Separate the layers.** Name resolution → reachability → transport → application. These
   fail independently and users conflate them.
3. **Never read ICMP loss as proof a host is down.** Many networks drop ping while passing
   traffic; confirm with `tcp_latency` first.
4. **Compare against a reference.** A latency number alone means little. The same measurement
   to `1.1.1.1` distinguishes "this destination" from "this machine's connectivity".
5. **Say what was measured vs. inferred.** An operator acting on a confident wrong diagnosis
   is worse off than one told the data was inconclusive.

## Notes on the implementation

- **No `shell=True`, ever**, and every host argument is validated against a strict character
  set before reaching a subprocess — a hostname cannot smuggle in a second command.
- **Locale-independent parsing.** Windows `ping`/`tracert` print in the system language, so
  nothing depends on English words. Per-packet RTTs are taken only from lines containing
  `TTL=` (never translated); the raw output is returned too, so the model can read what the
  parser could not.
- **Caps on everything** — ping count ≤ 20, hops ≤ 30, one port per `check_port` call. These
  are diagnostics for hosts the operator names, and the caps stop a mistyped argument from
  turning one into a scan.
- **A failed probe is data.** Tool errors are returned to the model as text rather than raised,
  so it can see what went wrong and correct itself instead of the run aborting.

## A real example

Asked *"Is UDP DNS blocked on this network, or are my resolvers just dead?"*, the agent found
a genuine misconfiguration on the development machine and, in doing so, **falsified its own
earlier hypothesis**.

It queried `8.8.8.8` over both transports, then each configured resolver in turn:

| resolver | UDP/53 | TCP/53 | ICMP |
|---|---|---|---|
| `192.168.88.1` | timeout 5.0 s | — | 100% loss |
| `203.0.113.140` | timeout 5.0 s | timeout 5.0 s | 100% loss |
| `203.0.113.141` | timeout 5.0 s | — | — |
| `1.1.1.1` | **NOERROR 13.7 ms** | — | — |
| `8.8.8.8` | **NOERROR 19.2 ms** | **NOERROR 32.4 ms** | 0% loss |

Its conclusion: *"A filter blocks a protocol; this blocks everything."* UDP/53 is not filtered
— the signature of filtering is TCP succeeding while UDP times out **to the same server**, and
that appears nowhere. It also noted that a captive resolver hijacking UDP/53 would have
returned *different data* on the TCP path, and the answers matched — ruling out interception
too, a check the tools were never explicitly designed for.

The actual fault: `192.168.88.1` is on `192.168.88.0/24` while the machine is on
`10.50.16.0/24` — a leftover from another network with no route to it. The `203.0.113.x`
pair are internal resolvers from a different site, unreachable from here. Both sit *ahead* of the working
public resolvers in the adapter's list, so every cold lookup burns three full timeouts before
falling through. Windows hides this; anything honouring the list order (`dig`, dnspython, most
container stacks) stalls or fails outright.

Two things about this run matter more than the diagnosis:

**It contradicted itself when the evidence changed.** Before `dns_query_server` existed, the
agent twice named UDP/53 filtering as its leading hypothesis — a reasonable inference it could
not test. Given the tool, it tested it and reported it wrong.

**It states what it did not establish.** Here: whether the campus resolvers are down or merely
source-restricted, which it cannot tell from off-campus — and it named the measurement that
would settle it. An operator acting on a confident wrong diagnosis is worse off than one told
the data was inconclusive.
