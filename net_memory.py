"""Measurement history - what turns this from a diagnostic tool into an observability one.

Without history an agent can report "14.4 ms to 1.1.1.1" but cannot answer the question an
operator actually has, which is "is that normal?". Every measurement is therefore stored, and
`baseline` and `detect_change` read it back. Answers stop being bare numbers and become
comparisons, and the store improves on its own the more the agent is used.

STORAGE IS THE MONITOR'S SQLITE DATABASE (net_store), not a private file. The agent and the
background collector now write to and read from the same table, so a measurement taken while
answering a question also feeds the monitor, and vice versa. Two stores would have meant two
disagreeing notions of "normal" for the same host.

EVERYTHING IS SCOPED TO THE CURRENT NETWORK. Baselines never cross a net_id boundary, because
a baseline gathered at home says nothing about the same host measured from the office - and
this machine moves. Without that separation, walking between buildings looks like a
catastrophic regression and buries every real signal.

Three deliberate choices:

* Tools keep returning plain text; numbers are extracted here by a parser that knows their
  formats. If a format ever drifts this degrades to "no metrics recorded" rather than breaking
  the tool.
* Failures never enter as latencies. A 5 s timeout is stored as reachable=0, not as a 5000 ms
  measurement - one outage would otherwise poison every baseline containing it.
* Both tools report SAMPLE COUNT and TIME SPAN alongside every statistic. A median over three
  samples from one afternoon is not a baseline, and an agent that cannot see the difference
  will state it with the same confidence as one over three hundred.
"""
from __future__ import annotations

import os
import re
import statistics
import time
from typing import Any, Optional

import net_store

# Which argument names a measurement's subject, per tool. Order matters: first match wins.
_TARGET_KEYS = ("host", "server", "url", "name")

# How many placebo windows a noise floor needs before it means anything.
#
# The count is len(base) - k + 1, so when the recent window is nearly as large as the baseline
# there are only a handful of positions and they overlap almost completely. Their medians are
# then all the same number, the "95th percentile of the null" comes out at ~0%, and every
# shift clears it. That failure is worse than having no detector, because it produces a
# confident verdict with a real-looking statistic attached.
#
# This was found the way it should be: an alert fired on live data carrying the line
# "95th pct of 5 placebo windows", and the evidence in the alert is what exposed it.
MIN_PLACEBO_WINDOWS = 20

# Effect sizes searched when reporting the minimum detectable shift. Shared by detect_change
# and can_detect so the two can never quote different resolutions for the same signal.
_MDE_GRID = [0.02, 0.05, 0.10, 0.20, 0.35, 0.50, 0.75, 1.00, 1.50, 2.00]


def _target_of(args: dict) -> Optional[str]:
    for k in _TARGET_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _f(pattern: str, text: str) -> Optional[float]:
    m = re.search(pattern, text, re.I)
    if not m:
        return None
    try:
        return float(m.group(1).replace(",", "."))
    except ValueError:
        return None


def extract_metrics(tool: str, text: str) -> dict[str, float]:
    """Pull the numbers out of a tool's own output format.

    Only records a metric when the measurement SUCCEEDED - a timeout must not enter the store
    as a latency of 5000 ms, or every baseline containing one failure would be poisoned. A
    failure is recorded as reachable=0.0 instead, which is its own trendable signal.
    """
    m: dict[str, float] = {}
    if tool == "ping":
        for k, pat in (("rtt_min_ms", r"min=([0-9.]+)"),
                       ("rtt_avg_ms", r"avg=([0-9.]+)"),
                       ("rtt_max_ms", r"max=([0-9.]+)"),
                       ("loss_pct", r"loss_percent_reported=([0-9.]+)")):
            v = _f(pat, text)
            if v is not None:
                m[k] = v
        m["reachable"] = 1.0 if "rtt_avg_ms" in m else 0.0
    elif tool == "tcp_latency":
        ok, failed = _f(r"succeeded=([0-9]+)", text), _f(r"failed=([0-9]+)", text)
        for k, pat in (("handshake_min_ms", r"min=([0-9.]+)"),
                       ("handshake_avg_ms", r"avg=([0-9.]+)"),
                       ("handshake_max_ms", r"max=([0-9.]+)")):
            v = _f(pat, text)
            if v is not None:
                m[k] = v
        if ok is not None and failed is not None and (ok + failed) > 0:
            m["success_rate"] = ok / (ok + failed)
        m["reachable"] = 1.0 if "handshake_avg_ms" in m else 0.0
    elif tool == "dns_lookup":
        v = _f(r"resolved_in_ms=([0-9.]+)", text)
        if v is not None:
            m["resolve_ms"] = v
        m["reachable"] = 1.0 if v is not None else 0.0
    elif tool == "dns_query_server":
        v = _f(r"elapsed_ms=([0-9.]+)", text)
        if v is not None and "NOERROR" in text:
            m["query_ms"] = v
        m["reachable"] = 1.0 if v is not None and "NOERROR" in text else 0.0
    elif tool == "check_port":
        if "OPEN" in text:
            v = _f(r"connect_ms=([0-9.]+)", text)
            if v is not None:
                m["connect_ms"] = v
            m["open"] = 1.0
        else:
            m["open"] = 0.0
    elif tool == "http_check":
        st, el = _f(r"status=([0-9]+)", text), _f(r"elapsed_ms=([0-9.]+)", text)
        if st is not None:
            m["http_status"] = st
            m["ok_2xx"] = 1.0 if 200 <= st < 300 else 0.0
        if el is not None and st is not None:
            m["response_ms"] = el
        m["reachable"] = 1.0 if st is not None else 0.0
    return m


# --------------------------------------------------------------------------- storage

_CONN = None


def conn():
    global _CONN
    if _CONN is None:
        _CONN = net_store.connect()
    return _CONN


def record(tool: str, args: dict, output: str) -> None:
    """Store one measurement, tagged with the current network. Never raises - losing history
    must not break a diagnosis in progress."""
    try:
        target = _target_of(args)
        metrics = extract_metrics(tool, output or "")
        if not target or not metrics:
            return
        net = net_store.network_identity()
        c = conn()
        net_store.remember_net(c, net)
        net_store.add_samples(c, target, metrics, net["net_id"])
        c.commit()
    except Exception:
        pass


def _rows(target: str, days: float, metric: str = "") -> tuple[list[tuple], dict]:
    """(ts, metric, value) for one target on the CURRENT network only."""
    net = net_store.network_identity()
    cutoff = int(time.time() - days * 86400)
    sql = ("SELECT ts, metric, value FROM sample "
           "WHERE target=? AND net_id=? AND ts>=?")
    params: list[Any] = [target, net["net_id"], cutoff]
    if metric:
        sql += " AND metric=?"
        params.append(metric)
    return list(conn().execute(sql + " ORDER BY ts", params)), net


# --------------------------------------------------------- beyond the raw retention horizon
#
# Raw samples are deleted after net_store.RAW_RETENTION_DAYS and rolled into hourly rows kept
# for a year. Until this was written, NOTHING read those rows: every reader here, in
# net_season and in net_size queried `sample` alone. The consequence was not a missing feature
# but a false statement - `baseline("1.1.1.1", days=90)` answered "No history for '1.1.1.1' on
# this network in the last 90 days" while ninety days of it sat in the same file, summarised.
# Saying "I have no record" when the record exists is the same class of error as claiming a
# change that is not there, and it was ten days from firing for the first time.
#
# The split below is not symmetry for its own sake. Rolled-up rows may describe what a path
# USED to look like, and may never be used to decide what can be DETECTED, because an hourly
# mean of ~12 samples varies far less than the samples do. A placebo floor calibrated on them
# would come out narrow, and the tool would announce it could resolve shifts it cannot see -
# which is exactly the over-claim the whole project is built to avoid. So `baseline` reads
# them, and every floor stays on raw data and says out loud where its horizon is.

RAW_DAYS = net_store.RAW_RETENTION_DAYS


def _hourly(target: str, days: float, metric: str = "") -> list[tuple]:
    """(hour, metric, mean, lo, hi, n) from the rolled-up table, current network, oldest first.

    Bounded ABOVE by the raw horizon as well as below by `days`, so these rows never overlap
    the raw ones and a reader cannot double-count the same hour.
    """
    net = net_store.network_identity()
    now = time.time()
    c_mean, c_lo, c_hi = net_store.hourly_cols(conn())
    sql = (f"SELECT hour, metric, {c_mean}, {c_lo}, {c_hi}, n FROM sample_hourly "
           "WHERE target=? AND net_id=? AND hour>=? AND hour<?")
    params: list[Any] = [target, net["net_id"], int(now - days * 86400),
                         int(now - RAW_DAYS * 86400)]
    if metric:
        sql += " AND metric=?"
        params.append(metric)
    return list(conn().execute(sql + " ORDER BY hour", params))


def _rolled_up_section(target: str, days: float, metric: str = "") -> str:
    """Describe pre-horizon history, or return "" when there is none in the asked-for window."""
    rows = _hourly(target, days, metric)
    if not rows:
        return ""
    by_metric: dict[str, list[tuple]] = {}
    for _h, m, mean, lo, hi, n in rows:
        by_metric.setdefault(m, []).append((mean, lo, hi, n))
    span_d = (rows[-1][0] - rows[0][0]) / 86400.0
    out = [f"  ---- older than {RAW_DAYS:g} days: rolled up, {len(rows)} hourly rows spanning "
           f"{span_d:.1f} days ----"]
    for m, vals in sorted(by_metric.items()):
        means = [v[0] for v in vals]
        out.append(f"  {m:18} hours={len(vals)} samples={sum(v[3] for v in vals)} "
                   f"mean-of-hourly-means={statistics.mean(means):.1f} "
                   f"min={min(v[1] for v in vals):.1f} max={max(v[2] for v in vals):.1f}")
    out.append("  These are hourly summaries, not measurements: the raw samples behind them "
               "were deleted. Use them to say what this path USED to look like. They cannot "
               "support a change verdict or a resolution limit, because the spread of hourly "
               "means understates the spread of the samples they came from.")
    return "\n".join(out)


def _horizon_note(days: float, for_floors: bool) -> str:
    """Say when a requested window reaches past the raw data, instead of silently shortening."""
    if days <= RAW_DAYS:
        return ""
    if for_floors:
        return (f"  HORIZON         : you asked for {days:g} days; raw samples are kept for "
                f"{RAW_DAYS:g}, so this used the last {RAW_DAYS:g} days. Older history exists "
                f"only as hourly summaries and is deliberately excluded here - a floor "
                f"calibrated on hourly means would come out too narrow and overstate what "
                f"this path can resolve. Use baseline to see the older period.")
    return (f"NOTE: {days:g} days were asked for; raw samples reach back {RAW_DAYS:g} days. "
            f"Anything older is reported separately below, from hourly summaries.")


def _describe(values: list[float]) -> str:
    n = len(values)
    if n == 1:
        return f"n=1 value={values[0]:.1f}  (a single sample is not a baseline)"
    vs = sorted(values)
    med = statistics.median(vs)
    if n >= 4:
        q = statistics.quantiles(vs, n=20)      # 5% steps
        return (f"n={n} median={med:.1f} p05={q[0]:.1f} p95={q[18]:.1f} "
                f"min={vs[0]:.1f} max={vs[-1]:.1f}")
    return f"n={n} median={med:.1f} min={vs[0]:.1f} max={vs[-1]:.1f}  (few samples)"


# --------------------------------------------------------------------------- tools

def baseline(target: str = "", metric: str = "", days: float = 7.0) -> str:
    """Look up what past measurements of a host normally look like, from stored history.

    Call this BEFORE concluding that a number is good or bad. A latency of 40 ms means nothing
    on its own - it is unremarkable for a distant host and alarming for the local gateway. This
    is the only tool that can tell you which.

    History is scoped to the network this machine is currently on, so a baseline gathered
    elsewhere is never mixed in.

    Always check the sample count and time span it reports. A median over three samples taken
    in one afternoon is not a baseline, and saying "this is normal" on that basis is a guess
    wearing a statistic's clothes. Say so plainly when the history is thin.

    Args:
        target: Host, IP or URL to look up, e.g. "1.1.1.1". Leave empty to list every target
            that has recorded history.
        metric: Which metric, e.g. "rtt_avg_ms", "handshake_avg_ms", "query_ms", "loss_pct",
            "reachable". Leave empty to see every metric held for that target.
        days: How far back to look, in days.
    """
    net = net_store.network_identity()
    cutoff = int(time.time() - days * 86400)
    if not target:
        rows = list(conn().execute(
            "SELECT target, COUNT(*) FROM sample WHERE net_id=? AND ts>=? "
            "GROUP BY target ORDER BY COUNT(*) DESC LIMIT 30", (net["net_id"], cutoff)))
        older = list(conn().execute(
            "SELECT target, SUM(n) FROM sample_hourly WHERE net_id=? AND hour>=? "
            "GROUP BY target ORDER BY SUM(n) DESC LIMIT 30", (net["net_id"], cutoff)))
        tail = ""
        if older:
            tail = (f"\nOlder than {RAW_DAYS:g} days, as hourly summaries only: "
                    + ", ".join(f"{t} ({c})" for t, c in older))
        if not rows:
            if older:
                return (f"No raw samples on network {net['label']!r} in the last {days:g} "
                        f"days.{tail}")
            return (f"No history on network {net['label']!r} in the last {days:g} days. "
                    f"Measurements taken now will build it. (Other networks may have history; "
                    f"it is deliberately not mixed in.)")
        return (f"Targets with history on network {net['label']!r}, last {days:g} days: "
                + ", ".join(f"{t} ({c})" for t, c in rows) + tail)

    rows, _ = _rows(target, days, metric)
    rolled = _rolled_up_section(target, days, metric)
    if not rows:
        if rolled:
            # Not "no history" - history that outlived its raw samples. Reporting the first
            # when the truth is the second is a false statement about what is known.
            return (f"No raw samples for {target!r} on network {net['label']!r} in the last "
                    f"{days:g} days - they are kept for {RAW_DAYS:g} days. Rolled-up history "
                    f"does survive:\n" + rolled)
        known = [r[0] for r in conn().execute(
            "SELECT DISTINCT target FROM sample WHERE net_id=? AND ts>=? LIMIT 20",
            (net["net_id"], cutoff))]
        return (f"No history for {target!r} on network {net['label']!r} in the last "
                f"{days:g} days. Known here: {', '.join(known) or '(none)'}")

    span_h = (rows[-1][0] - rows[0][0]) / 3600.0
    by_metric: dict[str, list[float]] = {}
    for _ts, m, v in rows:
        by_metric.setdefault(m, []).append(float(v))
    n_meas = len({r[0] for r in rows})

    head = (f"{target} on network {net['label']!r}, last {days:g} days: {n_meas} measurements "
            f"spanning {span_h:.1f} h")
    # Sample COUNT is not the binding constraint - time SPAN is. Fifty samples taken inside one
    # minute describe that minute, not a norm: no diurnal cycle, no peak-hour congestion, no
    # link flap. Warn on span regardless of how many samples there are.
    if n_meas < 5:
        head += ("\nWARNING: too few samples to describe a norm - treat these as raw readings, "
                 "not a baseline.")
    elif span_h < 2:
        head += (f"\nWARNING: every sample comes from a {span_h * 60:.0f}-minute window, so "
                 "this captures no daily variation. It is a snapshot of that moment, and a "
                 "value matching it is not thereby 'normal'.")
    elif span_h < 24:
        head += f"\nNote: history covers {span_h:.1f} h, so it spans no full day-night cycle."
    note = _horizon_note(days, for_floors=False)
    if note and rolled:
        head += "\n" + note
    body = "\n".join(f"  {k:18} {_describe(v)}" for k, v in sorted(by_metric.items()))
    return head + "\n" + body + (("\n" + rolled) if rolled else "")


def _null_deviations(values: list[float], k: int) -> tuple[list[float], float, bool]:
    """How much does a k-sample median move, when NOTHING has changed?

    This is the placebo idea: take windows from the history itself, where by construction no
    event occurred, and see how far their medians stray from the overall median. That spread
    is what noise alone produces, so any real shift has to beat it.

    Contiguous windows are used, because measurements next to each other in time are
    correlated - drawing random subsets would break that correlation and make the null look
    tighter than reality, understating how big a shift has to be. That is the same error a
    textbook standard error makes on autocorrelated network data, and it is worth several-fold
    on real paths.

    Returns (deviations, centre, relative); relative is False when the centre is zero (a loss
    percentage that is always 0), in which case deviations are absolute.
    """
    centre = statistics.median(values)
    relative = abs(centre) > 1e-9
    devs: list[float] = []
    for s in range(0, max(1, len(values) - k + 1)):
        w = values[s:s + k]
        if len(w) < k:
            continue
        m = statistics.median(w)
        devs.append((m - centre) / centre if relative else (m - centre))
    return devs, centre, relative


def assess(target: str, metric: str = "rtt_avg_ms", recent_hours: float = 2.0,
           baseline_days: float = 7.0, now: Optional[float] = None) -> dict:
    """The statistics behind detect_change, as numbers rather than prose.

    This exists so the agent's answer and the monitor's alert are computed ONCE. Two
    implementations of "has this changed" would eventually disagree, and then an alert would
    fire that the agent, asked about the same host a second later, would deny - which destroys
    trust in both faster than either being wrong on its own.

    Returns a dict that always carries `status`:
      "insufficient" - `reason` says what is missing; nothing else is meaningful
      "ok"           - `exceeds` is the verdict, with the evidence that produced it

    `now` is injectable so the behaviour can be tested against constructed history.
    """
    now = time.time() if now is None else now
    rows, net = _rows(target, baseline_days, metric)
    r = dict(target=target, metric=metric, net_id=net["net_id"], net_label=net["label"],
             status="insufficient", reason="",
             horizon=_horizon_note(baseline_days, for_floors=True))
    where = f"on network {net['label']!r}"

    if len(rows) < 8:
        r["reason"] = (f"{target}/{metric} {where}: only {len(rows)} measurements on record. "
                       f"Change detection needs a history to compare against - at least ~10, "
                       f"ideally spanning a day. Let the collector run, or take more "
                       f"measurements, before asking whether something changed.")
        # "No record" and "the raw samples expired" are different situations with different
        # remedies - waiting fixes the first and never fixes the second.
        if _hourly(target, baseline_days, metric):
            r["reason"] += (f" (This path DOES have history older than {RAW_DAYS:g} days, but "
                            f"only as hourly summaries; baseline can show it. It cannot be "
                            f"used to test for a change, so more raw samples are still what "
                            f"is needed.)")
        return r

    cutoff = now - recent_hours * 3600
    recent = [float(v) for ts, _m, v in rows if ts >= cutoff]
    base = [float(v) for ts, _m, v in rows if ts < cutoff]
    span_h = (rows[-1][0] - rows[0][0]) / 3600.0
    r.update(span_h=span_h, n_recent=len(recent), n_base=len(base))

    if not recent:
        r["reason"] = (f"{target}/{metric} {where}: no measurements in the last "
                       f"{recent_hours:g} h, so there is nothing recent to compare. Take a "
                       f"fresh measurement first.")
        return r
    if len(base) < 6:
        r["reason"] = (f"{target}/{metric} {where}: {len(recent)} recent samples but only "
                       f"{len(base)} older ones. Everything on record is inside the recent "
                       f"window, so there is no 'before' to compare against. History spans "
                       f"{span_h:.1f} h.")
        return r

    k = len(recent)
    devs, centre, relative = _null_deviations(base, k)
    if len(devs) < MIN_PLACEBO_WINDOWS:
        r["reason"] = (
            f"{target}/{metric} {where}: cannot build a noise floor. The recent window holds "
            f"{k} samples and the baseline only {len(base)}, which leaves {len(devs)} "
            f"placebo window(s) - and they overlap almost entirely, so their spread is near "
            f"zero and ANY shift would look significant. Needs at least "
            f"{MIN_PLACEBO_WINDOWS}, i.e. roughly {k + MIN_PLACEBO_WINDOWS} baseline samples "
            f"for a window this size. Collect more history, or compare a shorter recent "
            f"window.")
        return r

    rec_med = statistics.median(recent)
    observed = (rec_med - centre) / centre if relative else (rec_med - centre)
    absdevs = sorted(abs(d) for d in devs)
    p = sum(1 for d in absdevs if d >= abs(observed)) / len(absdevs)
    crit = absdevs[min(int(0.95 * len(absdevs)), len(absdevs) - 1)]

    # Smallest shift this history could resolve at ~80% power - the minimum detectable effect.
    mde = None
    for d in _MDE_GRID:
        step = d if relative else d * max(abs(centre), 1e-9)
        if sum(1 for x in devs if abs(x + step) > crit) / len(devs) >= 0.80:
            mde = d
            break

    r.update(status="ok", baseline_median=centre, recent_median=rec_med, shift=observed,
             relative=relative, noise_floor=crit, p=p, mde=mde, n_placebo=len(devs),
             exceeds=abs(observed) > crit)
    return r


def format_assessment(r: dict) -> str:
    """Render assess() for a reader. Both the agent and an alert use this, so the wording of a
    verdict cannot drift between them."""
    if r["status"] != "ok":
        return r["reason"]
    unit = "%" if r["relative"] else " (absolute)"
    scale = 100.0 if r["relative"] else 1.0
    out = [f"{r['target']}/{r['metric']} on network {r['net_label']!r}: recent "
           f"{r['n_recent']} samples vs {r['n_base']} earlier, history spans "
           f"{r['span_h']:.1f} h",
           f"  baseline median : {r['baseline_median']:.2f}",
           f"  recent median   : {r['recent_median']:.2f}",
           f"  shift           : {r['shift'] * scale:+.1f}{unit}",
           f"  noise floor     : windows of {r['n_recent']} in the quiet history move up to "
           f"{r['noise_floor'] * scale:.1f}{unit} (95th pct of {r['n_placebo']} placebo "
           f"windows)"]
    if r["exceeds"]:
        out.append(f"  VERDICT: the shift EXCEEDS what this path's own noise produces "
                   f"(p={r['p']:.3f}). Treat it as real.")
    else:
        out.append(f"  VERDICT: NOT distinguishable from noise (p={r['p']:.3f}). The "
                   f"measurement may well have moved, but this history cannot tell that from "
                   f"ordinary variation.")
    if r["mde"] is None:
        out.append(f"  Even a 200{unit} shift would not clear the noise floor with this much "
                   f"history. Collect more before trusting any change here.")
    else:
        out.append(f"  Smallest shift this history could resolve: about {r['mde'] * 100:.0f}% "
                   f"(at 80% power). Anything smaller is invisible until you have more "
                   f"samples, however real it is.")
    if r["span_h"] < 24:
        out.append(f"  CAVEAT: history spans {r['span_h']:.1f} h, covering no full day-night "
                   f"cycle, so a normal diurnal swing can masquerade as a change.")
    if r.get("horizon"):
        out.append(r["horizon"])
    return "\n".join(out)


def detect_change(target: str, metric: str = "rtt_avg_ms", recent_hours: float = 2.0,
                  baseline_days: float = 7.0) -> str:
    """Compare recent measurements of a host against its longer history, and say whether any
    shift is real or just noise.

    This answers the question baseline cannot: not "what is normal" but "has something
    CHANGED". Crucially it reports both halves - the size of the shift AND whether the history
    can actually distinguish a shift that size from ordinary variation. "Latency is up 12%" is
    meaningless alone: on a path that swings 20% hour to hour it is nothing, on one stable to
    2% it is an incident.

    When a shift cannot be called either way, this says so and reports the smallest shift the
    current history COULD resolve. That is the honest answer, and far more useful than a
    confident verdict the data does not support.

    Only history from the network this machine is on now is used.

    Args:
        target: Host, IP or URL, e.g. "1.1.1.1".
        metric: Which metric to test, e.g. "rtt_avg_ms", "query_ms", "handshake_avg_ms".
        recent_hours: How much of the tail counts as "recent".
        baseline_days: How far back the comparison history reaches.
    """
    return format_assessment(assess(target, metric, recent_hours, baseline_days))


def _quantum(values: list[float]) -> float:
    """The smallest step this instrument actually reports, read off the data itself.

    Not configured, because a configured number would be a claim about the tool rather than an
    observation of it. If the values sit on a lattice - as `ping` output does, because Windows
    reports whole milliseconds and this tool averages `count` of them - the smallest gap
    between distinct observed values IS the lattice spacing. Genuinely continuous measurements
    produce a near-zero gap, which is the correct answer for them.
    """
    u = sorted({round(float(v), 9) for v in values})
    if len(u) < 3:
        return 0.0
    return min(b - a for a, b in zip(u, u[1:]))


def _mde_for_window(values: list[float], k: int) -> tuple[Optional[float], float, int, bool]:
    """Smallest relative shift a k-sample window could resolve at 80% power.

    Same placebo calibration detect_change uses, exposed on its own so the question "could I
    see a change of this size?" can be answered WITHOUT waiting for the change to happen.
    """
    devs, centre, relative = _null_deviations(values, k)
    if len(devs) < MIN_PLACEBO_WINDOWS:
        return None, 0.0, len(devs), relative
    absdevs = sorted(abs(d) for d in devs)
    crit = absdevs[min(int(0.95 * len(absdevs)), len(absdevs) - 1)]
    for d in _MDE_GRID:
        step = d if relative else d * max(abs(centre), 1e-9)
        if sum(1 for x in devs if abs(x + step) > crit) / len(devs) >= 0.80:
            return d, crit, len(devs), relative
    return None, crit, len(devs), relative


def can_detect(target: str, metric: str = "rtt_avg_ms", shift_pct: float = 10.0,
               recent_hours: float = 2.0, window: int = 0,
               baseline_days: float = 7.0) -> str:
    """Ask whether a change of a given size could be seen here AT ALL, before trusting any
    verdict about whether it happened.

    This is the tool for "I measured it, but is my measurement precise enough to answer the
    question?" - which is a different question from "did it change", and one that has to be
    settled first. A negative result from detect_change means one of two very different things:
    nothing happened, or something happened that this setup could never have seen. Reporting
    the first when the truth is the second is the worst error this agent can make, because it
    sounds like an all-clear.

    Three separate limits are checked, and only one of them is usually binding. Each has a
    different remedy, so naming the right one is the whole point:

      INSTRUMENT  - the measurement cannot even express a change that small. `ping` reports
                    whole milliseconds, so averaging 5 of them gives 0.2 ms steps; on a 2.4 ms
                    gateway that is an 8% floor no amount of extra sampling will lower.
                    Remedy: a finer instrument, or more packets per measurement.
      STATISTICS  - the path's own variability swamps a change that small at the current number
                    of samples. Remedy: more samples.
      COVERAGE    - the history spans no full day, so normal daily variation is not yet part of
                    the noise model. Remedy: wait.

    Args:
        target: Host, IP or URL, e.g. "1.1.1.1".
        metric: Which metric, e.g. "rtt_avg_ms", "query_ms", "loss_pct".
        shift_pct: The size of change you care about, in percent, e.g. 10 for a 10% change.
        recent_hours: The comparison window, matching detect_change's argument of the same
            name. Leave at the default so the two tools describe the same comparison.
        window: Override the window as a raw sample count. Normally leave at 0.
        baseline_days: How far back the history reaches.
    """
    rows, net = _rows(target, baseline_days, metric)
    where = f"on network {net['label']!r}"
    if len(rows) < 10:
        return (f"{target}/{metric} {where}: only {len(rows)} samples on record, which is not "
                f"enough to say what this setup can resolve. Measure more, or let the "
                f"collector run.")

    values = [float(v) for _ts, _m, v in rows]
    span_h = (rows[-1][0] - rows[0][0]) / 3600.0
    centre = statistics.median(values)
    want = abs(shift_pct) / 100.0

    # The minimum detectable shift depends on how many samples the comparison uses, so this
    # MUST use the same window detect_change would. An earlier version picked its own, and the
    # two tools then quoted different resolutions for the same signal (35% vs 75%) - which
    # reads as one of them being wrong rather than as a window-size effect.
    if window > 0:
        k = window
    else:
        cutoff = time.time() - recent_hours * 3600
        k = sum(1 for ts, _m, _v in rows if ts >= cutoff)
        if k < 5:
            k = max(5, min(60, len(values) // 4))      # too little recent data; fall back

    q = _quantum(values)
    inst_floor = (q / abs(centre)) if abs(centre) > 1e-9 else 0.0
    mde, crit, n_placebo, relative = _mde_for_window(values, k)

    out = [f"{target}/{metric} {where}: could I detect a {shift_pct:g}% change?",
           f"  history         : {len(values)} samples over {span_h:.1f} h, median "
           f"{centre:.3g}",
           f"  window compared : {k} samples (the last {recent_hours:g} h, which is what "
           f"detect_change compares)"]
    horizon = _horizon_note(baseline_days, for_floors=True)
    if horizon:
        out.append(horizon)

    limits = []
    if inst_floor > 0:
        out.append(f"  instrument floor: values arrive in steps of {q:.3g} on a median of "
                   f"{centre:.3g} -> nothing below {inst_floor * 100:.1f}% is expressible")
        limits.append(("INSTRUMENT", inst_floor))
    else:
        out.append("  instrument floor: none measurable - values are effectively continuous")

    if mde is None:
        out.append(f"  statistical floor: cannot be established ({n_placebo} placebo windows, "
                   f"need {MIN_PLACEBO_WINDOWS})")
        return "\n".join(out + [
            "  VERDICT: UNKNOWN. There is not enough history to calibrate this path's noise, "
            "so I cannot say what I could or could not detect here. Collect more before "
            "trusting any verdict about change on this signal."])
    out.append(f"  statistical floor: {mde * 100:.0f}% at 80% power "
               f"({n_placebo} placebo windows of {k}, noise floor {crit * 100:.1f}%)")
    limits.append(("STATISTICS", mde))

    name, binding = max(limits, key=lambda t: t[1])
    out.append(f"  BINDING LIMIT   : {name}, at {binding * 100:.1f}%")

    if want >= binding:
        out.append(f"  VERDICT: YES. A {shift_pct:g}% change is above every limit here, so a "
                   f"'no change' result from detect_change is real evidence of no change.")
    else:
        out.append(f"  VERDICT: NO. I can measure this, but not finely enough to see a "
                   f"{shift_pct:g}% change. A 'no change' result here would mean 'invisible', "
                   f"NOT 'nothing happened' - do not report it as an all-clear.")
        if name == "INSTRUMENT":
            # ping averages `count` whole-millisecond replies, so the step is 1/count ms and
            # the count is recoverable from the step. Worth stating: it makes the remedy exact
            # rather than a vague "measure more".
            hint = ""
            if metric.startswith("rtt_") and q > 0:
                cnt = int(round(1.0 / q)) if q <= 1.0 else 1
                if cnt >= 1:
                    need = want * abs(centre)
                    hint = (f" ping averages whole-millisecond replies, so the step is "
                            f"1/count ms and this looks like count={cnt}. To express "
                            f"{shift_pct:g}% you need steps of {need:.3g} ms, i.e. "
                            f"count>={max(1, int(round(1.0 / max(need, 1e-9))))}, or use "
                            f"tcp_latency which measures in fractional milliseconds.")
            out.append("  REMEDY: a finer instrument - more samples will not help." + hint)
        else:
            # "More samples" is not actionable on its own. The floor depends on the size of
            # the compared window, so search for the window that would actually reach the
            # requested resolution and say whether the history can supply it. That turns
            # "collect more" into a number, and into an honest "not with this much history".
            need_k, need_mde = None, None
            for cand in (k * 2, k * 4, k * 8):
                if cand > len(values) // 2:
                    break
                m2, _c2, n2, _r2 = _mde_for_window(values, cand)
                if m2 is not None and m2 <= want:
                    need_k, need_mde = cand, m2
                    break
            if need_k:
                out.append(f"  REMEDY: widen the comparison window. {need_k} samples instead "
                           f"of {k} would resolve {need_mde * 100:.0f}%, which covers the "
                           f"{shift_pct:g}% you asked about - at the cost of reacting more "
                           f"slowly, since the window has to fill before a change shows.")
            else:
                out.append(f"  REMEDY: more history. Even widening the window as far as this "
                           f"record allows ({len(values)} samples over {span_h:.1f} h) does "
                           f"not reach {shift_pct:g}% on this path - its own variability is "
                           f"simply too large at this much data. The instrument is not the "
                           f"limit; the path is.")

    if span_h < 24:
        out.append(f"  COVERAGE: history spans {span_h:.1f} h and so contains no full "
                   f"day-night cycle. Normal daily variation is not yet in the noise model, "
                   f"so both floors above may be optimistic.")
    return "\n".join(out)


def coverage(hours: float = 24.0, target: str = "") -> str:
    """Check whether measurement was actually running over a period, BEFORE answering any
    question about the past.

    An absence of data is not an absence of problems. This machine sleeps, moves networks and
    gets shut down, and the record has holes wherever that happened. Reasoning across a hole -
    "nothing looks wrong last night" - answers from the data on either side of a period nobody
    observed, and states it with the same confidence as a period that was fully covered. That
    is the single easiest way for this agent to be confidently wrong.

    The collector writes a heartbeat every cycle whether or not any probe succeeded, so a gap
    in heartbeats means "we were not measuring", which is completely different from "we
    measured and nothing answered". This reports the first.

    Call this whenever a question refers to a past time - "was there a problem last night",
    "has it been slow this week" - and say plainly if the period was not observed.

    Args:
        hours: How far back to examine.
        target: Optionally also report how many samples exist for this host in the period.
    """
    net = net_store.network_identity()
    now = time.time()
    since = int(now - hours * 3600)
    beats = [r[0] for r in conn().execute(
        "SELECT ts FROM heartbeat WHERE net_id=? AND ts>=? ORDER BY ts",
        (net["net_id"], since))]

    head = f"measurement coverage on network {net['label']!r}, last {hours:g} h"
    if not beats:
        return (f"{head}\n  NOTHING was measured in this period on this network. Any question "
                f"about it cannot be answered from data - there is none. (The collector may "
                f"have been stopped, the machine asleep, or this may be a network it has not "
                f"run on before.)")

    # The expected cadence is read from the data rather than assumed, because the collector's
    # interval is configurable and has changed during this project.
    diffs = sorted(b - a for a, b in zip(beats, beats[1:])) or [0]
    cadence = statistics.median(diffs) if diffs else 0
    gap_threshold = max(4 * cadence, 300)

    gaps = [(a, b) for a, b in zip(beats, beats[1:]) if (b - a) > gap_threshold]
    if beats[0] - since > gap_threshold:
        gaps.insert(0, (since, beats[0]))
    if now - beats[-1] > gap_threshold:
        gaps.append((beats[-1], int(now)))

    missing = sum(b - a for a, b in gaps)
    covered = max(0.0, 1.0 - missing / (hours * 3600))
    out = [head,
           f"  {len(beats)} cycles, roughly every {cadence / 60:.1f} min",
           f"  covered {covered * 100:.0f}% of the period"]
    if gaps:
        out.append(f"  {len(gaps)} gap(s) where NOTHING was measured:")
        for a, b in gaps[:8]:
            out.append(f"    {time.strftime('%d %b %H:%M', time.localtime(a))} -> "
                       f"{time.strftime('%d %b %H:%M', time.localtime(b))}  "
                       f"({(b - a) / 3600:.1f} h)")
        if len(gaps) > 8:
            out.append(f"    ... and {len(gaps) - 8} more")
        out.append("  Do not describe these periods as quiet or healthy. They were not "
                   "observed, and that is a different statement.")
    else:
        out.append("  no gaps - the period was observed continuously.")

    if target:
        rows = list(conn().execute(
            "SELECT metric, COUNT(*), MIN(ts), MAX(ts) FROM sample "
            "WHERE target=? AND net_id=? AND ts>=? GROUP BY metric ORDER BY metric",
            (target, net["net_id"], since)))
        if not rows:
            out.append(f"  {target}: no samples at all in this period.")
        else:
            out.append(f"  {target}:")
            for m, n, lo, hi in rows:
                out.append(f"    {m:<18} {n:>5} samples, "
                           f"{time.strftime('%d %b %H:%M', time.localtime(lo))} -> "
                           f"{time.strftime('%d %b %H:%M', time.localtime(hi))}")
    return "\n".join(out)


# --------------------------------------------------------------------------- migration

def import_jsonl(path: str, assume_current_network: bool = False) -> str:
    """Import the old net_history.jsonl into the database.

    Legacy rows carry no network identity, so they cannot be assigned to one after the fact.
    Importing them under the CURRENT network is only sound if the machine did not move while
    they were collected - which is why it must be requested explicitly rather than happening
    quietly. Getting this wrong silently merges two networks' baselines, which is the exact
    failure net_id exists to prevent.
    """
    import json
    if not os.path.exists(path):
        return f"nothing to import: {path} does not exist"
    net = net_store.network_identity()
    rows, lo, hi = [], None, None
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = int(r.get("ts", 0))
            lo, hi = (ts if lo is None else min(lo, ts)), (ts if hi is None else max(hi, ts))
            for k, v in (r.get("metrics") or {}).items():
                rows.append((ts, r.get("target", ""), k, float(v), net["net_id"]))
    span_h = ((hi - lo) / 3600.0) if (lo and hi) else 0.0
    if not assume_current_network:
        return (f"{len(rows)} legacy rows spanning {span_h:.1f} h found in {path}.\n"
                f"They carry no network identity. Importing them would file them under "
                f"{net['label']!r}, which is correct ONLY if this machine stayed on that "
                f"network throughout.\nRe-run with assume_current_network=True to import.")
    c = conn()
    c.executemany("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                  "VALUES (?,?,?,?,?)", rows)
    c.commit()
    return f"imported {len(rows)} rows spanning {span_h:.1f} h as network {net['label']!r}"


if __name__ == "__main__":
    import sys
    a = sys.argv[1:]
    if a and a[0] == "change":
        print(detect_change(*a[1:]))
    elif a and a[0] == "import":
        print(import_jsonl(a[1] if len(a) > 1 else "net_history.jsonl",
                           assume_current_network="--yes" in a))
    else:
        print(baseline(*a))
