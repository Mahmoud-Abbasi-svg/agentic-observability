"""The evaluator and alert state machine - the part that makes this a monitor.

    python net_alert.py --once        # evaluate every mature signal once, print the table
    python net_alert.py               # evaluate on a schedule until stopped
    python net_alert.py --status      # current state per signal, no evaluation
    python net_alert.py --log         # alerts fired and cleared, most recent first

It reads the store the collector fills, asks net_memory.assess whether each signal has moved
beyond its OWN noise, and decides whether that is worth telling anyone about.

Four rules do the work, and each exists because of a specific way monitors fail:

1. NOTHING IMMATURE EVER ALERTS. A signal needs ~30 samples spanning >= 6 h on this network
   before it can be judged at all; below that its state is UNKNOWN. A monitor that starts
   shouting an hour after installation is a monitor people turn off, and "I am still learning
   this path" is a true and useful thing to say.

2. THE THRESHOLD IS THE PATH'S OWN NOISE, not a number a human typed. This is the whole claim.
   A 12% latency rise is nothing on a path that swings 20% between hours and an incident on one
   stable to 2%, and no fixed threshold can be right for both.

3. HYSTERESIS, k = 3. Three consecutive confirming evaluations before firing and three before
   clearing. Without it a signal sitting on the boundary flaps, and a flapping alert teaches
   people to ignore alerts faster than a false one does.

4. GAPS ARE NOT OUTAGES. If the collector was not running for most of the recent window - a
   closed lid, a stopped process - the signal is not evaluated at all. Otherwise every night's
   sleep produces an incident at breakfast.

5. STATISTICALLY REAL IS NOT THE SAME AS WORTH WAKING SOMEONE FOR. A shift must also be in the
   direction that is bad, large enough in the metric's own units, and large enough relative to
   the baseline. Each of those three was added after a case got past the ones before it - see
   worth_alerting. A shift that is real and deliberately not paged is shown with the reason,
   because unexplained silence is indistinguishable from a monitor that missed something.

There is no model call anywhere in this file. Detection must be a pure function of the data:
an alert that fires or not depending on sampling temperature is not an alert. The agent's job
starts after this one ends, explaining an alert this code decided to fire.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import time
from typing import Optional

import net_memory
import net_store

# Metrics worth alerting on. Deliberately not every stored metric: rtt_min_ms and rtt_max_ms
# move with rtt_avg_ms, and three alerts about one event is three times the fatigue for the
# same information.
ALERT_METRICS = ("rtt_avg_ms", "loss_pct", "reachable", "handshake_avg_ms", "query_ms",
                 "resolve_ms", "response_ms", "connect_ms", "success_rate", "ok_2xx")

MIN_SAMPLES, MIN_SPAN_H = 30, 6.0      # maturity gate (rule 1)
CONFIRMATIONS = 3                       # k, both directions (rule 3)
RECENT_HOURS, BASELINE_DAYS = 1.0, 7.0
MIN_HEARTBEATS_IN_WINDOW = 3            # rule 4

# The smallest shift anyone wants to hear about. NOT a detection threshold - detection is rule
# 2, the path's own noise - but a RELEVANCE one, and the two are different questions.
#
# A very stable path makes a 0.9% shift statistically undeniable, and waking someone for it is
# how a noise-aware monitor reinvents alert fatigue from the other end. This is the one number
# a human is supposed to choose, because only a human knows what matters to them.
#
# Its real value is the comparison it enables: this is the shift you asked to be told about,
# and `mde` is the smallest shift the path can actually resolve. When mde > this, the monitor
# is under-instrumented for its own stated goal and says so, instead of quietly missing things.
MIN_PRACTICAL_SHIFT = 0.10

# A percentage alone is not enough, because a percentage of a small number is a small number.
#
# Found on live data: the gateway alerted at -25%, which was 2.4 ms -> 1.8 ms. Every recorded
# value on that path is a multiple of 0.2 ms, because `ping` reports whole milliseconds and the
# tool averages five of them - so ONE QUANTISATION STEP IS ~20% at this baseline, and the 20.8%
# "noise floor" was measuring the clock rather than the network. Relative thresholds break down
# whenever the baseline approaches the instrument's resolution, and on a LAN they always do.
#
# So a shift must also be big enough in the metric's own units. In ms for latencies, percentage
# points for loss, and a fraction of 1 for the rate metrics.
MIN_ABSOLUTE_SHIFT = {
    "rtt_avg_ms": 1.0, "handshake_avg_ms": 1.0, "connect_ms": 1.0,
    "query_ms": 2.0, "resolve_ms": 2.0, "response_ms": 20.0,
    "loss_pct": 1.0,
    "reachable": 0.05, "success_rate": 0.05, "ok_2xx": 0.05,
}

# Which way is bad. The detector is deliberately direction-blind - a path that halved its
# latency HAS changed, and a diagnostic tool should say so - but a pager is a different thing.
# Nobody should be woken because the network got faster.
LOWER_IS_WORSE = {"reachable", "success_rate", "ok_2xx"}

def log_path() -> str:
    """The alert log lives beside the database it describes, resolved at call time.

    It was a constant frozen at import to this directory, and that put FIXTURE alerts in the
    live operational log: test_net_alert.py points NET_MONITOR_DB at a temp file, but the log
    path did not follow, so the record an operator reads carried repeated alerts about
    'quiet-big' - a target that does not exist - timestamped minutes before a real outage that
    produced no alert at all. Tying the log to the database makes that impossible rather than
    merely discouraged, and is the same fix as net_store's frozen DB_PATH once needed.
    """
    db = os.environ.get("NET_MONITOR_DB") or net_store.DB_PATH
    return os.path.join(os.path.dirname(os.path.abspath(db)), "net_alerts.log")
CONFIG_PATH = os.environ.get(
    "NET_MONITOR_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.json"))


# --------------------------------------------------------------------------- state

def get_state(conn: sqlite3.Connection, target: str, metric: str, net_id: str) -> dict:
    row = conn.execute("SELECT state, since, streak, last_shift FROM alert_state "
                       "WHERE target=? AND metric=? AND net_id=?",
                       (target, metric, net_id)).fetchone()
    if not row:
        return dict(state="UNKNOWN", since=int(time.time()), streak=0, last_shift=None)
    return dict(state=row[0], since=row[1], streak=row[2], last_shift=row[3])


def put_state(conn: sqlite3.Connection, target: str, metric: str, net_id: str,
              st: dict, now: int) -> None:
    conn.execute(
        "INSERT INTO alert_state (target,metric,net_id,state,since,streak,last_shift,updated) "
        "VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT(target,metric,net_id) DO UPDATE SET state=excluded.state, "
        "since=excluded.since, streak=excluded.streak, last_shift=excluded.last_shift, "
        "updated=excluded.updated",
        (target, metric, net_id, st["state"], st["since"], st["streak"],
         st.get("last_shift"), now))


# --------------------------------------------------------------------------- notification

def render_alert(kind: str, r: dict, since: int, now: int) -> str:
    """What an alert says.

    "Latency high" is a static-threshold alert wearing better clothes. This one carries the
    evidence that justified it, including the LAST line - the smallest shift this history could
    have resolved. That line lets a reader tell a decisive result from a marginal one without
    having to trust the tool, which is the difference between a monitor and an oracle.
    """
    scale = 100.0 if r["relative"] else 1.0
    unit = "%" if r["relative"] else ""
    # Measured from when the confirmation run STARTED, not from the transition that just
    # happened - otherwise every alert claims it was confirmed over zero minutes.
    held_min = (now - since) / 60.0
    head = (f"{'ALERT' if kind == 'FIRED' else 'CLEAR'}  {r['target']} / {r['metric']}   "
            f"on net {r['net_label']!r}")
    body = [
        f"  baseline median : {r['baseline_median']:.2f}   "
        f"({BASELINE_DAYS:g} d, {r['n_base']} samples)",
        f"  now             : {r['recent_median']:.2f}   "
        f"(last {RECENT_HOURS:g} h, {r['n_recent']} samples)",
        # Both forms, always. A percentage hides how small a small number's percentage is, and
        # an absolute figure hides how large a large number's absolute change isn't.
        f"  shift           : {r['shift'] * scale:+.1f}{unit}   "
        f"({r['recent_median'] - r['baseline_median']:+.2g}{unit_of(r['metric'])})",
        f"  noise floor     : {r['noise_floor'] * scale:.1f}{unit}   "
        f"(95th pct of {r['n_placebo']} placebo windows)",
        f"  confirmed       : {CONFIRMATIONS} consecutive evaluations over {held_min:.0f} min",
    ]
    body.append("  smallest shift this history could resolve: "
                + ("none - even 200% would not clear the noise floor"
                   if r["mde"] is None else f"{r['mde'] * 100:.0f}%")
                + f"   (you asked about {MIN_PRACTICAL_SHIFT * 100:.0f}%)")
    if r["mde"] is not None and r["mde"] > MIN_PRACTICAL_SHIFT:
        body.append("  NOTE: this path cannot resolve the shift size you asked about, so "
                    "smaller real changes here are being missed, not ruled out.")
    if r["span_h"] < 24:
        body.append(f"  CAVEAT: history spans {r['span_h']:.1f} h, no full day-night cycle")
    return head + "\n" + "\n".join(body)


def notify(conn: sqlite3.Connection, kind: str, r: dict, text: str, now: int,
           webhook: str = "") -> None:
    print("\n" + text + "\n", flush=True)
    try:
        with open(log_path(), "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}] {text}\n\n")
    except OSError:
        pass
    conn.execute("INSERT INTO alert_log (ts,target,metric,net_id,kind,shift,detail) "
                 "VALUES (?,?,?,?,?,?,?)",
                 (now, r["target"], r["metric"], r["net_id"], kind, r["shift"], text))
    if webhook:
        # Best effort. A notifier that can crash the monitor is worse than no notifier: the
        # alert has already been printed and logged by the time we get here.
        try:
            import urllib.request
            payload = json.dumps({"kind": kind, "target": r["target"], "metric": r["metric"],
                                  "net": r["net_label"], "shift": r["shift"],
                                  "text": text}).encode()
            req = urllib.request.Request(webhook, data=payload,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).read()
        except Exception as e:
            print(f"  (webhook failed: {type(e).__name__})", flush=True)


# --------------------------------------------------------------------------- evaluation

def unit_of(metric: str) -> str:
    return "ms" if metric.endswith("_ms") else ("pp" if metric.endswith("_pct") else "")


def worth_alerting(r: dict) -> tuple[bool, str]:
    """Is this shift worth waking someone for? Returns (yes, why_not).

    Four tests, and a shift must survive all of them. The first is statistics; the rest are
    judgement, and each exists because of a case that got through the one before it:

      1. beyond the path's own noise floor          - the detection rule
      2. in the direction that is actually bad      - or the network improving pages someone
      3. big enough in the metric's own units       - or quantisation noise on a LAN does
      4. big enough as a fraction of the baseline   - or a rock-steady path pages on 0.9%

    A metric whose baseline sits at zero (loss_pct on a clean link) has no percentage to take,
    so test 4 is skipped for it - going from zero loss to some loss IS the event.
    """
    if not r["exceeds"]:
        return False, ""
    delta = r["recent_median"] - r["baseline_median"]
    worse = delta < 0 if r["metric"] in LOWER_IS_WORSE else delta > 0
    if not worse:
        return False, f"improved {r['shift'] * 100:+.0f}%, not paged"

    floor = MIN_ABSOLUTE_SHIFT.get(r["metric"], 0.0)
    if abs(delta) < floor:
        u = unit_of(r["metric"])
        return False, (f"real but only {abs(delta):.2g}{u} - under the {floor:g}{u} floor")

    if r["relative"] and abs(r["shift"]) < MIN_PRACTICAL_SHIFT:
        return False, f"real but under {MIN_PRACTICAL_SHIFT * 100:.0f}%"
    return True, ""


def signals(conn: sqlite3.Connection, net_id: str) -> list[tuple[str, str, int, float]]:
    """Every (target, metric) with any history on this network, with its maturity numbers."""
    cutoff = int(time.time() - BASELINE_DAYS * 86400)
    rows = conn.execute(
        "SELECT target, metric, COUNT(*), MIN(ts), MAX(ts) FROM sample "
        "WHERE net_id=? AND ts>=? GROUP BY target, metric ORDER BY target, metric",
        (net_id, cutoff)).fetchall()
    return [(t, m, n, (hi - lo) / 3600.0) for t, m, n, lo, hi in rows if m in ALERT_METRICS]


def measured_recently(conn: sqlite3.Connection, net_id: str, now: float) -> bool:
    """Did the collector actually run over the recent window? (rule 4)

    Distinguishes "we did not measure" from "we measured and nothing answered". Without this a
    laptop that slept through the recent window wakes to an incident on every signal at once,
    which is the single most common way this kind of monitor loses its audience.
    """
    n = conn.execute("SELECT COUNT(*) FROM heartbeat WHERE net_id=? AND ts>=?",
                     (net_id, int(now - RECENT_HOURS * 3600))).fetchone()[0]
    return n >= MIN_HEARTBEATS_IN_WINDOW


def step(state: str, streak: int, exceeds: bool) -> tuple[str, int, Optional[str]]:
    """One transition of the state machine. Pure, so it can be tested without a database.

        OK --exceeds--> SUSPECT --(k confirmations)--> ALERTING
                                                          |
        OK <--(k confirmations)-- RECOVERING <--within floor--

    Returns (new_state, new_streak, event) where event is "FIRED", "CLEARED" or None.
    """
    if state in ("UNKNOWN", "OK"):
        return ("SUSPECT", 1, None) if exceeds else ("OK", 0, None)
    if state == "SUSPECT":
        if not exceeds:
            return "OK", 0, None
        streak += 1
        return ("ALERTING", streak, "FIRED") if streak >= CONFIRMATIONS \
            else ("SUSPECT", streak, None)
    if state == "ALERTING":
        return ("ALERTING", CONFIRMATIONS, None) if exceeds else ("RECOVERING", 1, None)
    if state == "RECOVERING":
        if exceeds:
            return "ALERTING", CONFIRMATIONS, None
        streak += 1
        return ("OK", 0, "CLEARED") if streak >= CONFIRMATIONS \
            else ("RECOVERING", streak, None)
    return "UNKNOWN", 0, None


def evaluate(conn: sqlite3.Connection, webhook: str = "", now: Optional[float] = None,
             verbose: bool = True) -> list[dict]:
    """One evaluation pass over every signal. Returns a row per signal for display."""
    now = time.time() if now is None else now
    inow = int(now)
    net = net_store.network_identity()
    net_store.remember_net(conn, net)

    if not measured_recently(conn, net["net_id"], now):
        if verbose:
            print(f"  no collector heartbeats in the last {RECENT_HOURS:g} h - not evaluating. "
                  f"A gap in measurement is not an outage.")
        conn.commit()
        return []

    out = []
    for target, metric, n, span_h in signals(conn, net["net_id"]):
        st = get_state(conn, target, metric, net["net_id"])
        row = dict(target=target, metric=metric, n=n, span_h=span_h,
                   state=st["state"], streak=st["streak"], note="", shift=None)

        if n < MIN_SAMPLES or span_h < MIN_SPAN_H:
            # Immature: record that we know nothing, and make sure it cannot alert.
            row["state"], row["note"] = "UNKNOWN", (
                f"needs {MIN_SAMPLES} samples over {MIN_SPAN_H:g} h; has {n} over {span_h:.1f} h")
            put_state(conn, target, metric, net["net_id"],
                      dict(state="UNKNOWN", since=st["since"] if st["state"] == "UNKNOWN"
                           else inow, streak=0, last_shift=None), inow)
            out.append(row)
            continue

        r = net_memory.assess(target, metric, RECENT_HOURS, BASELINE_DAYS, now=now)
        if r["status"] != "ok":
            # No evidence this round. The state is held, but the confirmation chain is broken -
            # three confirmations must be three in a row, not three whenever they happen.
            # Carry the reason through, trimmed of the "target/metric on network 'x':" prefix.
            # "cannot evaluate" on its own tells an operator nothing they can act on.
            why = r["reason"].split(": ", 1)[-1].replace("\n", " ")
            row["note"] = why[:60] + ("..." if len(why) > 60 else "")
            st["streak"] = 0
            put_state(conn, target, metric, net["net_id"], st, inow)
            out.append(row)
            continue

        pages, why_not = worth_alerting(r)
        new_state, new_streak, event = step(st["state"], st["streak"], pages)
        since = inow if new_state != st["state"] else st["since"]
        new = dict(state=new_state, since=since, streak=new_streak, last_shift=r["shift"])
        put_state(conn, target, metric, net["net_id"], new, inow)

        row.update(state=new_state, streak=new_streak, shift=r["shift"],
                   relative=r["relative"], floor=r["noise_floor"], mde=r["mde"])
        # A real shift that is deliberately not paged says WHY. Otherwise the monitor looks
        # like it missed something, and an operator who thinks that stops trusting the silence.
        if why_not:
            row["note"] = why_not
        elif r["mde"] is not None and r["mde"] > MIN_PRACTICAL_SHIFT:
            # Under-instrumented: the goal asks for a resolution this history cannot deliver.
            # Worth surfacing every pass - it is a silent miss, not a visible failure.
            row["note"] = (f"can only resolve {r['mde'] * 100:.0f}%, "
                           f"goal is {MIN_PRACTICAL_SHIFT * 100:.0f}%")
        if event:
            notify(conn, event, r, render_alert(event, r, st["since"], inow), inow, webhook)
            row["note"] = event
        out.append(row)

    conn.commit()
    return out


# --------------------------------------------------------------------------- display

def print_pass(rows: list[dict]) -> None:
    if not rows:
        return
    print(f"{'target':<22}{'metric':<18}{'state':<12}{'shift':>9}{'floor':>9}  note")
    for r in sorted(rows, key=lambda x: (x["state"] != "ALERTING", x["target"])):
        sc = 100.0 if r.get("relative", True) else 1.0
        shift = f"{r['shift'] * sc:+.1f}%" if r.get("shift") is not None else "-"
        floor = f"{r['floor'] * sc:.1f}%" if r.get("floor") is not None else "-"
        streak = f" ({r['streak']}/{CONFIRMATIONS})" if r["state"] in (
            "SUSPECT", "RECOVERING") else ""
        print(f"{r['target'][:21]:<22}{r['metric'][:17]:<18}"
              f"{r['state'] + streak:<12}{shift:>9}{floor:>9}  {r['note']}")


def show_status(conn: sqlite3.Connection) -> None:
    net = net_store.network_identity()
    print(f"network: {net['label']}  ({net['net_id']})")
    rows = list(conn.execute(
        "SELECT target, metric, state, since, streak, last_shift FROM alert_state "
        "WHERE net_id=? ORDER BY state, target", (net["net_id"],)))
    if not rows:
        print("no signals evaluated yet - run: python net_alert.py --once")
        return
    now = time.time()
    print(f"\n{'target':<22}{'metric':<18}{'state':<12}{'for':>9}{'shift':>9}")
    for t, m, s, since, streak, shift in rows:
        held = (now - since) / 3600.0
        sv = f"{shift * 100:+.1f}%" if shift is not None else "-"
        st = s + (f" ({streak}/{CONFIRMATIONS})" if s in ("SUSPECT", "RECOVERING") else "")
        print(f"{t[:21]:<22}{m[:17]:<18}{st:<12}{held:>8.1f}h{sv:>9}")
    counts: dict[str, int] = {}
    for _t, _m, s, *_ in rows:
        counts[s] = counts.get(s, 0) + 1
    print("\n" + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))


def show_log(conn: sqlite3.Connection, limit: int = 20) -> None:
    rows = list(conn.execute("SELECT ts, kind, detail FROM alert_log "
                             "ORDER BY ts DESC LIMIT ?", (limit,)))
    if not rows:
        print("no alerts have fired or cleared.")
        return
    for ts, _kind, detail in rows:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}]\n{detail}\n")


# --------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate collected history and alert on real "
                                             "changes.")
    ap.add_argument("--once", action="store_true", help="one evaluation pass then exit")
    ap.add_argument("--status", action="store_true", help="current state per signal")
    ap.add_argument("--log", action="store_true", help="alerts fired and cleared")
    ap.add_argument("--interval", type=float, default=300.0, help="seconds between passes")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print alerts")
    args = ap.parse_args()

    conn = net_store.connect()
    if args.status:
        show_status(conn)
        return 0
    if args.log:
        show_log(conn)
        return 0

    webhook = ""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, encoding="utf-8") as f:
            webhook = (json.load(f).get("notify") or {}).get("webhook", "")

    if args.once:
        print_pass(evaluate(conn, webhook, verbose=not args.quiet))
        conn.close()
        return 0

    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    print(f"evaluator: every {args.interval:g}s, k={CONFIRMATIONS} confirmations, "
          f"recent={RECENT_HOURS:g}h vs baseline={BASELINE_DAYS:g}d")
    while not stop["flag"]:
        if not args.quiet:
            print(f"\n[{time.strftime('%H:%M:%S')}]")
        rows = evaluate(conn, webhook, verbose=not args.quiet)
        if not args.quiet:
            print_pass(rows)
        for _ in range(int(args.interval)):
            if stop["flag"]:
                break
            time.sleep(1)
    conn.close()
    print("\nstopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
