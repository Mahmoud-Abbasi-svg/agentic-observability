"""Does a binary signal alert on a real outage, and only on a real outage?

    python test_net_downrun.py

`reachable` is 0 or 1 per probe. It has no shift size, so the placebo floor that judges every
other signal cannot judge it: with earlier outages in the history the floor grows until 100%
down is "within noise", and on 2026-09-08 every host was down for 96 consecutive probes and
reachable alerted on none of them. Rule 6 in net_alert judges it by run length instead.

Pre-registered before the code was run, with the thresholds fixed from the live store's own
outages (flaps: 1-3 probes, under a minute; outages: 15+ probes, 17+ minutes; nothing between):

  R1   twenty single dropped probes over nine hours never leave OK
  R2   a three-probe, two-minute flap never leaves OK  (probes pass, minutes fail)
  R3   three probes on a five-minute cadence DO exceed  (both conditions met)
  R4   an ongoing outage fires on the third consecutive evaluation, not before
  R5   the same outage with two earlier outages in its history STILL fires, while the
       placebo path on that history does not - the live failure, reproduced and fixed
  R6   a down run followed by a measurement gap does NOT fire: open-ended is not ongoing
  R7   one up probe inside an outage never CLEARs; the state may wobble to RECOVERING and
       is back in ALERTING before k non-exceeding passes elapse
  R8   once the host is back, CLEAR lands on the third pass and names the outage that ended
  R9   a 70-second lab-style run (S4's link-down) does NOT page - below threshold by design
  R10  the alert carries its evidence: run length in probes and minutes, since when, the
       cadence, and the longest earlier run on this path

Evaluations are run at chosen moments in the past, so one constructed day yields the whole
state history of every case. Throwaway database; never the real one.
"""
from __future__ import annotations

import os
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netdown_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB          # before any project import

import net_store                                                     # noqa: E402

NET = "dddddddddddd"
IDENTITY = dict(net_id=NET, label="test-net", gateway="10.7.0.1", gw_mac="00:aa:bb:cc:dd:ee",
                ssid="test-net", subnet="10.7.0.0/24", strength="strong", assumed=False)
net_store.network_identity = lambda force=False: dict(IDENTITY)      # noqa: E731 - hermetic

import net_alert                                                     # noqa: E402
import net_memory                                                    # noqa: E402

M = 60.0
NOW = float(int(time.time()) // 60 * 60)
START = NOW - 9 * 3600


def check(name: str, ok, detail: str = "") -> bool:
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def series(target: str, cadence: float, down_when, start: float = START,
           end: float = NOW) -> list[tuple]:
    """(ts, target, 'reachable', value, net) rows from start to end, down where down_when(ts)."""
    out, t = [], start
    while t <= end + 1e-6:
        out.append((int(t), target, "reachable", 0.0 if down_when(t) else 1.0, NET))
        t += cadence
    return out


def between(a_min: float, b_min: float):
    """Down when NOW - a_min <= ts <= NOW - b_min (minutes before now, a >= b)."""
    return lambda ts: NOW - a_min * M <= ts <= NOW - b_min * M


def build(conn) -> None:
    rows: list[tuple] = []
    # R1 flappy: one dropped probe every 27 minutes, twenty of them
    drops = {int(START + (13 + 27 * k) * M) for k in range(20)}
    rows += series("flappy", M, lambda ts: int(ts) in drops)
    # R2 flap3: the last three probes down - 3 probes, ~2 min, ongoing
    rows += series("flap3", M, between(2, 0))
    # R3 slow-http: 5 min cadence, last three probes down - 3 probes, 10 min, ongoing
    rows += series("slow-http", 5 * M, between(10, 0))
    # R4 outage: down for the last 29 minutes, ongoing
    rows += series("outage", M, between(29, 0))
    # R5 outage-hist: the same, with two 100-minute outages earlier in the same history
    rows += series("outage-hist", M, lambda ts: between(29, 0)(ts) or between(440, 340)(ts)
                   or between(280, 180)(ts))
    # R6 gap-down: 30 failures ending 151 min ago, then NOTHING - the collector stopped
    #    probing this one (its heartbeats continue, so the network as a whole is evaluated)
    rows += series("gap-down", M, between(180, 151), end=NOW - 151 * M)
    # R7 blip: down 40..11 min ago, one up probe at 10, down again 9..0
    rows += series("blip", M, lambda ts: between(40, 11)(ts) or between(9, 0)(ts))
    # R8 recovered: down 60..31 min ago, up ever since
    rows += series("recovered", M, between(60, 31))
    # R9 lab-s4: 5 s cadence for 7 h, down for the last 70 s (14 probes), ongoing
    rows += series("lab-s4", 5.0, between(70 / 60, 0), start=NOW - 7 * 3600)
    conn.executemany("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                     "VALUES (?,?,?,?,?)", rows)
    conn.executemany("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) "
                     "VALUES (?,?,?,?)",
                     [(int(START + k * M) + 3, NET, 9, 0) for k in range(int(9 * 60) + 1)])
    conn.commit()
    print(f"built {len(rows)} samples across 9 paths, 9 h ending now")


# Evaluation moments, minutes before now, chronological. The last four are seconds apart and
# see identical evidence - only the confirmation count changes between them.
PASSES = [50, 45, 40, 30, 25, 20, 11, 10, 5, 0, -1 / 60, -2 / 60, -3 / 60]


def main() -> int:
    conn = net_store.connect()
    build(conn)

    hist: dict[str, list[tuple[float, str, str]]] = {}
    texts: dict[tuple[str, str], str] = {}
    for p in PASSES:
        at = NOW - p * M
        for r in net_alert.evaluate(conn, now=at, verbose=False):
            if r["metric"] != "reachable":
                continue
            hist.setdefault(r["target"], []).append((p, r["state"], r["note"]))
            if r["note"] in ("FIRED", "CLEARED"):
                row = conn.execute("SELECT detail FROM alert_log WHERE target=? AND kind=? "
                                   "ORDER BY ts DESC LIMIT 1", (r["target"], r["note"])).fetchone()
                texts[(r["target"], r["note"])] = row[0] if row else ""

    print("\nstate per pass (minutes before now)")
    for tgt, h in sorted(hist.items()):
        print(f"  {tgt:<12} " + " ".join(
            f"[{p:>3.0f}:{s[:5]}{'*' if n in ('FIRED', 'CLEARED') else ''}]" for p, s, n in h))

    def states(t): return [s for _, s, _ in hist[t]]
    def events(t): return [n for _, _, n in hist[t] if n in ("FIRED", "CLEARED")]
    def at(t, p): return next(s for q, s, _ in hist[t] if abs(q - p) < 1e-9)

    print("\nchecks")
    ok = True
    ok &= check("R1  twenty single drops never leave OK", set(states("flappy")) == {"OK"},
                str(set(states("flappy"))))
    ok &= check("R2  a 3-probe 2-minute flap never leaves OK", set(states("flap3")) == {"OK"},
                hist["flap3"][-1][2])
    d3 = net_alert.down_run(conn, "slow-http", NET, NOW)
    ok &= check("R3  3 probes on a 5-min cadence exceed (probes AND minutes both met)",
                d3["exceeds"] and d3["run"]["n"] == 3
                and d3["run"]["end"] - d3["run"]["start"] >= net_alert.DOWN_MIN_S,
                d3["note"])
    ok &= check("R3  and it reaches ALERTING within k passes", states("slow-http")[-1] == "ALERTING")
    ok &= check("R4  the outage fires on the third exceeding pass, not before",
                at("outage", 20) == "SUSPECT" and at("outage", 11) == "SUSPECT"
                and at("outage", 10) == "ALERTING" and events("outage") == ["FIRED"],
                " -> ".join(states("outage")[3:7]))
    ok &= check("R4  and was OK while the run was under five minutes", at("outage", 25) == "OK",
                hist["outage"][4][2])

    a = net_memory.assess("outage-hist", "reachable", net_alert.RECENT_HOURS,
                          net_alert.BASELINE_DAYS, now=NOW)
    floor_fires = a["status"] == "ok" and net_alert.worth_alerting(a)[0]
    ok &= check("R5  the placebo path does NOT fire on an outage with outages in its history",
                not floor_fires,
                (f"status={a['status']}" + (f" shift={a['shift'] * 100:+.0f}% floor="
                                            f"{a['noise_floor'] * 100:.0f}%"
                                            if a["status"] == "ok" else "")))
    ok &= check("R5  the run rule fires on it regardless",
                states("outage-hist")[-1] == "ALERTING" and events("outage-hist") == ["FIRED"],
                " -> ".join(states("outage-hist")[3:7]))
    ok &= check("R6  a down run followed by a gap never fires - open-ended is not ongoing",
                set(states("gap-down")) == {"OK"}, hist["gap-down"][-1][2])
    ok &= check("R7  one up probe inside an outage never CLEARs",
                "CLEARED" not in events("blip") and events("blip") == ["FIRED"])
    ok &= check("R7  it wobbles to RECOVERING on the up probe and is ALERTING again at the end",
                at("blip", 10) == "RECOVERING" and at("blip", 0) == "ALERTING"
                and states("blip")[-1] == "ALERTING",
                " -> ".join(states("blip")[5:10]))
    ok &= check("R8  after the host is back, CLEAR lands on the third pass",
                at("recovered", 30) == "RECOVERING" and at("recovered", 25) == "RECOVERING"
                and at("recovered", 20) == "OK" and events("recovered") == ["FIRED", "CLEARED"],
                " -> ".join(states("recovered")[:6]))
    ct = texts.get(("recovered", "CLEARED"), "")
    ok &= check("R8  and the CLEAR names the outage that ended, in probes and minutes",
                "reachable again" in ct and "30 consecutive failures" in ct and "min" in ct,
                # a detail must never raise: a one-line CLEAR is a failure, not a crash
                (ct.splitlines()[1:2] or [ct])[0] if ct else "no CLEAR text")
    ok &= check("R9  a 70 s lab-style run does not page (below threshold by design)",
                set(states("lab-s4")) == {"OK"}, hist["lab-s4"][-1][2])
    d9 = net_alert.down_run(conn, "lab-s4", NET, NOW)
    # 15, not 14: between() is inclusive at both ends, so 70 s at 5 s is fifteen probes.
    ok &= check("R9  though the run itself is seen: 15 probes, 70 s, ongoing",
                d9["run"] is not None and d9["run"]["n"] == 15 and not d9["exceeds"]
                and d9["run"]["end"] - d9["run"]["start"] < net_alert.DOWN_MIN_S, d9["note"])
    ft = texts.get(("outage-hist", "FIRED"), "")
    ok &= check("R10 the alert carries run length, since-when, cadence and the longest earlier run",
                "consecutive failures" in ft and "since" in ft and "probe every 60 s" in ft
                and "longest earlier : 101 failures" in ft,        # inclusive range: 101
                "\n        ".join(ft.splitlines()[:5]) if ft else "no FIRED text")
    ft0 = texts.get(("outage", "FIRED"), "")
    ok &= check("R10 with no earlier run it says so rather than omitting the line",
                "longest earlier : none" in ft0)
    ok &= check("R10 and every run alert says it was judged by run length, not a floor",
                all("judged by run length" in t for t in texts.values()))

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    conn.close()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
