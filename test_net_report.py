"""Does the report show what is known, and refuse to colour in what is not?

    python test_net_report.py

A picture can lie faster than prose, and in one specific way: by drawing unobserved time in
the same colour as quiet time. Every check here is about that boundary, plus the two things
this report exists for - the SHAPE of an event, and the FRESHNESS of a held alert state.

Renders against a throwaway database and parses the HTML back. Never touches the real store.
"""
from __future__ import annotations

import os
import re
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netreport_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_report                                                    # noqa: E402
import net_store                                                     # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()["net_id"]
OTHER = "bbbbbbbbbbbb"
STEP, NOW = 60, int(time.time()) // 60 * 60
HOURS = 6.0
EVIL = "<script>alert(1)</script>"


def check(name: str, ok, detail: str = "") -> bool:
    # bool(), not the value: callers pass expressions like `a and b and c`, which yield the
    # last truthy operand rather than True. The suite accumulates with `ok &= check(...)`, and
    # `True & 6` is 0 - so every check printed PASS while the suite reported failure.
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def put(target: str, m: int, up: bool) -> None:
    CONN.execute("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                 "VALUES (?,?,?,?,?)",
                 (NOW - m * STEP, target, "reachable", 1.0 if up else 0.0, NET))


def main() -> int:
    # 300..181 min ago measured (with a 30-min outage), 180..11 asleep, 10..0 measured again.
    for m in range(300, 180, -1):
        down = 250 >= m >= 221
        for t in ("gw", EVIL):
            put(t, m, not down)
        CONN.execute("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) "
                     "VALUES (?,?,?,?)", (NOW - m * STEP + 5, NET, 2, 0))
    for m in range(10, -1, -1):
        for t in ("gw", EVIL):
            put(t, m, True)
        CONN.execute("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) "
                     "VALUES (?,?,?,?)", (NOW - m * STEP + 5, NET, 2, 0))
    # The sleep window was in fact the machine on another network, end to end.
    CONN.execute("INSERT OR REPLACE INTO net (net_id,label,gateway,gw_mac,ssid,subnet,"
                 "first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
                 (OTHER, "office-wifi", "10.0.0.1", "a", "office-wifi", "10.0.0.0/24",
                  NOW - 99999, NOW))
    CONN.executemany("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) "
                     "VALUES (?,?,?,?)",
                     [(NOW - m * STEP + 7, OTHER, 2, 0) for m in range(179, 11, -1)])
    # One alert evaluated seconds ago, one abandoned on a network we left.
    CONN.executemany(
        "INSERT OR REPLACE INTO alert_state (target,metric,net_id,state,since,streak,"
        "last_shift,updated) VALUES (?,?,?,?,?,?,?,?)",
        [("gw", "loss_pct", NET, "ALERTING", NOW - 600, 3, 1.0, NOW - 30),
         ("far", "rtt_avg_ms", OTHER, "ALERTING", NOW - 90000, 3, 0.4, NOW - 80000),
         ("gw", "reachable", NET, "OK", NOW - 600, 0, 0.0, NOW - 30)])
    CONN.commit()

    h = net_report.build(HOURS)
    ok = True

    # ------------------------------------------------------------------ the colour boundary
    kinds = {k: len(re.findall(f'class="seg {k}"', h)) for k in ("up", "down", "gap", "else")}
    ok &= check("all four states are drawn, and unobserved time is not drawn as reachable",
                kinds["up"] and kinds["down"] and (kinds["gap"] or kinds["else"]), str(kinds))
    titles = re.findall(r'class="seg (\w+)"[^>]*title="([^"]*)"', h)
    ok &= check("every unobserved segment is labelled not-measured, never quiet or healthy",
                all("not measured" in t for k, t in titles if k in ("gap", "else"))
                and not any(w in t.lower() for k, t in titles if k in ("gap", "else")
                            for w in ("healthy", "quiet", "fine")))
    ok &= check("the sleep window is attributed to the other network, not to a dead collector",
                any(k == "else" and "office-wifi" in t for k, t in titles),
                next((t[:74] for k, t in titles if k == "else"), "no 'else' segment"))
    ok &= check("the legend says outright that hatched time is unknown, not quiet",
                "NOT MEASURED - unknown, not quiet" in h)
    ok &= check("and the footer refuses the reading a picture invites",
                "not observed" in h and "different from observed and quiet" in h)

    # ------------------------------------------------------------------ shape
    ok &= check("the outage is one segment carrying its length and cause",
                any(k == "down" and "consecutive failure" in t for k, t in titles),
                next((t[:74] for k, t in titles if k == "down"), ""))

    # ------------------------------------------------------------------ freshness
    ok &= check("a stale held alert is flagged, with how long ago it was evaluated",
                "last evaluated" in h and "has not been re-evaluated recently" in h)
    ok &= check("the fresh alert on this network is NOT flagged stale",
                len(re.findall(r"last evaluated", h)) == 1)
    ok &= check("the abandoned alert names the network, and that it is not the current one",
                "office-wifi (not the current one)" in h)
    ok &= check("a signal at rest is not listed as an alert",
                "reachable" not in re.search(r"<table>.*?</table>", h, re.S).group(0))

    # ------------------------------------------------------------------ it must not be a hole
    ok &= check("a target named like an injection is escaped, not embedded",
                "<script>" not in h and "&lt;script&gt;" in h)
    bad = [(l, w) for l, w in
           ((float(a), float(b)) for a, b in re.findall(r'left:([\d.]+)%;width:([\d.]+)%', h))
           if l < -0.01 or l + w > 100.01]
    ok &= check("no segment is positioned outside its window", not bad, str(bad[:3]))
    ok &= check("it is one self-contained file - no external requests",
                not re.search(r'(src|href)="(?!#)(?!data:)', h))

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
