"""Does the availability timeline show the SHAPE of an event, not just its statistics?

    python test_net_availability.py

The case it exists for is a real one. On 2026-09-06 the network was cut for 33 minutes, every
failed probe was recorded, and the agent - reading baseline's "median 0%, p95 100%" - called
it "brief cellular dropouts, episodes not a steady condition". Nothing had shown it the
samples in order. This suite constructs that evening: an ordinary blip, a long outage, a
sleep that hides the outage's end, a recovery, a host the collector skipped while running,
and a host the agent probed twice afterwards - and requires each to be reported as what it
is. The last two are there because the real data had them and the first version of the tool
got both wrong.

Writes only to a throwaway database.
"""
from __future__ import annotations

import os
import re
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netavail_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_memory                                                    # noqa: E402
import net_store                                                     # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()["net_id"]
STEP = 60
NOW = int(time.time()) // 60 * 60
OUTAGE = range(213, 180, -1)          # 33 minutes, counted back from now


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def put(target: str, minutes_ago: int, up: bool) -> None:
    CONN.execute("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                 "VALUES (?,?,?,?,?)",
                 (NOW - minutes_ago * STEP, target, "reachable", 1.0 if up else 0.0, NET))


def beat(minutes_ago: int, offset_s: int = 5) -> None:
    # A few seconds AFTER the samples of that cycle, as the real collector does - which is
    # what puts one stray heartbeat just inside every gap.
    CONN.execute("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) VALUES (?,?,?,?)",
                 (NOW - minutes_ago * STEP + offset_s, NET, 1, 0))


def kinds(text: str) -> list[str]:
    """The sequence of run kinds as printed, for order checks that say what went wrong."""
    return re.findall(r"^\s+\S+ \S+ \S+ -> \S+(?: \S+ \S+)?\s+(NOT MEASURED|DOWN|up)\b",
                      text, re.M)


def main() -> int:
    # The evening, minute by minute, counted back from now:
    #   300..241  up
    #   240       one dropped probe on gw alone - a blip, not an outage
    #   239..214  up
    #   213..181  DOWN on every monitored host   <- the outage
    #   180..11   nothing at all: the machine slept, so no heartbeats either
    #   10..0     up again
    for m in range(300, 180, -1):
        down = m in OUTAGE
        put("gw", m, not down and m != 240)
        put("dns", m, not down)
        if not (260 >= m >= 230):                  # web was skipped for half an hour
            put("web", m, not down)                 # while the collector kept running
        beat(m)
    for m in range(10, -1, -1):
        for t in ("gw", "dns", "web"):
            put(t, m, True)
        beat(m)
    put("adhoc", 3, True)                           # probed twice by the agent, afterwards
    put("adhoc", 2, True)
    CONN.commit()

    ok = True
    gw = net_memory.availability("gw", hours=6)
    print(gw, "\n")

    ok &= check("the outage is one run of 33 consecutive failures",
                "33 consecutive failures" in gw)
    ok &= check("its end is UNKNOWN, because measurement stopped while it was still down",
                "END UNKNOWN" in gw and "still down when measurement stopped" in gw)
    ok &= check("and the first observation afterwards is named, with its state",
                "the next observation" in gw and "was up" in gw)
    ok &= check("the blip is reported as a single dropped probe, distinct from the outage",
                "1 failed probe" in gw and "single dropped probe, which is not an outage" in gw)
    ok &= check("runs come out in time order",
                kinds(gw) == ["NOT MEASURED", "up", "DOWN", "up", "DOWN", "NOT MEASURED", "up"],
                str(kinds(gw)))
    ok &= check("the summary names the longest run and where it started",
                "longest 32 min" in gw, gw.splitlines()[-1][:90])
    # The heartbeat for the last cycle before sleep lands seconds after its samples, inside
    # the gap. That single cycle must not turn a sleeping collector into a running one.
    ok &= check("the sleep is NOT MEASURED and the collector was NOT running, despite one "
                "stray heartbeat inside the gap",
                "collector was not running" in gw.split("33 consecutive")[1]
                and "did not probe this host" not in gw.split("33 consecutive")[1])

    web = net_memory.availability("web", hours=6)
    ok &= check("a host the collector skipped while running says so, and does not blame sleep",
                "collector ran" in web and "did not probe this host" in web)
    ok &= check("but ITS sleep gap is still the collector not running",
                "collector was not running" in web.split("33 consecutive")[1])

    ok &= check("a host with no availability data says so rather than inventing a timeline",
                "no reachability probes" in net_memory.availability("nothing", hours=6))

    every = net_memory.availability(hours=6)
    ok &= check("with no target, every monitored host is reported",
                all(f"availability of {t}" in every for t in ("gw", "dns", "web")))
    ok &= check("a host probed twice is named, not given a timeline, and not hidden",
                "adhoc" in every and "availability of adhoc" not in every
                and "fewer than 3 times" in every)
    ok &= check("the period when EVERY observed host was down together is named - the outage",
                "under observation was down at once" in every and "32 min" in every)
    ok &= check("and the twice-probed host, absent during the outage, did not veto that",
                "At no point" not in every)
    ok &= check("but the blip, which hit gw alone, does not count as the network",
                every.split("down at once")[1].count("->") == 1)

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
