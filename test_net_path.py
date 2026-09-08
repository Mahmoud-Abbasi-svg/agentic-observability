"""Does route_history tell a route CHANGE from a route that ALTERNATES, and from the same
route getting slower?

    python test_net_path.py

The trap it exists for is per-flow load balancing: two traceroutes that differ are not
evidence that anything changed, because the network may hash each probe onto a different
equal-cost link every time. A tool that reported every such difference as a reroute would be
the attribution error this project keeps finding in its own instruments - the measurement
right, the meaning invented. So the cases below are pre-registered: each constructs a history
whose truth is known, and requires the verdict to say that and only that.

Runs offline against a throwaway database. The parser fixtures are real tracert output from
this machine plus the Linux format, with the "<1 ms" and mixed-silence lines both formats
produce.
"""
from __future__ import annotations

import os
import random
import re
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netpath_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_memory                                                    # noqa: E402
import net_store                                                     # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()["net_id"]
NOW = time.time()
STEP = 600.0                       # the collector traces every 10 min

WINDOWS = """host=1.1.1.1 max_hops=15 exit_code=0
--- raw ---
Tracing route to 1.1.1.1 over a maximum of 15 hops

  1    <1 ms     2 ms     3 ms  172.20.10.1
  2     *        *        *     Request timed out.
  3    57 ms    45 ms    52 ms  172.29.39.105
  4     *       30 ms     *     172.29.37.33
  5     *        *        *     Request timed out.
  6    67 ms    69 ms   102 ms  188.114.108.4
  7    53 ms    93 ms    27 ms  188.114.108.10
  8    36 ms    30 ms    29 ms  188.114.108.9
  9    28 ms    39 ms    38 ms  1.1.1.1

Trace complete."""

LINUX = """host=example.com max_hops=30 exit_code=0
--- raw ---
traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  192.168.1.1  0,412 ms  0,380 ms  0,355 ms
 2  * * *
 3  10.0.0.1  1.2 ms 10.0.0.2  1.3 ms 10.0.0.1  1.1 ms
 4  93.184.216.34  12.001 ms  11.9 ms  12.2 ms"""

UNREACHED = """host=10.99.0.1 max_hops=6 exit_code=0
--- raw ---
Tracing route to 10.99.0.1 over a maximum of 6 hops

  1     1 ms     1 ms     1 ms  172.20.10.1
  2    40 ms    41 ms    39 ms  172.29.39.105
  3     *        *        *     Request timed out.
  4     *        *        *     Request timed out.
  5     *        *        *     Request timed out.
  6     *        *        *     Request timed out.

Trace complete."""

A = ["172.20.10.1", "*", "172.29.39.105", "172.29.37.33", "*", "188.114.108.4",
     "188.114.108.10", "188.114.108.9", "1.1.1.1"]
B = A[:3] + ["172.29.37.41", "*", "188.114.108.6"] + A[6:]          # diverges at hop 4
C = A[:5] + ["188.114.108.20", "188.114.108.21"] + A[7:]           # a third branch


def check(name: str, ok, detail: str = "") -> bool:
    # bool(), not the value: callers pass expressions like `a and b and c`, which
    # yield the last truthy operand rather than True. Suites accumulate with
    # `ok &= check(...)`, and `True & 6` is 0 - so every check printed PASS while the
    # suite reported failure. It can only raise a false alarm, never hide a real one,
    # but a suite that cries wolf gets ignored like any other.
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def put(target: str, i_back: int, addrs: list[str], rtt: float = 30.0,
        bump: dict | None = None, silent_at: int | None = None) -> None:
    """One trace, i_back steps before now. Per-hop RTT rises with the hop; `bump` adds ms at
    given hop indexes; `silent_at` blanks one hop that normally answers."""
    hops = []
    for i, a in enumerate(addrs):
        if a == "*" or i == silent_at:
            hops.append(("*", []))
        else:
            r = rtt + 3.0 * i + (bump or {}).get(i, 0.0)
            hops.append((a, [r, r + 1, r - 1]))
    net_store.add_path(CONN, target, hops, NET, reached=addrs[-1] == "1.1.1.1",
                       ts=NOW - i_back * STEP)
    CONN.commit()                     # route_history reads through its own connection


def main() -> int:
    ok = True
    pt = net_memory.parse_trace

    p = pt(WINDOWS)
    ok &= check("tracert: nine hops, addresses in order, silent hops as '*'",
                [a for a, _ in p["hops"]] == A and p["reached"] and p["target_ip"] == "1.1.1.1")
    ok &= check("tracert: '<1 ms' is 1 ms and a hop with one answer of three keeps that one",
                p["hops"][0][1] == [1.0, 2.0, 3.0] and p["hops"][3][1] == [30.0])
    p = pt(LINUX)
    ok &= check("traceroute: comma decimals, an ECMP hop with two addresses, target from the "
                "header",
                [a for a, _ in p["hops"]] == ["192.168.1.1", "*", "10.0.0.1", "93.184.216.34"]
                and p["hops"][0][1] == [0.412, 0.38, 0.355] and p["reached"]
                and p["target_ip"] == "93.184.216.34")
    p = pt(UNREACHED)
    ok &= check("a trace that never reached its target is trimmed to its last answering hop",
                [a for a, _ in p["hops"]] == ["172.20.10.1", "172.29.39.105"]
                and not p["reached"])
    ok &= check("extract_metrics records length and arrival, nothing about reachability",
                net_memory.extract_metrics("traceroute", WINDOWS)
                == {"path_hops": 9.0, "path_reached": 1.0}
                and "reachable" not in net_memory.extract_metrics("traceroute", UNREACHED))

    # record(): a traceroute the AGENT runs must land in the path table too.
    net_memory.record("traceroute", {"host": "1.1.1.1", "max_hops": 15}, WINDOWS)
    rows = net_store.paths(net_memory.conn(), "1.1.1.1", NET, 1)
    ok &= check("an agent-run traceroute is stored as a path, with the tracert silence kept",
                len(rows) == 1 and rows[0][1] == " ".join(A) and rows[0][3] == 1)
    CONN.execute("DELETE FROM path")

    # --- STABLE, with a hop that answers only sometimes
    for i in range(60, 0, -1):
        put("stable", i, A, silent_at=(3 if i % 4 == 0 else None))
    t = net_memory.route_history("stable", 1)
    ok &= check("a hop that sometimes does not answer is the same route: STABLE, one path, "
                "scoped to the span covered",
                t.startswith("route to stable") and "STABLE over 9.8 h" in t
                and "path B" not in t
                and "CHANGED" not in t and "ALTERNATING" not in t, t.splitlines()[1][:70])
    ok &= check("the silent hop is filled in from the traces that saw it",
                "  4  172.29.37.33" in t and "(never answered)" in t)

    # --- one clean change
    for i in range(100, 40, -1):
        put("change", i, A)
    for i in range(40, 0, -1):
        put("change", i, B)
    t = net_memory.route_history("change", 1)
    ok &= check("A then B: CHANGED once, placed between the last A and the first B",
                "CHANGED 1 time(s)" in t and "A -> B between" in t
                and "ALTERNATING" not in t, [l for l in t.splitlines() if "A -> B" in l][0][:90])
    ok &= check("the change names the hop where the paths diverge and where they rejoin",
                "diverges at hop 4 (172.29.37.33 -> 172.29.37.41), rejoins for the last 3 hop(s)"
                in t)
    ok &= check("it says why this is not load balancing",
                "Not load balancing" in t)

    # --- change and change back
    for i in range(100, 60, -1):
        put("flap", i, A)
    for i in range(60, 30, -1):
        put("flap", i, B)
    for i in range(30, 0, -1):
        put("flap", i, A)
    t = net_memory.route_history("flap", 1)
    ok &= check("A, B for five hours, A again: CHANGED twice, the second back to a path seen "
                "before", "CHANGED 2 time(s)" in t and "B -> A" in t
                and "(back to a path seen before)" in t and "ALTERNATING" not in t)

    # --- ECMP: the path flips at random every trace, all week. NOT a change.
    rnd = random.Random(7)
    for i in range(400, 0, -1):
        put("ecmp", i, rnd.choice([A, B]))
    t = net_memory.route_history("ecmp", 7)
    ok &= check("a path that flips at random is ALTERNATING, never CHANGED",
                "ALTERNATING: 2 paths" in t and "CHANGED" not in t
                and "load balancing" in t, t.splitlines()[1][:80])
    ok &= check("and it does not claim the rotating set changed when it did not",
                "BUT the set of paths" not in t)

    # --- ECMP whose rotating set changes: {A,B} early, {A,C} late. The alternation hides a
    # real change; the tool must say so rather than file it all under load balancing.
    rnd = random.Random(11)
    for i in range(400, 200, -1):
        put("ecmp2", i, rnd.choice([A, B]))
    for i in range(200, 0, -1):
        put("ecmp2", i, rnd.choice([A, C]))
    t = net_memory.route_history("ecmp2", 7)
    # Letters go by first appearance, which a random draw decides - so the check is on the
    # shape of the statement, not on which letters it names.
    sets = re.search(r"itself changed: ([A-Z]), ([A-Z]) in the first third of the window, "
                     r"([A-Z]), ([A-Z]) in the last", t)
    ok &= check("alternation whose SET of paths changed is reported as a change underneath",
                "ALTERNATING: 3 paths" in t and sets
                and len({sets.group(1), sets.group(2)} & {sets.group(3), sets.group(4)}) == 1)

    # --- scattered single-trace excursions: STABLE with excursions, not CHANGED, not
    # ALTERNATING (3 switches... 6 transitions in 200 traces = 3%, under the rate).
    for i in range(200, 0, -1):
        put("excur", i, B if i in (150, 90, 30) else A)
    t = net_memory.route_history("excur", 7)
    ok &= check("three lone traces on another path: STABLE plus excursions, no change claimed",
                "STABLE" in t and "3 trace(s) in 3 excursion(s)" in t and "3 on path B" in t
                and "CHANGED" not in t and "ALTERNATING" not in t)

    # --- a change across a gap: the last A at -30 steps, the first B at -6 (4 h unobserved)
    for i in range(80, 30, -1):
        put("gap", i, A)
    for i in range(6, 0, -1):
        put("gap", i, B)
    t = net_memory.route_history("gap", 1)
    ok &= check("a change across a gap says the change is somewhere in the unobserved stretch",
                "CHANGED 1 time(s)" in t and "no traces for 4.2 h in between" in t)

    # --- the first real route change this tool saw, 2026-09-08: thirteen traces on one path,
    # a 12 h shutdown, seven on another (hop 4 moved). One switch in twenty traces is a rate
    # of 0.053, just over ROTATION_RATE, and the verdict was "ALTERNATING ... not a route
    # change". A single switch is never a rotation.
    for i in range(85, 72, -1):
        put("real", i, A)
    for i in range(7, 0, -1):
        put("real", i, B)
    t = net_memory.route_history("real", 1)
    ok &= check("one switch in twenty traces is a CHANGE across the gap, not ALTERNATING",
                "CHANGED 1 time(s)" in t and "ALTERNATING" not in t
                and "no traces for 11.0 h in between" in t,
                [l for l in t.splitlines() if "A -> B" in l][0][:60])
    # And the same twenty traces with no gap: still one change.
    for i in range(20, 7, -1):
        put("real2", i, A)
    for i in range(7, 0, -1):
        put("real2", i, B)
    t = net_memory.route_history("real2", 1)
    ok &= check("one switch in twenty consecutive traces is a CHANGE",
                "CHANGED 1 time(s)" in t and "ALTERNATING" not in t)

    # --- the latest traces are on a new path but too few to be established
    for i in range(50, 2, -1):
        put("fresh", i, A)
    for i in range(2, 0, -1):
        put("fresh", i, B)
    t = net_memory.route_history("fresh", 1)
    ok &= check("two fresh traces on a new path: not yet a change, and it says to trace again",
                "STABLE" in t and "CHANGED" not in t
                and "latest 2 trace(s) took path B, too few to call established" in t)

    # --- the same route got slower: a rise at hop 6 that every later hop shares
    for i in range(60, 12, -1):
        put("slow", i, A)
    for i in range(12, 0, -1):
        put("slow", i, A, bump={5: 40.0, 6: 42.0, 7: 41.0, 8: 40.0})
    t = net_memory.route_history("slow", 1)
    ok &= check("same path, latency up from hop 6 onward: STABLE, and the rise is placed at "
                "hop 6 - its onset, not hop 7 where it happens to be largest",
                "STABLE" in t and "first appears at hop 6 (+40.0 ms) and every later hop "
                "shares it" in t, [l for l in t.splitlines() if "rise" in l][0][:90])
    ok &= check("the table defers the is-it-real question to detect_change",
                "detect_change's question" in t)

    # --- a rise at ONE hop that the hops after it do not share: a slow router, not a slow path
    for i in range(60, 12, -1):
        put("slowhop", i, A)
    for i in range(12, 0, -1):
        put("slowhop", i, A, bump={2: 80.0})
    t = net_memory.route_history("slowhop", 1)
    ok &= check("a rise at one hop alone is that router answering slowly, not the path",
                "largest rise is at hop 3 (+80.0 ms) but the hops after it do not share it" in t
                and "does not delay traffic through it" in t)

    # --- both at once: a slow router at hop 3 AND a real rise from hop 6. The spike must not
    # hide the path rise, and the path rise must not absorb the spike.
    for i in range(60, 12, -1):
        put("both", i, A)
    for i in range(12, 0, -1):
        put("both", i, A, bump={2: 80.0, 5: 40.0, 6: 40.0, 7: 40.0, 8: 40.0})
    t = net_memory.route_history("both", 1)
    ok &= check("a spike before the onset is named separately from the rise that persists",
                "first appears at hop 6 (+40.0 ms)" in t
                and "hop 3 alone shows +80.0 ms" in t)

    # --- only the target got slower
    for i in range(60, 12, -1):
        put("tgt", i, A)
    for i in range(12, 0, -1):
        put("tgt", i, A, bump={8: 30.0})
    t = net_memory.route_history("tgt", 1)
    ok &= check("a rise at the last hop only is the target, with the path unchanged",
                "rise is at the last hop only (+30.0 ms)" in t)

    # --- nothing / one trace
    t = net_memory.route_history("nothing", 1)
    ok &= check("no traces: says so and how to get some, claims nothing",
                "no traces recorded" in t and "STABLE" not in t)
    put("once", 1, A)
    t = net_memory.route_history("once", 1)
    ok &= check("one trace: a path but no comparison, and no verdict",
                "ONE TRACE" in t and "STABLE" not in t and "CHANGED" not in t)
    # Live, three minutes after the table was created: two traces a minute apart came back
    # "STABLE: every trace took the same path". True of the traces, and read as a verdict
    # about the day. Fewer than MIN_RUN agreeing traces establish nothing.
    put("twice", 2, A)
    put("twice", 1, A)
    t = net_memory.route_history("twice", 1)
    ok &= check("two agreeing traces: the same path, not STABLE",
                "SAME PATH in all 2 traces, too few" in t and "STABLE" not in t)

    # --- retention: beyond the raw window only the traces where the route DIFFERED survive
    old = NOW - (net_store.RAW_RETENTION_DAYS + 3) * 86400
    seq = [A] * 5 + [B] * 4 + [A] * 3
    for j, addrs in enumerate(seq):
        net_store.add_path(CONN, "old", [(a, [1.0]) for a in addrs], NET, True,
                           ts=old + j * STEP)
    for j in range(4):                                             # recent, all kept
        net_store.add_path(CONN, "old", [(a, [1.0]) for a in A], NET, True,
                           ts=NOW - (4 - j) * STEP)
    CONN.commit()
    res = net_store.aggregate_and_prune(CONN, now=int(NOW))
    kept = [s for _t, s, _h, _r in net_store.paths(CONN, "old", NET, 30)]
    ok &= check("pruning keeps every change point beyond the raw window and drops repeats",
                res["path_rows_dropped"] == 9
                and kept == [" ".join(A), " ".join(B), " ".join(A)] + [" ".join(A)] * 4,
                f"dropped {res['path_rows_dropped']}, kept {len(kept)}")
    t = net_memory.route_history("old", 30)
    ok &= check("and route_history says counts that far back are partial",
                "only route-change traces are kept" in t)

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
