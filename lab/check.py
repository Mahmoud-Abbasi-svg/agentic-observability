"""What the tools say about the lab right now. Runs INSIDE the client container.

    python /app/lab/check.py route            # route_history for the server
    python /app/lab/check.py avail            # availability, last hour, from the PINGER
    python /app/lab/check.py change           # detect_change, every probe type, lab windows
    python /app/lab/check.py ics              # the PASSIVE path: ingest the capture, then
                                              # availability and the run rule from it alone
    python /app/lab/check.py all              # route, avail, change (not ics)

The lab runs at seconds, not minutes, so the windows are lab-sized: the per-hop table
compares the last 90 s against everything before it, and detect_change the same. Nothing
about the tools is changed for the lab; only the arguments are.

Every mode also prints one `verdict <target>: ...` line per host, and `ics` one
`rule6 <target>: ...` line, so lab.sh can match a scenario's expectation on a single line
(grep -E does not span newlines). The verdict is computed by the same _runs the tools use.

`ics` MUST set the database before anything from the project is imported: net_memory opens
its connection lazily from NET_MONITOR_DB and net_store reads that variable at call time, so
the order here is what keeps the capture out of the pinger's database.
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, "/app")

SERVER = "10.0.4.10"
GATEWAY = "10.0.1.1"
RECENT_H = 90 / 3600.0
PCAP = "/data/ics.pcap"
ICS_DB = "/data/ics.db"


def verdicts(net_memory, net_id: str, hours: float = 1.0) -> str:
    """One line per host: the longest DOWN run, or never down, or not measured. Same cut as
    `availability`, so the line and the prose cannot disagree."""
    import sqlite3
    now = time.time()
    since = now - hours * 3600
    conn = net_memory.conn()
    beats = [r[0] for r in conn.execute(
        "SELECT ts FROM heartbeat WHERE net_id=? AND ts>=? ORDER BY ts", (net_id, since))]
    bd = [b - a for a, b in zip(beats, beats[1:]) if b > a]
    bc = sorted(bd)[len(bd) // 2] if bd else 0.0
    out = []
    for (t,) in conn.execute(
            "SELECT DISTINCT target FROM sample WHERE net_id=? AND metric='reachable' "
            "AND ts>=? ORDER BY target", (net_id, since)):
        rows = list(conn.execute(
            "SELECT ts, value FROM sample WHERE target=? AND metric='reachable' AND net_id=? "
            "AND ts>=? ORDER BY ts", (t, net_id, since)))
        runs = net_memory._runs(rows, since, now, beats, bc)
        downs = [r for r in runs if r["kind"] == "down"]
        if downs:
            lg = max(downs, key=lambda r: r["end"] - r["start"])
            out.append(f"verdict {t}: DOWN {(lg['end'] - lg['start']) / 60:.1f} min longest "
                       f"run ({lg['n']} consecutive), {len(downs)} run(s)")
        elif any(r["kind"] != "gap" for r in runs):
            out.append(f"verdict {t}: never down ({len(rows)} probes)")
        else:
            out.append(f"verdict {t}: not measured")
    return "\n".join(out)


def route(net_memory) -> str:
    return net_memory.route_history(SERVER, days=1, recent_hours=RECENT_H)


def avail(net_memory, net_store) -> str:
    net_id = net_store.network_identity()["net_id"]
    return net_memory.availability(hours=1.0) + "\n" + verdicts(net_memory, net_id)


def change(net_memory) -> str:
    return net_memory.detect_change(SERVER, "all", recent_hours=RECENT_H, baseline_days=1)


def ics() -> str:
    """Ingest the live capture into its own database and judge it with the same tools."""
    for f in (ICS_DB, ICS_DB + "-wal", ICS_DB + "-shm"):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    os.environ["NET_MONITOR_DB"] = ICS_DB
    import net_ingest                                                # noqa: PLC0415
    # shift=False: this capture IS now. Shifting would move nothing and mislabel it a replay.
    r = net_ingest.ingest(PCAP, ICS_DB, label="lab capture (passive)", shift=False, port=5020)
    os.environ["NET_REPLAY_ID"] = r["net_id"]
    import net_alert                                                 # noqa: PLC0415
    import net_memory                                                # noqa: PLC0415
    import net_store                                                 # noqa: PLC0415
    lines = [f"capture: {sum(r['requests'].values())} Modbus requests on {r['streams']} "
             f"stream(s), {r['transactions']} answered, "
             f"{sum(r['unanswered'].values())} unanswered, {r['unresolved']} unresolved"]
    for t, c in r["requests"].items():
        un = r["unanswered"].get(t, 0)
        lines.append(f"  {t:<16}{c:>6} requests {c - un:>6} answered"
                     + (f" {un:>5} UNANSWERED" if un else ""))
    # The capture has no heartbeats; _runs then cuts gaps from the request cadence alone,
    # which is the honest reading of a capture: silence on the wire is silence.
    lines.append(net_memory.availability(hours=1.0))
    lines.append(verdicts(net_memory, r["net_id"]))
    conn = net_store.connect(ICS_DB)
    now = time.time()
    for t in r["requests"]:
        d = net_alert.down_run(conn, t, r["net_id"], now)
        lines.append(f"rule6 {t}: {d['note']}" + ("   EXCEEDS" if d["exceeds"] else ""))
    return "\n".join(lines)


def main() -> int:
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what == "ics":
        print(f"### ics\n{ics()}\n")
        return 0
    import net_memory                                                # noqa: PLC0415
    import net_store                                                 # noqa: PLC0415
    parts = {"route": lambda: route(net_memory),
             "avail": lambda: avail(net_memory, net_store),
             "change": lambda: change(net_memory)}
    for k, fn in parts.items():
        if what in (k, "all"):
            print(f"### {k}\n{fn()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
