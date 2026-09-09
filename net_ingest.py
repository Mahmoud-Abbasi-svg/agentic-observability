"""Turn a packet capture into the same kind of series the collector produces.

    python net_ingest.py clean.pcap --db ics.db
    python net_ingest.py clean.pcap --db ics.db --label "lemay 6-RTU poll"
    python net_ingest.py big.pcap  --db ics.db --bin 5      one row per 5 s, median

WHY PASSIVE INGESTION AND NOT PROBING

`net_collect.py` measures by sending traffic. On an industrial network that is often forbidden
and sometimes unsafe: a control loop with a cyclic budget does not want extra packets in it,
and ICMP is frequently disabled on the switches anyway. Industrial monitoring is passive - a
SPAN port, a TAP, or a stored capture.

Nothing downstream has to change. `net_memory`, `net_alert`, `net_size` and `net_verify` only
ever see rows of (ts, target, metric, value), and do not care whether a number came from a
probe this machine sent or from a conversation it merely watched.

WHERE THE LATENCY COMES FROM

Modbus/TCP carries a transaction identifier in its 7-byte MBAP header, and a server echoes it
in the reply. Pairing them gives a genuine response time per transaction - real timing, real
quantisation from the capture clock, no simulation. That is the whole point of using a capture
rather than a simulator: a simulated noise floor is whatever you programmed it to be.

TWO THINGS THIS DOES THAT MUST BE STATED, NOT HIDDEN

1. It writes under its OWN network identity, derived from the capture, never the live one.
   Baselines are per-network so that one path's normal is never compared against another's,
   and a 2016 factory capture must not contaminate the baseline for your office Wi-Fi.

2. It SHIFTS the timestamps forward so the capture ends "now". Every analysis function asks
   for the last N days relative to the current clock, so a 2016 capture would otherwise be
   invisible to all of them. Only the epoch offset changes - every interval, gap and ordering
   is preserved exactly - and the original start date is written into the network label so the
   data can never be mistaken for live measurement. `--no-shift` keeps the real times, and
   then the analysis tools will find nothing, which is why it is not the default.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import statistics
import struct
import sys
import time
from collections import defaultdict
from typing import Iterator, Optional

MBAP = 7                    # transId(2) protoId(2) length(2) unitId(1), then the function code
MODBUS_PORT = 502


def _reader(path: str):
    try:
        from scapy.all import PcapReader                            # noqa: PLC0415
    except ImportError:
        raise SystemExit("scapy is required to read captures:  pip install scapy")
    return PcapReader(path)


MIN_GAPS_TO_JUDGE = 5       # inter-request gaps a stream must show before rule ii applies
STALE_GAPS = 2.0            # a pending request older than this many typical gaps is unanswered


def modbus_events(path: str, port: int = MODBUS_PORT,
                  stats: Optional[dict] = None) -> Iterator[dict]:
    """Yield every Modbus request as one event: answered (with its response time) or not.

    Streamed rather than loaded: the 4SICS captures are 200 MB, and holding a parsed copy of
    one in memory to compute a median is a waste of a machine that also has to do other work.

    THE PASSIVE MEANING OF "DOWN". A collector measures reachability by sending a probe and
    seeing whether it is answered. A capture cannot send anything; its equivalent of a failed
    probe is a request that got no reply. The first version of this reader paired replies with
    requests and dropped the rest, so the one event that matters most on a plant floor - the
    device went silent - was the one event it could not see.

    A pending request is judged UNANSWERED by two rules, neither of them a constant:
      i.  a LATER request on the same stream (client, server, unit) was answered while this one
          is still pending. Modbus over one connection answers in order; the device skipped it.
      ii. a newer request is sent on the stream and this one is older than STALE_GAPS times the
          stream's own typical inter-request gap (running median of the last 20, judged only
          once MIN_GAPS_TO_JUDGE have been seen). Rule i cannot fire when the device has gone
          silent for good - nothing later is ever answered - and that is exactly the case that
          matters, so the stream's own cadence supplies the deadline.
    Requests still pending when the capture ends are UNRESOLVED, not unanswered: "the capture
    stopped" and "the device did not answer" are different statements and the data only
    supports the first. They are counted in `stats` and never yielded.

    Matching is on (client socket, unit, transaction id). Transaction ids are 16 bits and wrap,
    so a pending request is replaced if the same key is seen twice - the second is the live
    one, and pairing the reply with the older would invent a response time of however long the
    wrap took. The replaced one is judged by the rules above like any other.

    `stats`, if given, receives: late (replies with no pending request), unresolved,
    skipped_proto (port-502 payloads whose protocol id is not 0), skipped_short.
    """
    from scapy.all import IP, TCP                                    # noqa: PLC0415

    st = stats if stats is not None else {}
    st.update(late=0, unresolved=0, skipped_proto=0, skipped_short=0, undecided_early=0)
    # per stream: pending {key: (ts, func)}, gaps deque, last request ts
    streams: dict[tuple, dict] = {}

    def stream(client: str, server: str, unit: int) -> dict:
        s = streams.get((client, server, unit))
        if s is None:
            s = streams[(client, server, unit)] = dict(pending={}, gaps=[], last=None)
        return s

    def unanswered(s: dict, key: tuple, server: str, unit: int) -> dict:
        t0, func = s["pending"].pop(key)
        return dict(kind="unanswered", ts=t0, server=server, unit=unit, func=func & 0x7F,
                    exception=False, rtt_ms=None)

    with _reader(path) as pcap:
        for pkt in pcap:
            if IP not in pkt or TCP not in pkt:
                continue
            tcp, ip = pkt[TCP], pkt[IP]
            if tcp.dport != port and tcp.sport != port:
                continue
            payload = bytes(tcp.payload)
            if not payload:
                continue                          # pure ACKs and handshakes carry no ADU
            if len(payload) < MBAP + 1:
                st["skipped_short"] += 1
                continue
            trans, proto, _length, unit = struct.unpack(">HHHB", payload[:MBAP])
            if proto != 0:                        # protocol id 0 is what makes it Modbus
                st["skipped_proto"] += 1
                continue
            func = payload[MBAP]
            ts = float(pkt.time)

            if tcp.dport == port:                 # ---------------------------- a request
                s = stream(ip.src, ip.dst, unit)
                key = (tcp.sport, trans)
                if key in s["pending"]:           # id reused before the old one was answered
                    yield unanswered(s, key, ip.dst, unit)
                if s["last"] is not None and ts > s["last"]:
                    s["gaps"].append(ts - s["last"])
                    if len(s["gaps"]) > 20:
                        s["gaps"].pop(0)
                s["last"] = ts
                if len(s["gaps"]) >= MIN_GAPS_TO_JUDGE:          # rule ii
                    typical = statistics.median(s["gaps"])
                    stale = [k for k, (t0, _f) in s["pending"].items()
                             if ts - t0 > STALE_GAPS * typical]
                    for k in stale:
                        yield unanswered(s, k, ip.dst, unit)
                s["pending"][key] = (ts, func)
                continue

            # ------------------------------------------------------------------ a reply
            s = stream(ip.dst, ip.src, unit)
            key = (tcp.dport, trans)
            hit = s["pending"].pop(key, None)
            if hit is None:
                st["late"] += 1
                continue
            t0, _f = hit
            yield dict(kind="reply", ts=t0, server=ip.src, unit=unit, func=func & 0x7F,
                       exception=bool(func & 0x80), rtt_ms=(ts - t0) * 1000.0)
            older = [k for k, (tp, _f) in s["pending"].items() if tp < t0]     # rule i
            for k in older:
                yield unanswered(s, k, ip.src, unit)

    st["unresolved"] = sum(len(s["pending"]) for s in streams.values())
    st["streams"] = len(streams)


def modbus_transactions(path: str, port: int = MODBUS_PORT) -> Iterator[dict]:
    """The answered requests only, as before. Kept for callers that want pairs."""
    for ev in modbus_events(path, port):
        if ev["kind"] == "reply":
            yield ev


def _bin_rows(rows: list[tuple[float, float]], width: float) -> list[tuple[float, float]]:
    """Median per fixed window.

    Binning changes what the data IS: `net_memory` reads the smallest step between distinct
    values to infer the instrument's resolution, and a median over a bin destroys that. Use it
    only when a capture is too dense to work with, and know that the reported instrument
    quantum afterwards describes the binning, not the capture.
    """
    buckets: dict[int, list[float]] = defaultdict(list)
    for ts, v in rows:
        buckets[int(ts // width)].append(v)
    return [(b * width + width / 2, statistics.median(vs)) for b, vs in sorted(buckets.items())]


def ingest(path: str, db: str, label: str = "", shift: bool = True,
           bin_s: float = 0.0, port: int = MODBUS_PORT) -> dict:
    # The connection is opened by explicit path rather than through NET_MONITOR_DB: that
    # variable is read once when net_store is imported, so setting it here would silently do
    # nothing in any process that had already imported the module.
    import net_store                                                 # noqa: PLC0415

    conn = net_store.connect(db)

    per_server: dict[str, list[tuple[float, float]]] = defaultdict(list)   # answered
    reach: dict[str, list[tuple[float, float]]] = defaultdict(list)        # every request
    exceptions: dict[str, int] = defaultdict(int)
    unanswered: dict[str, int] = defaultdict(int)
    stats: dict = {}
    n = 0
    for t in modbus_events(path, port, stats):
        target = f"{t['server']}:{t['unit']}" if t["unit"] else t["server"]
        if t["kind"] == "reply":
            per_server[target].append((t["ts"], t["rtt_ms"]))
            reach[target].append((t["ts"], 1.0))
            if t["exception"]:
                exceptions[target] += 1
            n += 1
        else:
            reach[target].append((t["ts"], 0.0))
            unanswered[target] += 1

    if not n and not unanswered:
        raise SystemExit(f"{path}: no Modbus/TCP requests on port {port} "
                         f"({stats.get('skipped_proto', 0)} port-{port} payloads with a "
                         f"non-Modbus protocol id, {stats.get('skipped_short', 0)} too short). "
                         f"Is this the right protocol? Try --port.")

    first = min(r[0] for rows in reach.values() for r in rows)
    last = max(r[0] for rows in reach.values() for r in rows)
    offset = (time.time() - last) if shift else 0.0

    # The identity is the CAPTURE's, not this machine's, and is derived from the file so that
    # re-ingesting the same capture lands in the same network rather than creating a new one.
    basis = f"pcap:{os.path.basename(path)}:{first:.3f}"
    net_id = hashlib.sha1(basis.encode()).hexdigest()[:12]
    when = time.strftime("%Y-%m-%d", time.localtime(first))
    info = dict(net_id=net_id,
                label=label or f"replay {os.path.basename(path)} ({when})",
                gateway=None, gw_mac=None, ssid=None,
                subnet=f"capture of {os.path.basename(path)}")
    net_store.remember_net(conn, info)

    offered = 0
    for target, rows in sorted(per_server.items()):
        rows = sorted(rows)
        if bin_s > 0:
            rows = _bin_rows(rows, bin_s)
        for ts, v in rows:
            offered += net_store.add_samples(conn, target, {"response_ms": v},
                                             net_id, ts=ts + offset)
    # Every request, answered or not, as a reachable sample at the REQUEST's time. This is
    # the series availability, the report, the live page and alert rule 6 all read, so the
    # passive path gets them without any of them changing. Never binned: a run of zeros is
    # the event, and a median over a bin would erase it.
    for target, rows in sorted(reach.items()):
        for ts, v in sorted(rows):
            net_store.add_samples(conn, target, {"reachable": v}, net_id, ts=ts + offset)
    conn.commit()

    # Count what is actually in the table, not what was handed to it. add_samples returns the
    # number of rows it was given, and the primary key is (target, metric, ts) with INSERT OR
    # REPLACE - so two measurements sharing a timestamp collapse into one and report success.
    # On the first real capture that silently discarded two thirds of the data, and a noise
    # floor was then computed on the remainder with no indication anything was missing.
    stored = {t: c for t, c in conn.execute(
        "SELECT target, COUNT(*) FROM sample WHERE net_id=? AND metric='response_ms' "
        "GROUP BY target", (net_id,))}
    written = sum(stored.values())
    lost = offered - written
    if lost > 0 and bin_s <= 0:
        print(f"\n  WARNING: {lost} of {offered} samples ({100.0 * lost / offered:.0f}%) "
              f"collided on timestamp and were overwritten.\n"
              f"  Two measurements of the same target cannot share a time. Every statistic "
              f"below is computed on what survived.", file=sys.stderr)

    reach_stored = {t: c for t, c in conn.execute(
        "SELECT target, COUNT(*) FROM sample WHERE net_id=? AND metric='reachable' "
        "GROUP BY target", (net_id,))}
    return dict(db=db, net_id=net_id, label=info["label"], transactions=n, written=written,
                offered=offered, lost=lost, stored=stored,
                targets={t: len(r) for t, r in sorted(per_server.items())},
                requests={t: len(r) for t, r in sorted(reach.items())},
                reach_stored=reach_stored,
                unanswered=dict(unanswered), unresolved=stats.get("unresolved", 0),
                late=stats.get("late", 0), skipped_proto=stats.get("skipped_proto", 0),
                skipped_short=stats.get("skipped_short", 0), streams=stats.get("streams", 0),
                exceptions=dict(exceptions), first=first, last=last,
                span_h=(last - first) / 3600.0, shifted=shift)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Read Modbus/TCP response times out of a capture into the sample store.")
    ap.add_argument("pcap")
    ap.add_argument("--db", default="ics.db", help="a SEPARATE database; do not mix a capture "
                                                   "with live measurements")
    ap.add_argument("--label", default="")
    ap.add_argument("--port", type=int, default=MODBUS_PORT)
    ap.add_argument("--bin", type=float, default=0.0, dest="bin_s",
                    help="seconds per bin, median (destroys instrument quantisation)")
    ap.add_argument("--no-shift", action="store_true",
                    help="keep the original capture timestamps; the analysis tools will then "
                         "find nothing, because they all ask for the last N days")
    a = ap.parse_args()

    if os.path.abspath(a.db) == os.path.abspath(
            os.environ.get("NET_MONITOR_DB", "net_monitor.db")):
        print("refusing to write a capture into the live database; pass a different --db",
              file=sys.stderr)
        return 2

    r = ingest(a.pcap, a.db, a.label, not a.no_shift, a.bin_s, a.port)

    total_req = sum(r["requests"].values())
    total_un = sum(r["unanswered"].values())
    print(f"\n{total_req} Modbus request(s) over {r['span_h']:.2f} h on {r['streams']} "
          f"stream(s): {r['transactions']} answered, {total_un} unanswered, "
          f"{r['unresolved']} unresolved at the end of the capture")
    print(f"-> {r['written']} response_ms + {sum(r['reach_stored'].values())} reachable "
          f"sample(s) in {r['db']}")
    print(f"network {r['net_id']}  {r['label']!r}")
    for t, c in r["requests"].items():
        exc = r["exceptions"].get(t, 0)
        un = r["unanswered"].get(t, 0)
        print(f"  {t:<24}{c:>8} requests  {c - un:>8} answered"
              + (f"  {un:>6} UNANSWERED" if un else "")
              + (f"   ({exc} Modbus exceptions)" if exc else ""))
    skipped = []
    if r["late"]:
        skipped.append(f"{r['late']} reply(ies) with no pending request (mid-stream start, "
                       f"or a reply after its request was already judged)")
    if r["skipped_proto"]:
        skipped.append(f"{r['skipped_proto']} port-{a.port} payload(s) with a non-Modbus "
                       f"protocol id, skipped")
    if r["skipped_short"]:
        skipped.append(f"{r['skipped_short']} port-{a.port} payload(s) too short for an MBAP "
                       f"header, skipped")
    if r["unresolved"]:
        skipped.append(f"{r['unresolved']} request(s) still pending when the capture ended: "
                       f"UNRESOLVED, not stored as failures")
    for s in skipped:
        print(f"  note: {s}")
    if r["shifted"]:
        print("\ntimestamps shifted so the capture ends now; intervals are unchanged")
    print("\nnow analyse it - the replay identity keeps it out of your live baselines:\n"
          f'  set NET_MONITOR_DB={r["db"]}\n'
          f'  set NET_REPLAY_ID={r["net_id"]}\n'
          f"  python net_db.py targets\n"
          f"  python net_size.py --goal 5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
