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


def modbus_transactions(path: str, port: int = MODBUS_PORT) -> Iterator[dict]:
    """Yield one matched request/response pair at a time.

    Streamed rather than loaded: the 4SICS captures are 200 MB, and holding a parsed copy of
    one in memory to compute a median is a waste of a machine that also has to do other work.

    Matching is on (client socket, unit, transaction id). Transaction ids are only 16 bits and
    wrap, so a pending request is replaced if the same key is seen twice - the second request
    is the live one, and pairing the reply with the older request would invent a response time
    of however long the wrap took.
    """
    from scapy.all import IP, TCP                                    # noqa: PLC0415

    pending: dict[tuple, float] = {}
    unmatched = 0
    with _reader(path) as pcap:
        for pkt in pcap:
            if IP not in pkt or TCP not in pkt:
                continue
            tcp, ip = pkt[TCP], pkt[IP]
            payload = bytes(tcp.payload)
            if len(payload) < MBAP + 1:
                continue
            if tcp.dport != port and tcp.sport != port:
                continue

            trans, proto, _length, unit = struct.unpack(">HHHB", payload[:MBAP])
            if proto != 0:                       # protocol id 0 is what makes it Modbus
                continue
            func = payload[MBAP]
            ts = float(pkt.time)

            if tcp.dport == port:                # request
                key = (ip.src, tcp.sport, ip.dst, unit, trans)
                pending[key] = ts
                continue

            key = (ip.dst, tcp.dport, ip.src, unit, trans)
            t0 = pending.pop(key, None)
            if t0 is None:
                unmatched += 1
                continue
            yield dict(ts=ts, server=ip.src, unit=unit, func=func & 0x7F,
                       exception=bool(func & 0x80), rtt_ms=(ts - t0) * 1000.0)

    if unmatched:
        print(f"  {unmatched} response(s) had no matching request (capture starts mid-stream, "
              f"or requests were not captured)", file=sys.stderr)


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

    per_server: dict[str, list[tuple[float, float]]] = defaultdict(list)
    exceptions: dict[str, int] = defaultdict(int)
    n = 0
    for t in modbus_transactions(path, port):
        target = f"{t['server']}:{t['unit']}" if t["unit"] else t["server"]
        per_server[target].append((t["ts"], t["rtt_ms"]))
        if t["exception"]:
            exceptions[target] += 1
        n += 1

    if not n:
        raise SystemExit(f"{path}: no matched Modbus/TCP transactions on port {port}. "
                         f"Is this the right protocol? Try --port.")

    first = min(r[0] for rows in per_server.values() for r in rows)
    last = max(r[0] for rows in per_server.values() for r in rows)
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

    written = 0
    for target, rows in sorted(per_server.items()):
        rows = sorted(rows)
        if bin_s > 0:
            rows = _bin_rows(rows, bin_s)
        for ts, v in rows:
            written += net_store.add_samples(conn, target, {"response_ms": v},
                                             net_id, ts=int(ts + offset))
    conn.commit()

    return dict(db=db, net_id=net_id, label=info["label"], transactions=n, written=written,
                targets={t: len(r) for t, r in sorted(per_server.items())},
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

    print(f"\n{r['transactions']} matched transaction(s) over {r['span_h']:.2f} h "
          f"-> {r['written']} sample(s) in {r['db']}")
    print(f"network {r['net_id']}  {r['label']!r}")
    for t, c in r["targets"].items():
        exc = r["exceptions"].get(t, 0)
        print(f"  {t:<24}{c:>8} transactions" + (f"   ({exc} Modbus exceptions)" if exc else ""))
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
