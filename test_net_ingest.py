"""Does the pcap ingester produce the series the capture actually contains?

    python test_net_ingest.py

A capture is built here with response times chosen in advance, so the right answer is known
exactly. That is the only part of this pipeline where a synthetic signal is legitimate: it
tests the PARSER, which has a correct answer. It would not be legitimate for the statistics -
a noise floor measured on noise you generated is a measurement of your own generator, which is
the whole reason for using real captures rather than a simulator.

The failures worth guarding against:

  wrong pairing        transaction ids are 16 bits and wrap; pairing a reply with a stale
                       request invents a response time of however long the wrap took
  identity bleed       a factory capture written under this laptop's net_id would contaminate
                       the baselines for the live network, which is what net_id exists to stop
  invisible data       every analysis function asks for the last N days against the current
                       clock, so an unshifted 2016 capture is silently empty

Writes only to a throwaway directory.
"""
from __future__ import annotations

import os
import struct
import tempfile
import time

WORK = tempfile.mkdtemp(prefix="netingest_")
DB = os.path.join(WORK, "ics.db")
PCAP = os.path.join(WORK, "modbus.pcap")
os.environ["NET_MONITOR_DB"] = os.path.join(WORK, "live.db")   # never the real one

import net_ingest                                                    # noqa: E402
import net_store                                                     # noqa: E402

CLIENT, SERVER = "10.0.0.5", "10.0.0.90"
BASE = 1462000000.0            # a 2016 capture, like the real ones


def adu(trans: int, unit: int, func: int) -> bytes:
    return struct.pack(">HHHB", trans, 0, 3, unit) + bytes([func, 0x02, 0x00, 0x01])


def build(pairs: list[tuple[int, float, float]], extra: list = None) -> None:
    """pairs = (transaction id, request time offset, response delay in seconds)."""
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
    pkts = []
    for trans, at, delay in pairs:
        q = (Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=40000, dport=502)
             / Raw(adu(trans, 1, 3)))
        q.time = BASE + at
        r = (Ether() / IP(src=SERVER, dst=CLIENT) / TCP(sport=502, dport=40000)
             / Raw(adu(trans, 1, 3)))
        r.time = BASE + at + delay
        pkts += [q, r]
    pkts += (extra or [])
    wrpcap(PCAP, pkts)


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def main() -> int:
    from scapy.all import Ether, IP, TCP, Raw, UDP

    # 40 polls at 1 s, response times stepping 10.0 .. 10.39 ms - values chosen so that a
    # wrong pairing or a lost pair changes the median visibly.
    pairs = [(i + 1, float(i), 0.0100 + i * 0.00001) for i in range(40)]

    # Traffic that must be ignored: a non-Modbus TCP stream, a UDP packet, a too-short
    # payload, and a response whose request was never captured (a mid-stream start).
    noise = []
    p = Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=1234, dport=80) / Raw(b"GET / HTTP")
    p.time = BASE + 1
    noise.append(p)
    p = Ether() / IP(src=CLIENT, dst=SERVER) / UDP(sport=1, dport=502) / Raw(adu(9, 1, 3))
    p.time = BASE + 2
    noise.append(p)
    p = Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=40000, dport=502) / Raw(b"\x00\x01")
    p.time = BASE + 3
    noise.append(p)
    p = Ether() / IP(src=SERVER, dst=CLIENT) / TCP(sport=502, dport=40000) / Raw(adu(999, 1, 3))
    p.time = BASE + 4
    noise.append(p)

    build(pairs, noise)
    r = net_ingest.ingest(PCAP, DB, label="unit test")

    ok = True
    ok &= check("every request/response pair is matched, and nothing else is",
                r["transactions"] == 40, f"{r['transactions']} transaction(s), expected 40")

    conn = net_store.connect(DB)
    rows = list(conn.execute(
        "SELECT ts, value FROM sample WHERE metric='response_ms' ORDER BY ts"))
    vals = [v for _ts, v in rows]
    ok &= check("one sample per transaction", len(vals) == 40, f"{len(vals)}")

    want = [round((0.0100 + i * 0.00001) * 1000, 3) for i in range(40)]
    got = [round(v, 3) for v in vals]
    ok &= check("response times match the capture exactly",
                got == want, f"first three {got[:3]} vs {want[:3]}")

    ok &= check("the server is the target, with its unit id",
                list(r["targets"]) == [f"{SERVER}:1"], f"{list(r['targets'])}")

    # Identity must be the capture's, never this machine's.
    live = net_store.network_identity()
    ok &= check("the capture gets its own net_id, not the live one",
                r["net_id"] != live["net_id"], f"capture {r['net_id']}, live {live['net_id']}")
    # The DEFAULT label must say replay and carry the capture date, so a shifted series is
    # never mistaken for live measurement. (r above was given an explicit label, so the
    # default is checked on its own ingest.)
    auto = net_ingest.ingest(PCAP, os.path.join(WORK, "auto.db"))
    ok &= check("the default label records that this is a replay, and the capture date",
                "replay" in auto["label"].lower() and "2016" in auto["label"], auto["label"])

    # Re-ingesting the same file must land in the same network rather than making a new one.
    r2 = net_ingest.ingest(PCAP, DB, label="unit test")
    ok &= check("re-ingesting the same capture reuses its network",
                r2["net_id"] == r["net_id"])

    # Shifted timestamps are what make the data visible to every analysis function.
    newest = max(ts for ts, _v in rows)
    ok &= check("timestamps are shifted so the capture ends about now",
                abs(newest - time.time()) < 120,
                f"newest sample is {(time.time() - newest):.0f}s old")
    span = max(ts for ts, _v in rows) - min(ts for ts, _v in rows)
    ok &= check("shifting preserves the intervals", abs(span - 39) <= 1, f"span {span}s")

    # And the analysis layer must actually see them through the replay identity.
    os.environ["NET_MONITOR_DB"] = DB
    os.environ["NET_REPLAY_ID"] = r["net_id"]
    net_store._CACHE.update(at=0.0, info=None)
    ident = net_store.network_identity()
    ok &= check("NET_REPLAY_ID makes the tools adopt the capture's identity",
                ident["net_id"] == r["net_id"] and ident["strength"] == "replay",
                f"{ident['net_id']} / {ident['strength']}")

    # --no-shift must be honest about what it costs, not silently produce an empty analysis.
    r3 = net_ingest.ingest(PCAP, os.path.join(WORK, "unshifted.db"), shift=False)
    c3 = net_store.connect(os.path.join(WORK, "unshifted.db"))
    oldest = list(c3.execute("SELECT MIN(ts) FROM sample"))[0][0]
    ok &= check("--no-shift keeps the original capture times",
                abs(oldest - BASE) < 120, f"{oldest} vs {BASE}")

    # --- sub-second polling must survive the store ------------------------------------------
    # The primary key is (target, metric, ts). While ts was truncated to whole seconds, every
    # measurement taken inside the same second overwrote the one before it - silently, since
    # INSERT OR REPLACE reports success either way. Found on the first real capture: six RTUs
    # polled in bursts of three transactions within one second, every ten seconds, arrived in
    # the table with exactly two thirds missing, and a noise floor was computed on what was
    # left with nothing indicating anything had gone.
    burst = []
    for cycle in range(30):                       # 3 transactions ~10 ms apart, every 10 s
        for k in range(3):
            burst.append((cycle * 3 + k + 1, cycle * 10.0 + k * 0.010, 0.0008 + k * 0.0001))
    build(burst)
    rb = net_ingest.ingest(PCAP, os.path.join(WORK, "burst.db"))
    cb = net_store.connect(os.path.join(WORK, "burst.db"))
    n_stored = list(cb.execute("SELECT COUNT(*) FROM sample WHERE metric='response_ms'"))[0][0]
    ok &= check("three polls inside one second are three samples, not one",
                n_stored == 90, f"{n_stored} stored of 90 transactions")
    ok &= check("the ingester reports what was STORED, not what it handed over",
                rb["written"] == n_stored and rb["lost"] == 0,
                f"written={rb['written']}, lost={rb['lost']}")

    ts = [r[0] for r in cb.execute(
        "SELECT ts FROM sample WHERE metric='response_ms' ORDER BY ts")]
    ok &= check("sub-second spacing is preserved in the store",
                any(0 < (b - a) < 0.5 for a, b in zip(ts, ts[1:])),
                f"smallest gap {min(b - a for a, b in zip(ts, ts[1:])):.4f}s")

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
