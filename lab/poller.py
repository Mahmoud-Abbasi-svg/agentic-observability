"""The SCADA host in miniature: poll every Modbus device once a second, forever.

    python /app/lab/poller.py 10.0.5.10 10.0.6.10        # runs inside the client container

This is the traffic the passive path watches. It is deliberately dumb - one holding-register
read per device per second, one TCP connection per device, reconnect on failure - because a
real poller is dumb too, and the point is the packets on the wire, not the poller.

A poll that gets no reply is logged and the loop carries on: the device being silent is the
event the capture must record, so the poller must keep asking. The socket timeout is shorter
than the poll interval so a dead device cannot stall the polling of a live one.
"""
from __future__ import annotations

import sys
import time

from pymodbus.client import ModbusTcpClient

INTERVAL = 1.0
TIMEOUT = 0.6


def main() -> int:
    hosts = sys.argv[1:] or ["10.0.5.10", "10.0.6.10"]
    # 5020, not 502: the device image runs unprivileged and cannot bind a port under 1024.
    # net_ingest takes --port for exactly this; the wire format is identical.
    clients = {h: ModbusTcpClient(h, port=5020, timeout=TIMEOUT) for h in hosts}
    print(f"polling {hosts} every {INTERVAL:g}s", flush=True)
    while True:
        t0 = time.time()
        for h, c in clients.items():
            try:
                if not c.connected:
                    c.connect()
                rr = c.read_holding_registers(0, count=2)     # unit 1, pymodbus' default
                if rr.isError():
                    print(f"{time.strftime('%H:%M:%S')} {h} error {rr}", flush=True)
            except Exception as exc:                 # noqa: BLE001 - keep polling regardless
                print(f"{time.strftime('%H:%M:%S')} {h} no reply ({type(exc).__name__})",
                      flush=True)
                try:
                    c.close()
                except Exception:                    # noqa: BLE001
                    pass
        time.sleep(max(0.0, INTERVAL - (time.time() - t0)))


if __name__ == "__main__":
    raise SystemExit(main())
