"""Seed or extend the measurement history without asking the agent anything.

    python net_seed.py            # one round over the default targets
    python net_seed.py 12 300     # 12 rounds, 300 s apart - leave it running to build a real
                                  # baseline across a working day

The agent builds history as a side effect of answering questions, but that only ever samples
whatever it happened to be asked about, in bursts. A baseline worth trusting needs samples
spread over time - which is exactly what `baseline` warns about when it reports the span
alongside the median. This is the cheap way to get one.
"""
from __future__ import annotations

import sys
import time

import net_agent          # for run_tool, which records
import net_memory

TARGETS = [
    ("ping", {"host": "1.1.1.1", "count": 5}),
    ("ping", {"host": "8.8.8.8", "count": 5}),
    ("ping", {"host": "10.50.16.1", "count": 5}),          # this machine's gateway
    ("tcp_latency", {"host": "1.1.1.1", "port": 443, "attempts": 3}),
    ("dns_query_server", {"server": "1.1.1.1", "name": "example.com"}),
    ("dns_query_server", {"server": "8.8.8.8", "name": "example.com"}),
    ("http_check", {"url": "https://example.com"}),
]


def one_round(verbose: bool = True) -> None:
    for tool, args in TARGETS:
        out = net_agent.run_tool(tool, args)
        if verbose:
            head = (out or "").splitlines()[0][:100]
            print(f"  {tool:18} {net_memory._target_of(args):<16} {head}")


def main() -> int:
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    gap = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0
    print(f"history: {net_memory.HISTORY_PATH}")
    for i in range(rounds):
        print(f"\nround {i + 1}/{rounds}  {time.strftime('%H:%M:%S')}")
        one_round()
        if i < rounds - 1:
            time.sleep(gap)
    print("\n" + net_memory.baseline())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
