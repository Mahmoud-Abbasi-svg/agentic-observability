"""The collector: measures on a schedule and writes to the store. No model calls, ever.

    python net_collect.py --once           # one cycle, then exit - use this to check config
    python net_collect.py                  # run until stopped
    python net_collect.py --status         # what has been collected, per network

This is deliberately dumb. Detection and alerting live downstream; the collector's only jobs
are to measure on time, tag correctly, and never lose data. It contains no LLM call, because
an alert that fires or not depending on sampling temperature is not an alert, and because a
model call per target per cycle is unbounded spend for work arithmetic does correctly.

Two behaviours are worth knowing about:

  A heartbeat is written every cycle, successful or not, so a later reader can tell "we did
  not measure" (asleep, stopped) from "we measured and nothing answered". Without it every
  laptop lid-close looks like an outage.

  The network identity is captured before a cycle and re-checked after. If the machine moved
  networks mid-cycle the samples belong to neither, and are dropped rather than filed under
  the wrong baseline.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import net_memory
import net_store
import net_tools

CONFIG_PATH = os.environ.get(
    "NET_MONITOR_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.json"))

# kind -> (tool function, builder taking (target, resolved_host) -> complete kwargs).
# The builder receives the resolved host and produces every argument itself. An earlier
# version patched the host in afterwards with a conditional key name, which silently passed
# host= to http_check (which takes url=) and turned a TypeError into a fake outage.
KINDS = {
    "ping": (net_tools.ping,
             lambda t, h: {"host": h, "count": t.get("count", 5)}),
    "tcp": (net_tools.tcp_latency,
            lambda t, h: {"host": h, "port": t.get("port", 443),
                          "attempts": t.get("attempts", 3)}),
    "dns": (net_tools.dns_query_server,
            lambda t, h: {"server": h, "name": t.get("query", "example.com"),
                          "protocol": t.get("protocol", "udp")}),
    "http": (net_tools.http_check, lambda t, h: {"url": h}),
}

DEFAULT_CONFIG = {
    "targets": [
        {"name": "gateway", "kind": "ping", "host": "auto", "interval_s": 60},
        {"name": "cloudflare", "kind": "ping", "host": "1.1.1.1", "interval_s": 60},
        {"name": "google-dns", "kind": "ping", "host": "8.8.8.8", "interval_s": 60},
        {"name": "cloudflare-tcp", "kind": "tcp", "host": "1.1.1.1", "port": 443,
         "interval_s": 300},
        {"name": "dns-udp", "kind": "dns", "host": "1.1.1.1", "interval_s": 300},
        {"name": "example-http", "kind": "http", "host": "https://example.com",
         "interval_s": 300},
    ]
}


def load_config(path: str = CONFIG_PATH) -> dict:
    """JSON rather than the TOML in DESIGN.md: tomllib needs Python 3.11 and this runs on
    3.10. Same shape, one less dependency."""
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"[config] wrote defaults to {path}")
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    for t in cfg["targets"]:
        if t["kind"] not in KINDS:
            raise SystemExit(f"target {t['name']!r}: unknown kind {t['kind']!r}; "
                             f"expected one of {sorted(KINDS)}")
    return cfg


def resolve_host(target: dict, net: dict) -> str | None:
    """"auto" means this network's gateway, which differs per network - hardcoding one is the
    bug already sitting in net_seed.py, where this machine's 10.50.16.1 is pinned."""
    if target["host"] != "auto":
        return target["host"]
    return net.get("gateway")


def probe(target: dict, net: dict) -> tuple[str, str, dict]:
    """Run one target. Returns (name, resolved_host, metrics).

    A raised exception is a BUG OR MISCONFIGURATION, not evidence about the network, so it
    records nothing at all. Writing reachable=0 here would file a TypeError as an outage and
    poison the baseline with failures that never happened - and a baseline is expensive to
    rebuild once corrupted. Genuine unreachability comes back as a normal return whose parsed
    metrics contain reachable=0; only the tools decide that.
    """
    fn, build = KINDS[target["kind"]]
    host = resolve_host(target, net)
    if not host:
        return target["name"], "", {"_error": "host 'auto' but no gateway found"}
    try:
        out = fn(**build(target, host))
    except Exception as e:
        return target["name"], host, {"_error": f"{type(e).__name__}: {e}"[:120]}
    return target["name"], host, net_memory.extract_metrics(fn.__name__, out)


def cycle(conn, cfg: dict, due: list[dict], workers: int = 4, verbose: bool = True) -> dict:
    net = net_store.network_identity()
    if net["strength"] == "none":
        if verbose:
            print("  offline - no gateway or address; skipping cycle")
        return {"ok": 0, "failed": 0, "skipped": len(due)}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda t: probe(t, net), due))

    after = net_store.network_identity(force=True)
    if after["net_id"] != net["net_id"]:
        # Moved mid-cycle: these samples belong to neither network. Filing them under either
        # would corrupt that network's baseline, and a baseline is expensive to rebuild.
        if verbose:
            print(f"  network changed mid-cycle ({net['label']} -> {after['label']}); "
                  f"discarding {len(results)} samples")
        net_store.remember_net(conn, after)
        conn.commit()
        return {"ok": 0, "failed": 0, "skipped": len(results)}

    n_ok = n_failed = n_broken = 0
    for name, host, metrics in results:
        err = metrics.get("_error")
        real = {k: v for k, v in metrics.items() if not k.startswith("_")}
        if real:
            # Store under the RESOLVED HOST, not the config name. The agent records "1.1.1.1"
            # when it measures; if the collector filed the same measurements under
            # "cloudflare" the two would never merge, and each would build its own weaker,
            # disagreeing notion of normal for the same host.
            net_store.add_samples(conn, host, real, net["net_id"])
        if err:
            n_broken += 1                      # a broken probe, recorded nowhere
        elif real.get("reachable", 1.0):
            n_ok += 1
        else:
            n_failed += 1                      # measured, nothing answered: real signal
        if verbose:
            shown = (f"PROBE ERROR: {err}" if err
                     else ", ".join(f"{k}={v:g}" for k, v in sorted(real.items()))
                     or "(no metrics parsed)")
            print(f"  {name:<16} {host:<22} {shown}")
    if n_broken and verbose:
        print(f"  {n_broken} probe(s) errored - not recorded, fix the config or the tool")
    net_store.remember_net(conn, net)
    net_store.add_heartbeat(conn, net["net_id"], n_ok, n_failed)
    conn.commit()
    return {"ok": n_ok, "failed": n_failed, "skipped": 0}


def show_status(conn) -> None:
    net = net_store.network_identity()
    print(f"current network : {net['label']}  ({net['net_id']}, {net['strength']} identity)")
    print(f"database        : {net_store.DB_PATH}")
    for k, v in net_store.stats(conn).items():
        print(f"  {k:12} {v}")
    cov = net_store.coverage(conn, net["net_id"], hours=24)
    print(f"\nlast 24 h on this network: {cov['heartbeats']} cycles, "
          f"spanning {cov['span_h']:.1f} h")
    rows = list(conn.execute(
        "SELECT target, metric, COUNT(*), MIN(ts), MAX(ts) FROM sample WHERE net_id=? "
        "GROUP BY target, metric ORDER BY target, metric", (net["net_id"],)))
    if not rows:
        print("no samples on this network yet")
        return
    print(f"\n{'target':<18}{'metric':<20}{'n':>7}{'span_h':>9}  baseline")
    for target, metric, n, lo, hi in rows:
        span = (hi - lo) / 3600.0
        # Mirrors the rule the agent's baseline tool applies: span is the binding constraint,
        # not sample count. Fifty samples inside a minute describe that minute.
        ready = "usable" if (n >= 30 and span >= 6) else (
            "thin" if n >= 10 else "collecting")
        print(f"{target:<18}{metric:<20}{n:>7}{span:>9.1f}  {ready}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect network measurements on a schedule.")
    ap.add_argument("--once", action="store_true", help="one cycle then exit")
    ap.add_argument("--status", action="store_true", help="show what has been collected")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--config", default=CONFIG_PATH)
    args = ap.parse_args()

    conn = net_store.connect()
    if args.status:
        show_status(conn)
        return 0

    cfg = load_config(args.config)
    verbose = not args.quiet
    net = net_store.network_identity()
    print(f"collector: {len(cfg['targets'])} targets on network {net['label']} "
          f"({net['net_id']}, {net['strength']} identity)")
    if net["strength"] == "weak":
        print("  NOTE: gateway MAC unreadable - two networks sharing a gateway IP and subnet "
              "would share a baseline.")

    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))

    next_due = {t["name"]: 0.0 for t in cfg["targets"]}
    last_prune = 0.0
    while not stop["flag"]:
        now = time.time()
        due = [t for t in cfg["targets"] if now >= next_due[t["name"]]]
        if due:
            if verbose:
                print(f"\n[{time.strftime('%H:%M:%S')}] {len(due)} due")
            cycle(conn, cfg, due, verbose=verbose)
            for t in due:
                next_due[t["name"]] = now + float(t.get("interval_s", 60))
        if now - last_prune > 86400:
            res = net_store.aggregate_and_prune(conn)
            last_prune = now
            if verbose and res["raw_rows_dropped"]:
                print(f"  retention: rolled up and dropped {res['raw_rows_dropped']} raw rows")
        if args.once:
            break
        sleep_for = max(1.0, min(next_due.values()) - time.time())
        # wake often enough that Ctrl-C is responsive rather than waiting out a long interval
        for _ in range(int(sleep_for)):
            if stop["flag"]:
                break
            time.sleep(1)
    conn.commit()
    conn.close()
    print("\nstopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
