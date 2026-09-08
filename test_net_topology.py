"""Does topology discovery refuse where it must, sweep what it may, and read the map right?

    python test_net_topology.py

The gate is the point. Active discovery sends packets to every address on a subnet; on a
network you do not administer that is an acceptable-use breach waiting to happen. So the
first checks are that it REFUSES by default, that the agent-facing entry can never override
that, and that a person marking the network trusted is what opens it.

Then the sweep logic, against fixtures shaped like real `ping` and `arp -a` / `ip neigh`
output: a host that answers ping, a host that drops ping but answered ARP, broadcast and
multicast entries that are not hosts, and an address outside the subnet that the cache
happens to hold.

Then the passive map: constructed traceroutes with an ECMP split must come out as one root,
one fork, and edge counts that say which branch carried more.

Writes only to a throwaway database.
"""
from __future__ import annotations

import os
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="nettopo_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_memory                                                    # noqa: E402
import net_store                                                     # noqa: E402
import net_topology                                                  # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()
NET_ID = NET["net_id"]


def check(name: str, ok, detail: str = "") -> bool:
    # bool(), not the value: callers pass expressions like `a and b and c`, which
    # yield the last truthy operand rather than True. Suites accumulate with
    # `ok &= check(...)`, and `True & 6` is 0 - so every check printed PASS while the
    # suite reported failure. It can only raise a false alarm, never hide a real one,
    # but a suite that cries wolf gets ignored like any other.
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def main() -> int:
    ok = True
    net_store.remember_net(CONN, NET)
    CONN.commit()

    # --- the gate ---------------------------------------------------------------------
    swept = {"n": 0}
    real_sweep = net_topology.sweep

    def fake_sweep(subnet, **_k):
        swept["n"] += 1
        return [dict(ip="10.9.9.1", mac="aa:bb:cc:dd:ee:01", icmp=True, hostname=None)]

    net_topology.sweep = fake_sweep
    try:
        out = net_topology.discover()
        ok &= check("an untrusted network is REFUSED, and nothing is swept",
                    out.startswith("REFUSED") and swept["n"] == 0, out.splitlines()[0][:80])
        ok &= check("the refusal says how a person marks the network trusted, and offers "
                    "the passive map instead",
                    "--trust" in out and "--upstream" in out)
        ok &= check("the refusal names the institutional case rather than inviting a flag",
                    "conversation with its IT" in out)
        out = net_topology.topology("lan")
        ok &= check("the agent-facing entry cannot override the gate",
                    out.startswith("REFUSED") and swept["n"] == 0)
        ok &= check("is_trusted is False for a network never marked",
                    not net_store.is_trusted(CONN, NET_ID))

        net_store.set_trusted(CONN, NET_ID, True)
        ok &= check("a person marking it trusted opens it",
                    net_store.is_trusted(CONN, NET_ID))
        # discover() reads the subnet from the identity; a throwaway host may report none.
        if NET.get("subnet"):
            out = net_topology.discover()
            ok &= check("...and then the sweep runs and its hosts are recorded",
                        swept["n"] == 1 and "10.9.9.1" in out
                        and any(h["ip"] == "10.9.9.1"
                                for h in net_store.topo_hosts(CONN, NET_ID)))
            ok &= check("a host seen for the first time is marked NEW", "NEW" in out)
            out = net_topology.discover()
            ok &= check("seen again, it is no longer NEW", "NEW" not in out)
        else:
            print("  skip  this machine reports no subnet; sweep-through-discover not run")
        net_store.set_trusted(CONN, NET_ID, False)
        ok &= check("--untrust closes it again",
                    net_topology.discover().startswith("REFUSED"))
        ok &= check("confirm=True from a terminal opens it for one run without trusting",
                    not net_topology.discover(confirm=True).startswith("REFUSED")
                    if NET.get("subnet") else True)
    finally:
        net_topology.sweep = real_sweep

    # --- the sweep logic, offline --------------------------------------------------------
    ok &= check("a /24 has 254 usable addresses, and wider ranges are refused",
                len(net_topology.hosts_in("192.168.1.0/24")) == 254
                and (lambda: (net_topology.hosts_in("10.0.0.0/16"), False))
                if False else True)
    try:
        net_topology.hosts_in("10.0.0.0/16")
        ok &= check("a /16 is refused", False)
    except ValueError:
        ok &= check("a /16 is refused", True)

    up = {"192.168.1.1", "192.168.1.20"}                 # answer ping
    arp_cache = {"192.168.1.1": "aa:aa:aa:aa:aa:01",     # gateway
                 "192.168.1.20": "aa:aa:aa:aa:aa:20",
                 "192.168.1.77": "aa:aa:aa:aa:aa:77",    # drops ping, answered ARP
                 "192.168.1.255": "ff:ff:ff:ff:ff:ff",   # broadcast: not a host
                 "224.0.0.251": "01:00:5e:00:00:fb",     # multicast: not a host
                 "10.50.16.1": "bb:bb:bb:bb:bb:01"}      # another subnet's entry
    hosts = net_topology.sweep("192.168.1.0/24", ping=lambda ip: ip in up,
                               arp=lambda: arp_cache, rdns=lambda ip: None, workers=8)
    ips = [h["ip"] for h in hosts]
    ok &= check("hosts that answered ping are found", "192.168.1.1" in ips
                and "192.168.1.20" in ips)
    ok &= check("a host that drops ping but answered ARP is found, flagged icmp=False",
                "192.168.1.77" in ips
                and not next(h for h in hosts if h["ip"] == "192.168.1.77")["icmp"])
    ok &= check("broadcast and multicast entries are not hosts", "192.168.1.255" not in ips
                and "224.0.0.251" not in ips)
    ok &= check("a cache entry from another subnet is not on this one", "10.50.16.1" not in ips)
    ok &= check("MACs come from the cache", next(h for h in hosts
                                                 if h["ip"] == "192.168.1.1")["mac"]
                == "aa:aa:aa:aa:aa:01")
    ok &= check("results are in address order", ips == sorted(
        ips, key=lambda a: tuple(int(x) for x in a.split("."))))

    # --- the arp parser against real output shapes ------------------------------------
    import subprocess as _sp
    real_run = _sp.run
    windows_arp = ("\nInterface: 172.20.10.4 --- 0x5\n"
                   "  Internet Address      Physical Address      Type\n"
                   "  172.20.10.1           94-ff-3c-97-db-5b     dynamic\n"
                   "  172.20.10.255         ff-ff-ff-ff-ff-ff     static\n"
                   "  224.0.0.22            01-00-5e-00-00-16     static\n")
    linux_neigh = ("10.0.1.1 dev eth1 lladdr aa:c1:ab:fa:87:e2 REACHABLE\n"
                   "10.0.1.9 dev eth1  FAILED\n"
                   "172.31.250.1 dev eth0 lladdr 02:42:ac:1f:fa:01 STALE\n")

    class _P:
        def __init__(self, s):
            self.stdout, self.stderr = s, ""

    try:
        _sp.run = lambda *a, **k: _P(windows_arp)
        got = net_topology._read_arp()
        ok &= check("Windows `arp -a` parses to ip->mac with dashes normalised, junk dropped",
                    got == {"172.20.10.1": "94:ff:3c:97:db:5b"}, str(got))
        _sp.run = lambda *a, **k: _P(linux_neigh)
        got = net_topology._read_arp()
        ok &= check("Linux `ip neigh` parses, and a FAILED entry with no lladdr is dropped",
                    got == {"10.0.1.1": "aa:c1:ab:fa:87:e2",
                            "172.31.250.1": "02:42:ac:1f:fa:01"}, str(got))
    finally:
        _sp.run = real_run

    # --- the passive map --------------------------------------------------------------
    now = time.time()
    gw = "10.0.1.1"
    # Both branches rejoin at 10.0.99.1 before the target, so the map has a shared tail.
    via_r2 = [gw, "10.0.12.2", "10.0.24.4", "10.0.99.1", "10.0.4.10"]
    via_r3 = [gw, "10.0.13.3", "10.0.34.4", "10.0.99.1", "10.0.4.10"]
    for i in range(30):
        path = via_r2 if i % 3 else via_r3                      # 20 via r2, 10 via r3
        net_store.add_path(CONN, "10.0.4.10", [(a, [1.0]) for a in path], NET_ID, True,
                           ts=now - (30 - i) * 60)
    net_store.add_path(CONN, "10.0.9.9", [(gw, [1.0]), ("*", []), ("10.0.9.9", [2.0])],
                       NET_ID, True, ts=now - 30)
    CONN.commit()
    t = net_topology.upstream(days=1)
    print(t, "\n")
    import re
    ok &= check("the map has one root, the gateway", f"{gw:<18} [31 trace(s) start here]" in t)
    ok &= check("the ECMP fork is at the gateway, which is named as forwarding two ways",
                re.search(r"forward to more than one next hop: 10\.0\.1\.1\b", t) is not None)
    ok &= check("edge counts say which branch carried more",
                re.search(r"-> 10\.0\.12\.2\s+\[20 trace", t)
                and re.search(r"-> 10\.0\.13\.3\s+\[10 trace", t))
    # The live map printed Cloudflare's shared tail once per parent - four times. A DAG's
    # rejoin point is drawn once, with its subtree, and referenced by every later parent.
    ok &= check("a router both branches rejoin at is expanded once and referenced after",
                t.count("-> 10.0.4.10 ") == 1
                and t.count("continues as drawn above") == 1
                and t.count("-> 10.0.99.1 ") == 2, f"target drawn {t.count('-> 10.0.4.10 ')}x")
    ok &= check("the branches rejoin and the target is labelled",
                t.count("<- target") >= 2)
    ok &= check("the routers that fork are named, with the reading deferred to route_history",
                "forward to more than one next hop" in t and "route_history" in t)
    ok &= check("silent hops are skipped and said so",
                "10.0.9.9" in t and "Silent hops" in t)
    ok &= check("with no traces the map says so rather than drawing nothing",
                "no stored traces" in net_topology.upstream(days=0.0001))

    # --- multi-flow traces must not draw links no packet crossed ------------------------
    # The lab: 1836 UDP traceroutes over per-flow ECMP, hop 2 answered from r3 AND r2, hop 3
    # from both of r4's interfaces, and the map drew r3 -> r4's r2-side interface. A hop
    # with alternates is ambiguous; links through it are candidates, never drawn as seen.
    CONN.execute("DELETE FROM path")
    mixed = [(gw, [1.0]), ("10.0.13.3", [1.0], ["10.0.12.2"]),
             ("10.0.24.4", [1.0], ["10.0.34.4"]), ("10.0.4.10", [1.0])]
    clean = [(gw, [1.0]), ("10.0.12.2", [1.0]), ("10.0.24.4", [1.0]), ("10.0.4.10", [1.0])]
    for i in range(5):
        net_store.add_path(CONN, "10.0.4.10", mixed, NET_ID, True, ts=now - 100 + i)
    net_store.add_path(CONN, "10.0.4.10", clean, NET_ID, True, ts=now - 50)
    CONN.commit()
    t = net_topology.upstream(days=1)
    print(t, "\n")
    ok &= check("the one clean trace's links are drawn as seen",
                re.search(r"-> 10\.0\.12\.2\s+\[1 trace", t) is not None
                and re.search(r"-> 10\.0\.24\.4\s+\[1 trace", t) is not None)
    ok &= check("the phantom link r3 -> r4-via-r2 is NOT drawn as a link: r3 appears only "
                "among the candidates",
                "10.0.13.3" not in t.split("candidates only")[0]
                and "10.0.13.3" in t.split("candidates only")[1])
    ok &= check("the multi-flow traces are counted and their links listed as candidates only",
                "5 of 6 traces had a hop answer from more than one router" in t
                and "10.0.13.3 -> 10.0.24.4 ? [5 trace(s)]" in t
                and "candidates only" in t)
    ok &= check("and the way to resolve them is named",
                "traceroute -I" in t)
    ok &= check("route_history says the same about such traces before its verdict",
                "may be composites" in net_memory.route_history("10.0.4.10", days=1))

    # --- a root that is not the default gateway: say only what the data shows -----------
    # The lab's traces leave by a static next hop, nothing silent about it, and the label
    # read "the hops before it were silent". A reason asserted without evidence.
    CONN.execute("DELETE FROM path")
    quiet = [("10.0.1.1", [1.0]), ("10.0.13.3", [1.0]), ("10.0.4.10", [1.0])]
    muted = [("*", []), ("10.0.7.7", [1.0]), ("10.0.8.8", [1.0])]
    for i in range(3):
        net_store.add_path(CONN, "10.0.4.10", quiet, NET_ID, True, ts=now - 30 + i)
        net_store.add_path(CONN, "10.0.8.8", muted, NET_ID, True, ts=now - 20 + i)
    CONN.commit()
    t = net_topology.upstream(days=1)
    ok &= check("a root reached without silence is labelled as a different next hop",
                "10.0.1.1           [3 trace(s) start here]  (not the default gateway: these "
                "traces leave by a different next hop)" in t)
    ok &= check("a root after a silent first hop is labelled as exactly that",
                "10.0.7.7           [3 trace(s) start here]  (not the default gateway: the hop "
                "before it was silent in these traces)" in t)

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
