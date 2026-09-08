"""Topology: what is on this network, and the path off it.

    python net_topology.py                # both halves; the LAN half only if this net is trusted
    python net_topology.py --upstream     # the router-level map beyond the gateway (passive)
    python net_topology.py --lan          # the hosts on this subnet (ACTIVE - see below)
    python net_topology.py --trust        # mark the CURRENT network as yours to scan
    python net_topology.py --untrust      # take that back

Two halves, and only the first sends packets to addresses nobody named. That is the line the
rest of this project never crosses, so it is fenced.

  LAN (active)   Sweep the /24 this machine sits on, read the ARP cache, list what answered.
                 Manual only - never in the collector. Scoped to the local subnet only: never
                 a range you type, never the internet. And GATED PER NETWORK: it refuses on
                 any network you have not marked trusted. Scanning a network you do not
                 administer - a campus wifi, a hotel, a cafe - can breach its acceptable-use
                 policy and light up its intrusion detection. Your own hotspot or home LAN is
                 yours to scan. A university's network is a conversation with its IT, and no
                 flag here stands in for that.

  UPSTREAM (passive)  Stitch the traceroute paths route_history already stores into the
                 router-level graph beyond the gateway. Not one new packet. Works anywhere.

What discovery can and cannot tell you, stated so the output is not over-read:

  * A host that answers ICMP or ARP is there. A host that answers neither may still be there:
    a firewall that drops both is invisible to this, and a scan is a lower bound on the
    network, never an inventory.
  * Hotspots isolate their clients from each other. Finding only the gateway and this machine
    on one is the hotspot working as designed, not a failed scan.
  * A MAC identifies a network card, not a person or a role. Nothing here guesses at what a
    host IS from its address.
"""
from __future__ import annotations

import argparse
import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

import net_memory
import net_store

IS_WINDOWS = platform.system().lower().startswith("win")
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}

SWEEP_WORKERS = 64
PING_TIMEOUT_MS = 700
_MAC_RE = re.compile(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.I)
_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


# --------------------------------------------------------------------------- primitives

def _own_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("1.1.1.1", 80))          # no packet is sent; selects the routing interface
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _ping_one(ip: str) -> bool:
    """One echo request, short timeout. True only on a reply line carrying TTL= - the return
    code alone is not enough on Windows, which exits 0 for 'Destination host unreachable'."""
    cmd = (["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip] if IS_WINDOWS
           else ["ping", "-c", "1", "-W", "1", ip])
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=4, encoding="utf-8",
                           errors="replace", **_NO_WINDOW)
    except Exception:
        return False
    return bool(re.search(r"ttl\s*=", (p.stdout or "") + (p.stderr or ""), re.I))


def _read_arp() -> dict[str, str]:
    """ip -> mac from the neighbour cache. Broadcast, multicast and incomplete entries are
    not hosts and are dropped."""
    cmd = ["arp", "-a"] if IS_WINDOWS else ["ip", "neigh"]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=8, encoding="utf-8",
                           errors="replace", **_NO_WINDOW)
        out = (p.stdout or "")
    except Exception:
        return {}
    found: dict[str, str] = {}
    for line in out.splitlines():
        ipm = _IP_RE.search(line)
        macm = _MAC_RE.search(line)
        if not (ipm and macm):
            continue
        mac = macm.group(0).lower().replace("-", ":")
        if mac.startswith(("ff:ff:ff", "01:00:5e", "33:33")) or mac == "00:00:00:00:00:00":
            continue
        found[ipm.group(1)] = mac
    return found


def _rdns(ip: str) -> Optional[str]:
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def hosts_in(subnet: str) -> list[str]:
    """The usable addresses of a /24 (or smaller). Anything wider is refused - a sweep is
    scoped to the subnet this machine is on, never a range."""
    net = ipaddress.ip_network(subnet, strict=False)
    if net.prefixlen < 24:
        raise ValueError(f"refusing to sweep {subnet}: wider than a /24")
    return [str(h) for h in net.hosts()]


def sweep(subnet: str, ping: Callable[[str], bool] = _ping_one,
          arp: Callable[[], dict[str, str]] = _read_arp,
          rdns: Callable[[str], Optional[str]] = _rdns,
          workers: int = SWEEP_WORKERS) -> list[dict]:
    """Probe every address in the subnet, then read the neighbour cache.

    Two signals, unioned. ICMP finds hosts that answer ping. The ARP cache finds hosts that
    answered the *address resolution* the ping forced, whether or not they answered the ping -
    a host that drops ICMP still has to answer ARP to exist on the segment, so it shows up
    here with a MAC and icmp=False. The ping's job is as much to populate that cache as to
    get a reply.

    Injectable, so the logic is tested offline against fixtures rather than the office LAN.
    """
    addrs = hosts_in(subnet)
    net = ipaddress.ip_network(subnet, strict=False)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        replied = dict(zip(addrs, ex.map(ping, addrs)))
    # The junk filter is applied HERE, to whatever the cache reader returns, not only inside
    # _read_arp: the broadcast address is inside the subnet and would otherwise be listed
    # as a host with a MAC of ff:ff:ff:ff:ff:ff.
    cache = {ip: mac for ip, mac in arp().items()
             if ipaddress.ip_address(ip) in net
             and ipaddress.ip_address(ip) != net.broadcast_address
             and not mac.lower().startswith(("ff:ff:ff", "01:00:5e", "33:33"))
             and mac != "00:00:00:00:00:00"}
    seen = sorted(set(a for a, ok in replied.items() if ok) | set(cache),
                  key=lambda a: ipaddress.ip_address(a))
    return [dict(ip=ip, mac=cache.get(ip), icmp=bool(replied.get(ip)), hostname=rdns(ip))
            for ip in seen]


# --------------------------------------------------------------------------- LAN (active)

def _refusal(net: dict) -> str:
    return (f"REFUSED: active discovery on network {net['label']!r} ({net['net_id']}), which "
            f"is not marked as yours to scan.\n"
            f"A sweep sends packets to every address on the subnet. On a network you do not "
            f"administer that can breach its acceptable-use policy and trip its intrusion "
            f"detection - a campus or institutional network is a conversation with its IT "
            f"department, not a flag to set here.\n"
            f"If this network IS yours (your own hotspot, your home LAN), mark it once:\n"
            f"    python net_topology.py --trust\n"
            f"The passive upstream map needs no trust and works here now: "
            f"python net_topology.py --upstream")


def discover(confirm: bool = False) -> str:
    """Active discovery of the local subnet. Refuses unless the network is trusted, or the
    caller - a person at a terminal, never the agent - passes confirm=True for this one run."""
    net = net_store.network_identity()
    if net["strength"] == "none":
        return "No network: no gateway or address to sweep from."
    c = net_memory.conn()
    net_store.remember_net(c, net)
    c.commit()
    if not confirm and not net_store.is_trusted(c, net["net_id"]):
        return _refusal(net)
    subnet = net.get("subnet")
    if not subnet:
        return f"Network {net['label']!r} has no readable subnet to sweep."

    t0 = time.perf_counter()
    found = sweep(subnet)
    took = time.perf_counter() - t0
    me, gw = _own_ip(), net.get("gateway")
    before = {h["ip"]: h for h in net_store.topo_hosts(c, net["net_id"])}
    net_store.add_topo_hosts(c, net["net_id"], found)

    out = [f"LAN discovery on network {net['label']!r}, subnet {subnet}: {len(found)} host(s) "
           f"answered of {len(hosts_in(subnet))} probed, in {took:.1f} s",
           f"  {'ip':<16}{'mac':<19}{'icmp':<6}note"]
    for h in found:
        note = []
        if h["ip"] == gw:
            note.append("gateway")
        if h["ip"] == me:
            note.append("this machine")
        if h["hostname"]:
            note.append(h["hostname"])
        if h["ip"] not in before:
            note.append("NEW - not seen on this network before")
        out.append(f"  {h['ip']:<16}{(h['mac'] or '-'):<19}{('yes' if h['icmp'] else 'arp'):<6}"
                   + ", ".join(note))
    gone = [ip for ip in before if ip not in {h['ip'] for h in found}]
    if gone:
        when = max(before[ip]["last_seen"] for ip in gone)
        out.append(f"  {len(gone)} host(s) seen on this network before did not answer this "
                   f"time (last seen {time.strftime('%d %b %H:%M', time.localtime(when))}): "
                   + ", ".join(sorted(gone)[:8]) + (" ..." if len(gone) > 8 else ""))
    out.append("  'arp' = did not answer ping but answered address resolution: present, and "
               "dropping ICMP. A host answering neither is invisible to this - a sweep is a "
               "lower bound on the network, not an inventory.")
    if len(found) <= 2 and (net.get("ssid") or "").lower().find("iphone") >= 0:
        out.append("  A phone hotspot isolates its clients from each other, so gateway plus "
                   "this machine is the hotspot working as designed, not a scan that failed.")
    return "\n".join(out)


# --------------------------------------------------------------------------- upstream (passive)

def upstream(days: float = 7.0) -> str:
    """The router-level graph beyond the gateway, stitched from stored traceroutes.

    Every trace to every target shares its first hops, so the union of stored paths is a
    partial map of the upstream network - built from measurements already taken, with no new
    packets. Edges carry how many traces crossed them, which is the only weight this data
    can honestly give: a hop seen in 200 traces is on the usual route, one seen in 3 was a
    transient or a load-balanced alternate.
    """
    import json as _json
    net = net_store.network_identity()
    c = net_memory.conn()
    cutoff = time.time() - days * 86400
    rows = list(c.execute("SELECT target, hops FROM path WHERE net_id=? AND ts>=?",
                          (net["net_id"], cutoff)))
    head = f"upstream topology on network {net['label']!r}, last {days:g} d"
    if not rows:
        return (f"{head}: no stored traces. Run traceroute to a few hosts, or let the "
                f"collector's trace targets accumulate, and the map builds itself.")
    edges: dict[tuple[str, str], int] = {}
    ambiguous: dict[tuple[str, str], int] = {}
    roots: dict[str, int] = {}
    silent_first: dict[str, int] = {}       # root -> traces whose earlier hops were silent
    n_multiflow = 0
    for target, hs in rows:
        # Each hop: (addr, rtts, alternates). A hop with alternates answered from more than
        # one router - per-flow load balancing splitting the probes - and a link drawn
        # through it would join two hops that different packets took. Only a pair of
        # single-answer hops is a link this data has actually seen one packet cross.
        raw = _json.loads(hs)
        hops = [(h[0], h[2] if len(h) > 2 else []) for h in raw if h[0] != "*"]
        if not hops:
            continue
        if any(alts for _a, alts in hops):
            n_multiflow += 1
        roots[hops[0][0]] = roots.get(hops[0][0], 0) + 1
        if raw and raw[0][0] == "*":
            silent_first[hops[0][0]] = silent_first.get(hops[0][0], 0) + 1
        for (a, a_alts), (b, b_alts) in zip(hops, hops[1:]):
            if a_alts or b_alts:
                for x in [a] + a_alts:
                    for y in [b] + b_alts:
                        ambiguous[(x, y)] = ambiguous.get((x, y), 0) + 1
            else:
                edges[(a, b)] = edges.get((a, b), 0) + 1
    children: dict[str, list[tuple[str, int]]] = {}
    for (a, b), n in edges.items():
        children.setdefault(a, []).append((b, n))
    for a in children:
        children[a].sort(key=lambda x: -x[1])
    nodes = {a for a, _ in edges} | {b for _, b in edges}
    tgts = {t for t, _ in rows}
    out = [f"{head}: {len(rows)} traces to {len(tgts)} target(s), "
           f"{len(nodes)} router(s) seen, {len(edges)} link(s)"
           + (f", {len(ambiguous)} ambiguous" if ambiguous else "")]

    # A DAG, not a tree: branches that split rejoin, and the first rendering expanded the
    # shared tail under every parent - the live map printed Cloudflare's last four hops four
    # times. A router already drawn is referenced, not redrawn.
    drawn: set[str] = set()

    def walk(node: str, depth: int) -> None:
        for child, n in children.get(node, []):
            tag = ""
            if child in tgts:
                tag = "  <- target"
            elif len(children.get(child, [])) > 1:
                tag = f"  (splits {len(children[child])} ways)"
            if child in drawn and children.get(child):
                tag += "  (continues as drawn above)"
            out.append(f"  {'   ' * depth}-> {child:<18} [{n} trace(s)]{tag}")
            if child in drawn or depth > 12:
                continue
            drawn.add(child)
            walk(child, depth + 1)

    gw = net.get("gateway")
    for root, n in sorted(roots.items(), key=lambda x: (x[0] != gw, -x[1])):
        if root == gw:
            tag = "  <- gateway"
        elif root in tgts and not children.get(root):
            tag = "  <- target, traced directly (on this subnet)"
        elif silent_first.get(root, 0) >= n:
            # A trace whose first hops did not answer starts, in this data, at its first
            # hop that did. That is where the record begins, not where the path does.
            tag = "  (not the default gateway: the hop before it was silent in these traces)"
        else:
            # Only what the data shows. The first version said "the hops before it were
            # silent" here too, for a lab route that leaves by a static next hop - nothing
            # was silent; a reason was asserted without evidence.
            tag = "  (not the default gateway: these traces leave by a different next hop)"
        out.append(f"  {root:<18} [{n} trace(s) start here]{tag}")
        drawn.add(root)
        walk(root, 1)
    branch = [a for a, ch in children.items() if len(ch) > 1]
    if branch:
        out.append(f"  {len(branch)} router(s) forward to more than one next hop: "
                   f"{', '.join(branch[:5])}. That is either load balancing or a route that "
                   f"changed in the window - route_history on a target tells which.")
    if ambiguous:
        out.append(f"  {n_multiflow} of {len(rows)} traces had a hop answer from more than one "
                   f"router - per-flow load balancing splitting the probes. Links through "
                   f"such a hop are NOT drawn above, because they would join two hops that "
                   f"different packets took. What those traces can say, as candidates only:")
        for (a, b), n in sorted(ambiguous.items(), key=lambda kv: -kv[1])[:12]:
            out.append(f"     {a} -> {b} ? [{n} trace(s)]")
        if len(ambiguous) > 12:
            out.append(f"     ... and {len(ambiguous) - 12} more")
        out.append("     To resolve them, trace with a single flow (ICMP on Linux: "
                   "traceroute -I) so every hop is answered by the same path.")
    out.append("  Silent hops ('*' in the traces) are skipped: a router that does not answer "
               "probes is on the path but not in this map.")
    return "\n".join(out)


# --------------------------------------------------------------------------- agent-facing

def topology(scope: str = "upstream", days: float = 7.0) -> str:
    """The shape of the network around this machine.

    scope="upstream" (default) - the routers beyond the gateway, stitched from stored
    traceroutes. Passive: reads history, sends nothing, works on any network.

    scope="lan" - the hosts on this machine's own subnet, by sweeping it. ACTIVE: it sends a
    probe to every address, and it refuses on any network the operator has not marked as
    theirs to scan. That mark is set by a person at the terminal, never from here. If it
    refuses, report the refusal and its reason; do not try to get around it.

    Args:
        scope: "upstream" or "lan".
        days: for upstream, how far back to read stored traces.
    """
    if scope.strip().lower() == "lan":
        return discover(confirm=False)          # the agent never gets to confirm
    return upstream(days)


# --------------------------------------------------------------------------- CLI

def main() -> int:
    ap = argparse.ArgumentParser(description="Topology: hosts on this subnet (active, gated) "
                                             "and the routers beyond it (passive).")
    ap.add_argument("--lan", action="store_true", help="sweep the local subnet (active)")
    ap.add_argument("--upstream", action="store_true", help="the router map from stored traces")
    ap.add_argument("--confirm", action="store_true",
                    help="sweep this once even though the network is not marked trusted")
    ap.add_argument("--trust", action="store_true", help="mark the CURRENT network as yours")
    ap.add_argument("--untrust", action="store_true", help="remove that mark")
    ap.add_argument("--days", type=float, default=7.0)
    args = ap.parse_args()

    if args.trust or args.untrust:
        net = net_store.network_identity()
        c = net_memory.conn()
        net_store.remember_net(c, net)
        net_store.set_trusted(c, net["net_id"], args.trust)
        print(f"network {net['label']!r} ({net['net_id']}) is now "
              f"{'TRUSTED: active discovery allowed here' if args.trust else 'untrusted'}")
        return 0
    both = not (args.lan or args.upstream)
    if args.upstream or both:
        print(upstream(args.days))
    if args.lan or both:
        if both:
            print()
        print(discover(confirm=args.confirm))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
