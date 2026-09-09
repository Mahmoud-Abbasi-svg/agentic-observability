# The lab — testing the tools against a network with known answers

Every other test in this repo builds a *history* by hand and checks the tools read it right.
This builds a *network* whose answers are known, runs the real collector inside it, and checks
the tools against ground truth. It is the first thing that can falsify `route_history` and
`availability` on traffic they did not stage themselves.

```
                +-- r2 --+           +-- server   (HTTP)
  client -- r1 -+        +- r4 -----+-- plc1     (Modbus/TCP)
                +-- r3 --+           +-- plc2     (Modbus/TCP)
```

Eight [containerlab](https://containerlab.dev/) nodes: four FRR routers running OSPF with two
equal-cost paths from `r1` to the far segment, a `client` that runs the collector, a `server`
serving HTTP, and two Modbus/TCP devices each on its own link off `r4` so one can be cut
without the other. Nothing here touches the host's real network — it is a private Docker bridge.

The client also runs the **passive path**: a SCADA host in miniature (`poller.py`) reads two
holding registers from each device once a second, `tcpdump` on the client's LAN interface
records the exchange, and `net_ingest` reads the capture back. The monitor never sends a
Modbus packet of its own. The devices listen on 5020 because the image runs unprivileged;
the wire format is the same and the ingester takes `--port`.

## Requirements

WSL2 with a Linux distro, Docker Engine **inside** that distro (not Docker Desktop's Windows
engine), and containerlab. On this machine the one-time setup was:

```bash
# as root inside the WSL distro
apt-get install -y docker.io iproute2
curl -sL https://get.containerlab.dev | bash
printf '[boot]\nsystemd=true\n' > /etc/wsl.conf   # then: wsl --terminate <distro>
```

**Quit Docker Desktop before running the scenarios.** If the Docker daemon restarts, every
containerlab veth pair is destroyed while the containers keep running, so each node is left
with only `eth0`, every host looks down — the gateway included — and the capture file is never
written. On 2026-09-09 Docker Desktop cycled this distro's daemon every 30–60 s (it integrates
with the *default* WSL distro, which is this one) and a full `ics` run graded fourteen
expectations against a dead network; `docker desktop stop` on the Windows side left the daemon
stable for the whole run. Nothing about that was visible in the output, which is why
`bash lab.sh guard` exists and why every grading point now calls it: a run that cannot
establish ground truth prints `VOID` and exits 2 instead of PASS/FAIL lines that look like
findings.

## Running it

All commands run as root inside the WSL distro. From the repo's `lab/` directory:

```bash
bash lab.sh build       # build the client image (collector + ping/traceroute/dig)
bash lab.sh up          # deploy the topology, start the collector in the client
bash lab.sh status      # containers, r1's route to the server, latest collector output
bash lab.sh check route # what route_history says right now
bash lab.sh check ics   # ingest the Modbus capture and judge the passive path from it alone
bash lab.sh passive     # (re)start the poller and the capture in the client
bash lab.sh scenarios   # run S1-S6 against their pre-registered expectations
bash lab.sh ics         # only S5 and S6, the passive-path scenarios (~16 min)
bash lab.sh guard       # can the lab still establish ground truth at all?
bash lab.sh down        # destroy everything
```

## The scenarios, and what each proves

Each sets the world to a known state, waits for the collector to trace it, asks the tool, and
grades the answer against an expectation written **before** the tool ran. The mutations use
link state and `tc netem`, driven through each node's own namespace, so no container needs
extra privilege and every change is reversible.

| # | ground truth set up | what the tool must say |
|---|---|---|
| **S1** | two equal-cost paths, per-flow hashing on | every stored path is ONE real branch, never a composite of both; no phantom link in the map |
| **S2** | one path removed (link down), then the other | `STABLE`, then `CHANGED` once, diverging at the exact hop that moved |
| **S3** | 40 ms of netem on the r3→r4 link | route `STABLE`; the per-hop rise placed at hop 3, every later hop sharing it |
| **S4** | the server's link down for ~70 s | a `DOWN` run on the server; the gateway `never observed down`; **not** a network-wide outage |
| **S5** | one device hung for 6 min (`docker pause plc2`: the kernel still completes TCP handshakes, so every poll is a real Modbus request that gets no reply) | **from the capture alone:** plc2 has a `DOWN` run of 400+ consecutive unanswered polls, plc1 `never down`, not all-down; asked *during* the hang, rule 6 pages plc2 and only plc2, and stops after recovery. The pinger reports plc2 `never down` throughout |
| **S6** | both device links down for 6 min | **from the capture alone:** both devices unanswered at the cut, a *short* `DOWN` run, then six minutes worded as silence on the wire; the two devices down together while both were polled. The pinger sees the full 6.4 min on both, the gateway `never down`, and correctly **not** a network outage |

### The passive path: what the two scenarios established

Both were pre-registered before the poller existed, and the first run failed five of eleven
claims. Two of those failures are the result; three were mine, and the S5/S6 comments in
`lab.sh` keep the original claim beside what replaced it, as S1 does. Re-registered and run
again on an intact lab: **16 of 16**, with the first run's numbers — 408 unanswered polls on
the hung device and none on its neighbour, ten unanswered then silence at the cut, the pinger
blind to the hang and seeing 6.4 min of the cut.

- **A hung device is invisible to ping and plain to the capture.** `docker pause` freezes the
  process while the kernel keeps answering ICMP, so the pinger reported plc2 `never down` for
  the whole six minutes. The capture recorded 408 consecutive polls with no reply. I had
  written "the pinger agrees" as a claim; the tool was right and the claim was wrong. This is
  the strongest single argument for passive monitoring on a plant floor, and the lab made it
  by accident.
- **A link cut looks different passively, and the pre-registered claim failed.** Expected: a
  six-minute `DOWN` run on both devices. Measured: ten unanswered polls, then six minutes of
  nothing. After the first timeout the poller's TCP connection is gone and it cannot
  reconnect, so it never sends a Modbus request the capture could count. The pinger, needing
  no connection, saw 6.4 min on both. Two things follow. The silence had been worded
  *"collector was not running"*, a cause a capture cannot support, and is now worded as the
  poller's. And the next build is SYN-level evidence: a connection attempt nobody answered is
  a request too, and it is on the wire.
- **The run rule judges the present.** My first check ran thirty seconds after recovery and
  found the current run `up`. Asked at five minutes into the hang it pages plc2 and only
  plc2; asked after recovery it does not. Both are now claims.
- **"Every host down together" was never true in S6.** The gateway and the HTTP server stayed
  up and the tool said *"At no point was every host under observation down together"*. The
  claim was sloppy; the tool was not.

The first four pass — but S1 did not always mean what it does now, and the correction is the
lab's most important result (the passive-path scenarios S5 and S6 have their own section
below, with a failure of the same kind):

**S1's first version passed on false evidence.** It expected `ALTERNATING` and got it. The
paths it was alternating between were composites: UDP traceroute gives each hop's probes a
different flow, hop 2 was always answered from r3 and hop 3 from either of r4's interfaces,
and the tool stitched `r1 → r3 → r4-via-r2`, a link that does not exist, 1,836 times. The
verdict was right by accident. Probes are ICMP now — one flow per trace — and on this kernel
every flow from the client hashes to the same branch, so a single flow's route is `STABLE`.
That is the truth about a flow. The fabric's load balancing is invisible to any single flow,
which is a property of traceroute, not a defect to fix here; the `ALTERNATING` logic stays
covered by constructed histories in `test_net_path.py`. S1 now grades what the lab can
actually establish: that no stored path mixes the branches and the map draws no phantom link.

Two further findings came out of building it:

- **Per-flow ECMP hashes each traceroute *probe* separately, and that manufactures paths.**
  Linux traceroute sends every probe as its own flow. Hop 2's first answer always came from
  r3 and hop 3's from the r4 interface behind r2, so the "path" built from first answers was
  r1 → r3 → r4-via-r2 — a link that does not exist — and r2 was absent from 1836 traces. The
  `ALTERNATING` verdict was right, but the paths it listed were composites no packet took,
  and the first upstream map drew the phantom link as real. Every address a hop answers
  from is now kept; a hop with more than one is ambiguous, `route_history` says so before
  its verdict, and the map lists links through such hops as candidates rather than drawing
  them. The clean fix is at the probe: a single-flow traceroute (`traceroute -I`) has every
  hop answered by the same path.
- **OSPF cost changes did not reconverge reliably** in this FRR build even after 25 s, so the
  route-change scenarios drive the change by downing a link instead — which converges at once
  and is a cleaner ground truth anyway.

## Why the cost-vs-link choice matters

A cost nudge is the realistic way a route changes in production, but for a *test* the point is
a change that is instantaneous and unambiguous. A downed link gives that: the path through it
is simply gone, SPF reruns immediately, and the before/after is not at the mercy of LSA
timers. The scenario grades the tool, not OSPF's convergence behaviour.
