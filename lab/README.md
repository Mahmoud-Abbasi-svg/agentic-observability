# The lab — testing the tools against a network with known answers

Every other test in this repo builds a *history* by hand and checks the tools read it right.
This builds a *network* whose answers are known, runs the real collector inside it, and checks
the tools against ground truth. It is the first thing that can falsify `route_history` and
`availability` on traffic they did not stage themselves.

```
                +-- r2 --+
  client -- r1 -+        +- r4 -- server
                +-- r3 --+
```

Six [containerlab](https://containerlab.dev/) nodes: four FRR routers running OSPF with two
equal-cost paths from `r1` to the server, a `client` that runs the collector, and a `server`
serving HTTP. Nothing here touches the host's real network — it is a private Docker bridge.

## Requirements

WSL2 with a Linux distro, Docker Engine **inside** that distro (not Docker Desktop's Windows
engine), and containerlab. On this machine the one-time setup was:

```bash
# as root inside the WSL distro
apt-get install -y docker.io iproute2
curl -sL https://get.containerlab.dev | bash
printf '[boot]\nsystemd=true\n' > /etc/wsl.conf   # then: wsl --terminate <distro>
```

## Running it

All commands run as root inside the WSL distro. From the repo's `lab/` directory:

```bash
bash lab.sh build       # build the client image (collector + ping/traceroute/dig)
bash lab.sh up          # deploy the topology, start the collector in the client
bash lab.sh status      # containers, r1's route to the server, latest collector output
bash lab.sh check route # what route_history says right now
bash lab.sh scenarios   # run S1-S4 against their pre-registered expectations
bash lab.sh down        # destroy everything
```

## The scenarios, and what each proves

Each sets the world to a known state, waits for the collector to trace it, asks the tool, and
grades the answer against an expectation written **before** the tool ran. The mutations use
link state and `tc netem`, driven through each node's own namespace, so no container needs
extra privilege and every change is reversible.

| # | ground truth set up | what the tool must say |
|---|---|---|
| **S1** | two equal-cost paths, per-flow hashing on | `ALTERNATING` — load balancing, **not** a route change |
| **S2** | one path removed (link down), then the other | `STABLE`, then `CHANGED` once, diverging at the exact hop that moved |
| **S3** | 40 ms of netem on the r3→r4 link | route `STABLE`; the per-hop rise placed at hop 3, every later hop sharing it |
| **S4** | the server's link down for ~70 s | a `DOWN` run on the server; the gateway `never observed down`; **not** a network-wide outage |

All four pass. Two findings came out of building it:

- **Per-flow ECMP hashes each traceroute *probe* separately**, so a single traceroute samples
  both physical paths and the tool sees more signatures than there are paths. The verdict
  (`ALTERNATING`) is still right; the path *count* is inflated. Real, and worth knowing when
  reading a busy ECMP fabric.
- **OSPF cost changes did not reconverge reliably** in this FRR build even after 25 s, so the
  route-change scenarios drive the change by downing a link instead — which converges at once
  and is a cleaner ground truth anyway.

## Why the cost-vs-link choice matters

A cost nudge is the realistic way a route changes in production, but for a *test* the point is
a change that is instantaneous and unambiguous. A downed link gives that: the path through it
is simply gone, SPF reruns immediately, and the before/after is not at the mercy of LSA
timers. The scenario grades the tool, not OSPF's convergence behaviour.
