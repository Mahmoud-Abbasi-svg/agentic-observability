#!/bin/bash
# Drive the lab. Run as root inside the WSL distro that has Docker and containerlab:
#
#   wsl -d Ubuntu -u root -e bash "/mnt/j/Spain/Agentic Observability/lab/lab.sh" <command>
#
#   build      build the client image
#   up         deploy the topology and start the collector in the client
#   down       destroy it
#   status     containers, routes on r1, latest collector output
#   check      what the tools say right now (route, availability, every probe type)
#   scenarios  run every scenario against its pre-registered expectation and print PASS/FAIL
#
# Mutations use the router's own CLI (vtysh) for routing and nsenter into the container's
# network namespace for netem and link state, so no container needs extra privileges.
# No `set -e`: vtysh returns nonzero on a harmless missing-vtysh.conf warning, and the
# scenario harness must report a FAIL rather than abort the whole run on the first one.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOPO="$HERE/topo.clab.yml"
LOG=/data/collector.log            # inside the client; /var/lib/obs-lab on the WSL side
SERVER=10.0.4.10

c() { docker exec "clab-obs-$1" "${@:2}"; }                         # run in a node
ns() { nsenter -t "$(docker inspect -f '{{.State.Pid}}' "clab-obs-$1")" -n "${@:2}"; }
vty() { docker exec "clab-obs-$1" vtysh "${@:2}"; }

build() { docker build -q -t obs-client:latest -f "$HERE/client.Dockerfile" "$HERE"; }

up() {
  mkdir -p /var/lib/obs-lab
  containerlab deploy -t "$TOPO" --reconfigure >/dev/null
  for r in r1 r2 r3 r4; do docker exec "clab-obs-$r" touch /etc/frr/vtysh.conf 2>/dev/null || true; done
  sleep 8                                                           # OSPF adjacency + SPF
  c r1 vtysh -c 'show ip route 10.0.4.0/24' 2>/dev/null | sed 's/^/  r1: /' || true
  collect
}

collect() {
  c client sh -c "pkill -f net_collect.py || true"
  sleep 1
  # docker exec -d detaches the process from the exec session, so it survives the session's
  # teardown - a plain `&` did not, and the collector kept dying the moment the driving
  # command returned. The log goes to a file inside the container.
  docker exec -d clab-obs-client sh -c "python /app/net_collect.py -q > $LOG 2>&1"
  echo "collector started in client (log: /var/lib/obs-lab/collector.log on the WSL side)"
}

down() { containerlab destroy -t "$TOPO" --cleanup >/dev/null 2>&1 || true; echo "destroyed"; }

status() {
  docker ps --filter name=clab-obs --format '  {{.Names}}  {{.Status}}'
  vty r1 -c 'show ip route 10.0.4.0/24' 2>/dev/null | sed 's/^/  r1: /' || true
  tail -3 /var/lib/obs-lab/collector.log 2>/dev/null | sed 's/^/  log: /' || true
}

check() { c client python /app/lab/check.py "${1:-all}"; }

# ---------------------------------------------------------------- mutations, all reversible
cost()     { vty "$1" -c 'conf t' -c "interface $2" -c "ip ospf cost $3"; }
delay()    { ns "$1" tc qdisc replace dev "$2" root netem delay "$3"; }
undelay()  { ns "$1" tc qdisc del dev "$2" root 2>/dev/null || true; }
linkdown() { ns "$1" ip link set "$2" down; }
linkup()   { ns "$1" ip link set "$2" up; }

reset_lab() {
  # Links, not costs: OSPF cost changes did not reconverge reliably in this FRR build even
  # after 25 s, while an interface down/up triggers immediate SPF. A downed link is also a
  # cleaner ground truth - the path via it is simply gone.
  linkup r1 eth2; linkup r1 eth3; linkup r4 eth3
  undelay r4 eth1; undelay r4 eth2; undelay r3 eth2
  sleep 6
}

# ---------------------------------------------------------------- scenarios
# Each one: set the world to a known state, wait for traces, ask the tool, compare against
# an expectation written BEFORE the tool ran. The expectation is a regex the output must
# match, and one it must not. Timings: traces every 10 s, so 60 s is six traces.
pass=0; fail=0
expect() {                       # expect <name> <output> <must-regex> [<must-not-regex>]
  local name=$1 out=$2 must=$3 mustnot=${4:-}
  if grep -Eq "$must" <<<"$out" && { [ -z "$mustnot" ] || ! grep -Eq "$mustnot" <<<"$out"; }; then
    echo "  PASS  $name"; pass=$((pass+1))
  else
    echo "  FAIL  $name"; fail=$((fail+1))
    echo "$out" | head -12 | sed 's/^/        /'
  fi
}

fresh_db() {                     # every scenario starts from an empty history
  c client sh -c "pkill -9 -f net_collect.py 2>/dev/null || true"
  sleep 2                                            # let the WAL handle close
  c client sh -c "rm -f /data/lab.db /data/lab.db-wal /data/lab.db-shm /data/collector.log"
  local n; n=$(c client sh -c "ls /data/lab.db 2>/dev/null | wc -l")
  [ "$n" = "0" ] || echo "  WARN: lab.db not removed"
  collect >/dev/null
  sleep 3                                            # first cycle before the caller's sleep
}

s1() {
  reset_lab
  echo "== S1  two equal-cost paths, per-flow hashing: the route ALTERNATES, and that is not a change"
  fresh_db; sleep 120
  out=$(check route)
  echo "$out" | head -6 | sed 's/^/    | /'
  # Per-flow ECMP hashes each traceroute PROBE separately, so one traceroute samples both
  # physical paths and the tool sees more than two signatures. The verdict - ALTERNATING,
  # not a change - is what matters and is what is graded; the count is not.
  expect "S1 verdict is ALTERNATING, not a change" "$out" '^ALTERNATING:' 'CHANGED [0-9]'
  expect "S1 says it is load balancing, not a route change" "$out" 'not a route change'
  report
}

s2() {
  echo "== S2  one path removed: STABLE; then the other removed: CHANGED once, at the hop that moved"
  reset_lab
  linkdown r1 eth3; sleep 6                    # kill the r3 path: everything via r2
  fresh_db; sleep 70
  out=$(check route)
  echo "$out" | head -4 | sed 's/^/    a| /'
  expect "S2a one path holds: STABLE, no rotation" "$out" '^STABLE over' 'ALTERNATING|CHANGED'
  linkup r1 eth3; linkdown r1 eth2; sleep 6    # flip: kill the r2 path, everything via r3
  sleep 70
  out=$(check route)
  echo "$out" | head -6 | sed 's/^/    b| /'
  expect "S2b the reroute is CHANGED exactly once" "$out" '^CHANGED 1 time' 'ALTERNATING'
  expect "S2b diverges at hop 2 (r2 -> r3)" "$out" 'diverges at hop 2 \(10\.0\.12\.2 -> 10\.0\.13\.3\)'
  linkup r1 eth2
  report
}

s3() {
  echo "== S3  the same route gets slower: 40 ms of netem on r3's far link; rise at hop 3 onward"
  reset_lab
  linkdown r1 eth2; sleep 6                     # single path via r3
  fresh_db; sleep 60
  delay r3 eth2 40ms                            # the r3->r4 link, which is hop 3 on this path
  sleep 100
  out=$(check route)
  echo "$out" | grep -E 'STABLE|CHANGED|rise|hop|10\.0' | head -12 | sed 's/^/    | /'
  expect "S3 route still one path, no rotation" "$out" '^(STABLE|CHANGED 1 time)' 'ALTERNATING'
  expect "S3 the rise first appears at hop 3 and every later hop shares it" "$out" 'rise first appears at hop 3 .*every later hop shares it'
  undelay r3 eth2; linkup r1 eth2
  report
}

s4() {
  echo "== S4  the server's link down for ~70 s: a DOWN run, not a gap; gateway stays up"
  reset_lab
  fresh_db; sleep 45
  linkdown r4 eth3; sleep 70; linkup r4 eth3; sleep 35
  out=$(check avail)
  echo "$out" | grep -E 'availability of|DOWN|summary|every host|At no point' | sed 's/^/    | /'
  # Single-line checks: grep -E does not span newlines, and the server's DOWN line, the
  # gateway's "never observed down", and the not-all-down verdict each sit on one line.
  expect "S4 the server has a DOWN run of consecutive failures" "$out" 'DOWN +.*consecutive failures'
  expect "S4 the server's block reports a down run" "$out" "$SERVER.*[0-9]+ probes"
  expect "S4 the gateway was never observed down" "$out" 'never observed down'
  expect "S4 not a network outage: hosts were not all down together" "$out" 'At no point was every host'
  report
}

report() { echo "  -- $pass passed, $fail failed so far"; }

scenarios() { s1; s2; s3; s4; reset_lab; echo; echo "TOTAL: $pass passed, $fail failed"; [ "$fail" -eq 0 ]; }

case "${1:-}" in
  build) build ;; up) up ;; down) down ;; status) status ;; collect) collect ;;
  check) check "${2:-all}" ;; scenarios) scenarios ;;
  s1) s1 ;; s2) s2 ;; s3) s3 ;; s4) s4 ;;
  reset) reset_lab ;;
  *) sed -n '2,16p' "$0"; exit 1 ;;
esac
