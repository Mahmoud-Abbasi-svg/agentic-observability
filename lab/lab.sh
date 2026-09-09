#!/bin/bash
# Drive the lab. Run as root inside the WSL distro that has Docker and containerlab:
#
#   wsl -d Ubuntu -u root -e bash "/mnt/j/Spain/Agentic Observability/lab/lab.sh" <command>
#
#   build      build the client image
#   up         deploy the topology and start the collector in the client
#   down       destroy it
#   status     containers, routes on r1, latest collector output
#   check      what the tools say right now (route, availability, every probe type; `check ics`
#              ingests the Modbus capture and judges the PASSIVE path from it alone)
#   passive    (re)start the Modbus poller and the tcpdump capture in the client
#   scenarios  run every scenario against its pre-registered expectation and print PASS/FAIL
#   ics        only the two passive-path scenarios (s5 one device hung, s6 both links cut)
#   guard      say whether the lab can still establish ground truth at all (see `guard()`)
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
PLC1=10.0.5.10
PLC2=10.0.6.10

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
  passive
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

# The passive path: a SCADA host in miniature polling the two Modbus devices once a second,
# and tcpdump on the client's LAN interface recording it. net_ingest reads the capture back;
# the monitor never sends a Modbus packet of its own. -U writes every packet as it arrives,
# so the file is readable while the capture is still running.
PCAP=/data/ics.pcap
passive() {
  # '[l]ab/poller.py', not 'lab/poller.py': pkill -f matches the sh -c running this very line,
  # killed it before the second pkill ran, and left two tcpdumps writing one capture file.
  # The bracketed pattern matches the real process and not its own literal text.
  c client sh -c "pkill -f '[l]ab/poller.py' 2>/dev/null; pkill -x tcpdump 2>/dev/null; true"
  sleep 1
  docker exec -d clab-obs-client sh -c "tcpdump -i eth1 -U -w $PCAP 'tcp port 5020' >/dev/null 2>&1"
  docker exec -d clab-obs-client sh -c "python /app/lab/poller.py $PLC1 $PLC2 > /data/poller.log 2>&1"
  echo "poller and capture started in client ($PCAP)"
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

# ---------------------------------------------------------------- is the lab still a lab?
# Every scenario's ground truth is the container network. If the Docker daemon restarts, each
# containerlab veth pair is destroyed while the containers keep running, so the nodes are left
# with only eth0 and EVERY host looks down - including the gateway - for a reason that has
# nothing to do with the tools. On 2026-09-09 Docker Desktop's WSL integration cycled the
# daemon three times in twenty minutes on the default distro and a full ics run graded 14
# expectations against a dead network. Two of those "failures" were indistinguishable in shape
# from real findings. A run that cannot establish ground truth must say so, not produce
# PASS/FAIL lines, so this is checked before every grading point and the run is VOIDed.
# Overridable so the restart branch below can be tested without restarting the real daemon:
#   DOCKERD_START="not the current daemon" bash lab.sh guard   ->   VOID
DOCKERD_START="${DOCKERD_START:-}"
# pid plus field 22 of /proc/<pid>/stat, the process's start time in jiffies SINCE BOOT.
# Not `ps -o lstart=`: that is boot time plus those jiffies, and WSL2's wall clock drifts and
# re-syncs, so the same untouched daemon reported 15:26:39 and then 15:27:12 while the journal
# showed it starting once at 15:26:25. The first version of this guard voided a good run on
# that alone. A boot-relative number cannot drift, and the pid catches a genuine restart.
dockerd_start() {
  local p; p=$(pgrep -x dockerd | head -1) || return 0
  [ -n "$p" ] && echo "$p:$(awk '{print $22}' "/proc/$p/stat" 2>/dev/null)"
}
intact() { docker exec clab-obs-client ip -o link 2>/dev/null | grep -q ': eth1[@:]'; }
guard() {                        # guard <where> - exits 2 if the lab is no longer a lab
  local now; now=$(dockerd_start)
  if [ -n "$DOCKERD_START" ] && [ "$now" != "$DOCKERD_START" ]; then
    echo "  VOID  the Docker daemon restarted mid-run (before: $DOCKERD_START / now: $now)"
    echo "        Every containerlab link dies with it. Nothing measured after that point is"
    echo "        about the tools. Redeploy with 'bash lab.sh up' and run again; if this keeps"
    echo "        happening, Docker Desktop's WSL integration is cycling this distro's daemon."
    echo "        Stopped at: $1"
    exit 2
  fi
  if ! intact; then
    echo "  VOID  the client has no data-plane interface (eth1); the container network is gone."
    echo "        The lab cannot establish ground truth, so nothing here grades the tools."
    echo "        Stopped at: $1"
    exit 2
  fi
}

# ---------------------------------------------------------------- scenarios
# Each one: set the world to a known state, wait for traces, ask the tool, compare against
# an expectation written BEFORE the tool ran. The expectation is a regex the output must
# match, and one it must not. Timings: traces every 10 s, so 60 s is six traces.
pass=0; fail=0
expect() {                       # expect <name> <output> <must-regex> [<must-not-regex>]
  local name=$1 out=$2 must=$3 mustnot=${4:-}
  guard "$name"                  # grade nothing unless the network the claim is about exists
  if grep -Eq "$must" <<<"$out" && { [ -z "$mustnot" ] || ! grep -Eq "$mustnot" <<<"$out"; }; then
    echo "  PASS  $name"; pass=$((pass+1))
  else
    echo "  FAIL  $name"; fail=$((fail+1))
    echo "$out" | head -12 | sed 's/^/        /'
  fi
}

fresh_db() {                     # every scenario starts from an empty history
  c client sh -c "pkill -9 -f '[n]et_collect.py' 2>/dev/null; pkill -9 -f '[l]ab/poller.py' 2>/dev/null; pkill -x tcpdump 2>/dev/null; true"
  sleep 2                                            # let the WAL handle close
  c client sh -c "rm -f /data/lab.db /data/lab.db-wal /data/lab.db-shm /data/collector.log $PCAP /data/ics.db /data/ics.db-wal /data/ics.db-shm /data/poller.log"
  local n; n=$(c client sh -c "ls /data/lab.db 2>/dev/null | wc -l")
  [ "$n" = "0" ] || echo "  WARN: lab.db not removed"
  collect >/dev/null
  passive >/dev/null
  sleep 3                                            # first cycle before the caller's sleep
}

s1() {
  reset_lab
  echo "== S1  two equal-cost paths: every trace is ONE real path, never a composite of both"
  fresh_db; sleep 120
  out=$(check route)
  echo "$out" | head -6 | sed 's/^/    | /'
  # Re-registered after the first version passed on false evidence. With UDP probes each
  # hop is a different flow, so hop 2 came from one branch and hop 3 from the other, and
  # "ALTERNATING" was read off composite paths that no packet took. Probes are ICMP now:
  # one flow per trace, one real path. On this kernel every flow from this client hashes to
  # the same branch, so a single flow's route is STABLE - which is the truth about that flow.
  # The fabric's load balancing is invisible to a single flow; ALTERNATING remains covered
  # by constructed histories in test_net_path.py, not here.
  expect "S1 every trace is a coherent branch (r2's hops never with r3's)" "$out" \
      '^STABLE over|^ALTERNATING:' 'CHANGED [0-9]'
  sigs=$(docker exec clab-obs-client python -c "import sqlite3; c=sqlite3.connect('/data/lab.db'); print('\n'.join(r[0] for r in c.execute('SELECT sig FROM path')))")
  mixed=$(grep -cE '(10\.0\.13\.3.*10\.0\.24\.4)|(10\.0\.12\.2.*10\.0\.34\.4)' <<<"$sigs" || true)
  expect "S1 no stored path mixes the two branches (composites=$mixed of $(wc -l <<<"$sigs"))" \
      "composites=$mixed" 'composites=0'
  expect "S1 no phantom link in the upstream map" \
      "$(docker exec clab-obs-client python /app/net_topology.py --upstream --days 1)" \
      'link\(s\)' '10\.0\.13\.3\s+\[.*\n\s+-> 10\.0\.24\.4'
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

# ---------------------------------------------------------------- the passive path (ICS)
# Pre-registered 2026-09-09 (prereg_ics.md). Both scenarios are judged from the CAPTURE, not
# the pinger; the pinger runs alongside as a cross-check and must agree on the DOWN interval.
# Six minutes because the shipped run rule is >= 3 polls AND >= 5 min, and at one poll per
# second the minutes bind.
#
# The mutations are chosen for what they put ON THE WIRE. `docker pause` freezes the device's
# process while the kernel still completes TCP handshakes, so every poll is a real Modbus
# request that gets no reply - a hung device. A link cut is different: after the first
# unanswered poll the poller's connection dies and TCP cannot even connect, so no Modbus
# request is sent at all. Whether the passive path can see THAT is exactly what S6 tests.
OUTAGE_S=${OUTAGE_S:-360}

s5() {
  echo "== S5  one device hung for ${OUTAGE_S}s (plc2 paused): plc2 DOWN, plc1 never down, not all-down"
  reset_lab
  fresh_db; sleep 60
  docker pause clab-obs-plc2 >/dev/null
  # Re-registered after the first run (2026-09-09). Two of the first version's five claims
  # failed for reasons that were mine, and each is kept here with what it taught:
  #   * "the run rule pages plc2" was checked 30 s AFTER the device recovered, when its
  #     current run is up. Rule 6 judges the present; it has to be asked during the outage.
  #     So the capture is judged at 300 s into the pause, before the device is released.
  #   * "the pinger agrees plc2 is down" was FALSE, and the tool was right: docker pause
  #     freezes the process while the kernel keeps answering ICMP. An active ping cannot see a
  #     hung device; the capture saw 408 unanswered polls. That is the passive path's whole
  #     case, established by accident, and is now the claim.
  sleep $((OUTAGE_S - 60))
  during=$(check ics)
  echo "$during" | grep -E 'requests|UNANSWERED|unresolved|verdict|rule6|At no point' | sed 's/^/    during| /'
  expect "S5 during the hang, the run rule pages plc2 and only plc2" "$during" "^rule6 $PLC2:1: .*EXCEEDS" "^rule6 $PLC1:1: .*EXCEEDS"
  sleep 60; docker unpause clab-obs-plc2 >/dev/null; sleep 30
  out=$(check ics)
  echo "$out" | grep -E 'requests|UNANSWERED|unresolved|verdict|rule6|every host|At no point' | sed 's/^/    after | /'
  # check.py prints one `verdict <target>: ...` and one `rule6 <target>: ...` line per target,
  # so every expectation is a single line - grep -E does not span newlines.
  expect "S5 plc2 has a DOWN run of consecutive unanswered polls" "$out" "^verdict $PLC2:1: DOWN [0-9.]+ min"
  expect "S5 plc1 was never observed down" "$out" "^verdict $PLC1:1: never down"
  expect "S5 not a network outage: hosts were not all down together" "$out" 'At no point was every host'
  expect "S5 after recovery the run rule no longer pages" "$out" "^rule6 $PLC2:1: up"
  cross=$(check avail)
  echo "$cross" | grep -E '^verdict' | sed 's/^/    ping  | /'
  expect "S5 the pinger CANNOT see a hung device: plc2 never down by ICMP while the capture had it DOWN" \
      "$cross" "^verdict $PLC2: never down" "^verdict $PLC2: DOWN"
  report
}

s6() {
  echo "== S6  both device links down for ${OUTAGE_S}s: all down together; what the CAPTURE can and cannot see"
  reset_lab
  fresh_db; sleep 60
  linkdown r4 eth4; linkdown r4 eth5; sleep "$OUTAGE_S"; linkup r4 eth4; linkup r4 eth5; sleep 30
  out=$(check ics)
  echo "$out" | grep -E 'requests|UNANSWERED|unresolved|verdict|rule6|NOT MEASURED|every host|At no point' | sed 's/^/    | /'
  expect "S6 the capture shows plc1 unanswered at the cut" "$out" "^ +$PLC1:1 .*UNANSWERED"
  expect "S6 the capture shows plc2 unanswered at the cut" "$out" "^ +$PLC2:1 .*UNANSWERED"
  # THE FINDING, re-registered after the first run (2026-09-09). Pre-registered: "both devices
  # have a ~6 min DOWN run in the capture". Measured: DOWN <1 min (10 consecutive) and then
  # six minutes of NOT MEASURED. After the first unanswered poll the poller's TCP connection
  # dies and it cannot reconnect, so no Modbus request is sent at all; the pinger, which
  # needs no connection, saw the full 6.4 min on both. A link cut is visible to a passive
  # monitor as a short run of failures followed by silence, and the silence must be worded as
  # the poller's, not the monitor's. The next build is SYN-level evidence: a connection
  # attempt nobody answered is also a request. Until then this is what the capture can see.
  expect "S6 the capture shows a SHORT down run on plc1, then silence (the poller stopped sending)" "$out" "^verdict $PLC1:1: DOWN 0?\.?[0-9]+ min"
  expect "S6 the capture shows a SHORT down run on plc2, then silence" "$out" "^verdict $PLC2:1: DOWN 0?\.?[0-9]+ min"
  expect "S6 the silence is worded as the poller's, never as a collector outage" "$out" 'nothing on the wire' 'collector was not running'
  expect "S6 the capture reports the two devices down together while both were polled" "$out" 'host under observation was down at once'
  cross=$(check avail)
  echo "$cross" | grep -E 'verdict|every host|At no point' | sed 's/^/    ping| /'
  expect "S6 the pinger sees the full outage on plc1" "$cross" "^verdict $PLC1: DOWN (5|6|7)(\.[0-9])? min"
  expect "S6 the pinger sees the full outage on plc2" "$cross" "^verdict $PLC2: DOWN (5|6|7)(\.[0-9])? min"
  # Re-registered: the first version claimed "every host under observation was down". It
  # was not - the gateway and the HTTP server stayed up throughout, and the tool said so.
  expect "S6 the pinger does NOT call it a network outage: gateway and server stayed up" "$cross" 'At no point was every host'
  expect "S6 the gateway was never observed down" "$cross" "^verdict 10\.0\.1\.1: never down"
  report
}

report() { echo "  -- $pass passed, $fail failed so far"; }

begin() {                        # the baseline the guard compares against
  DOCKERD_START=${DOCKERD_START:-$(dockerd_start)}
  guard "before the first scenario"
  echo "lab intact at start (dockerd up since $DOCKERD_START)"
}
scenarios() { begin; s1; s2; s3; s4; s5; s6; reset_lab; echo; echo "TOTAL: $pass passed, $fail failed"; [ "$fail" -eq 0 ]; }
ics() { begin; s5; s6; reset_lab; echo; echo "TOTAL: $pass passed, $fail failed"; [ "$fail" -eq 0 ]; }

case "${1:-}" in
  build) build ;; up) up ;; down) down ;; status) status ;; collect) collect ;; passive) passive ;;
  check) check "${2:-all}" ;; scenarios) scenarios ;; ics) ics ;; guard) begin ;;
  s1) s1 ;; s2) s2 ;; s3) s3 ;; s4) s4 ;; s5) s5 ;; s6) s6 ;;
  reset) reset_lab ;;
  *) sed -n '2,16p' "$0"; exit 1 ;;
esac
