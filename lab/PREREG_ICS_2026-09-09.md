# Pre-registration: the industrial track, day one

Written 2026-09-09 15:05, before any 4SICS capture was parsed and before the lab was changed.
Order agreed: lab now, SWaT requested today, 4SICS as the bridge.

## What "down" means passively, fixed in advance

The collector measures reachability by sending a probe and seeing whether it is answered. A
capture cannot send anything. The passive equivalent of a failed probe is A REQUEST THAT GOT NO
REPLY: the poller asked, the device did not answer. net_ingest today pairs requests with
replies and stores the response time of the pairs; an unanswered request is dropped when the
transaction id is reused, which means the one event that matters most on a plant floor -
silence - is the one event the ingester cannot see.

So the build is: for every Modbus request, a `reachable` sample at the request's time - 1.0
if a reply arrived within T, 0.0 if not - alongside `response_ms` for the answered ones.
T is not a constant: it is the series' own poll interval (a reply that arrives after the NEXT
poll was sent is a reply to nothing). A capture that ends with requests still pending reports
them as UNRESOLVED, not as failures: "the capture stopped" and "the device did not answer" are
different statements and the data only supports the first.

The same `_runs` logic then cuts `reachable` into up / down / gap, so the passive path gets
`availability`, the report, the live page and rule 6 for free. No downstream change.

## Claims: 4SICS (real hardware, direct download)

  I1  net_ingest finds Modbus/TCP transactions on port 502 in at least one of the three
      captures and reports every device it saw, with its unit id
  I2  for every device with >= 100 transactions, the response-time series has a computable
      noise floor (assess status "ok" or a stated reason why not) - the point of real hardware
  I3  after the build, every request has a reachable sample; the count of requests equals the
      count of reachable samples per device, and unanswered requests are non-zero somewhere
      (a conference lab with people unplugging things) or the ingester says they are zero
  I4  requests still pending when the capture ends are reported as UNRESOLVED and are NOT
      stored as reachable=0
  I5  anything on port 502 that is not protocol id 0, and any Modbus on another port, is
      counted and reported as skipped, never silently dropped

  What 4SICS cannot establish: cadence and floors of a POLLED PROCESS. It is a conference
  village; polling is whatever visitors ran. It exercises the parser on real hardware, no more.

## Claims: the lab (ground truth), two new scenarios

  Topology change: two Modbus/TCP devices (plc1, plc2) on the server segment behind r4, a
  poller in the client polling both every 1 s, a rolling tcpdump on the client's eth1, and
  the ingester run over the capture. The existing four scenarios are untouched.

  S5  ONE DEVICE DOWN: stop plc2's Modbus server for 6 min while plc1 answers.
      - plc2 has a DOWN run of ~6 min of consecutive unanswered polls; plc1 never down
      - `availability` says "At no point was every host down together"
      - rule 6 pages plc2 (>= 3 polls, >= 5 min) and nothing else
  S6  ALL DEVICES DOWN: r4's link to the server segment down for 6 min.
      - both devices have a DOWN run of the same ~6 min starting within one poll of each other
      - `availability` reports an interval where every host under observation was down
      - the gateway (10.0.1.1) is never down
      - both page under rule 6 (the correlation rule is a LATER step; here both page and
        that is recorded as the fatigue the later step must remove)

  Both are measured by the PASSIVE path: the capture, not the pinger. The pinger keeps running
  as a cross-check and its `availability` must agree on the DOWN interval within one probe.

## Not in scope today

The all-hosts-down correlation rule itself; S7comm; the SPAN-port continuous collector (the
lab uses a rolling pcap and periodic ingest, which is the batch path made repeatable).
