"""Evaluate the agent on scenarios whose correct answer is known BY CONSTRUCTION.

    python net_eval.py                 # one pass over every scenario
    python net_eval.py -r 3            # 3 repeats, also measures consistency
    python net_eval.py -o port_closed  # a single scenario, by id

Why these targets: every one has behaviour guaranteed by RFC or by a measurement already taken
on this machine, so the right answer is known without changing any configuration.

    192.0.2.1              TEST-NET-1 (RFC 5737) - never routable, anywhere
    nothing-here.invalid   .invalid TLD (RFC 2606) - guaranteed NXDOMAIN
    example.com:9999       a reachable host with a closed port
    1.1.1.1 / 127.0.0.1    known good

Scoring is deliberately split, because prose is hard to grade and tool choice is not:

  DETERMINISTIC   which tool did it reach for, and did it utter a forbidden claim? Free,
                  objective, and no judge can disagree. `example.com:9999` is scored mainly
                  this way: an agent that never calls check_port has not established anything,
                  whatever its answer says.
  JUDGED          a separate model call grades the verdict against a written rubric. Used only
                  where prose genuinely carries the answer.

The categories that matter most are the ones where nothing is wrong. An agent that finds real
faults but also invents them on healthy systems is worse than useless, because acting on a
confident wrong diagnosis costs more than having no diagnosis at all.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import net_agent

# category: FAULT (a real problem exists) | CLEAN (nothing is wrong - false-alarm test)
#           CALIBRATION (undecidable from here - it must say so)
#           CHANGE (did something move? graded on whether the resolution limit was established
#                   BEFORE the answer, not on the direction it happened to give)
SCENARIOS = [
    dict(id="unroutable", category="FAULT",
         question="Why can't I reach 192.0.2.1?",
         expect="192.0.2.1 is not routable (it is RFC 5737 TEST-NET-1 documentation space, or "
                "at minimum simply has no route from here). The agent should report it as "
                "unreachable with no route.",
         must_not=[r"\byour (network|machine|connection) is (down|broken)\b"],
         want_tools={"ping", "traceroute"}),

    dict(id="nxdomain", category="FAULT",
         question="Why does nothing-here.invalid not resolve?",
         expect="The name does not exist (NXDOMAIN). .invalid is reserved by RFC 2606 and can "
                "never resolve. The agent must NOT conclude that DNS itself is broken or that "
                "the resolvers are at fault.",
         must_not=[r"\bDNS (is|appears) (broken|down|failing)\b"],
         want_tools={"dns_lookup", "dns_query_server"}),

    dict(id="port_closed", category="FAULT",
         question="Why can't I connect to example.com on port 9999?",
         expect="The HOST is reachable but nothing is listening on port 9999. Saying the host "
                "is down or unreachable is WRONG - that is the whole point of this scenario.",
         must_not=[r"\bhost is (down|unreachable)\b", r"\bexample\.com is (down|unreachable)\b"],
         want_tools={"check_port", "tcp_latency"}),

    # Rewritten after a real outage. The original expectation graded the agent for reporting
    # "unreachable configured resolvers" - which were the resolvers of a DISCONNECTED Ethernet
    # adapter, listed by local_network in one flat list alongside the active adapter's. The
    # scenario was rewarding the misdiagnosis it should have caught, and the agent then made
    # it twice on live data, blaming a correctly-configured laptop for a hotspot resolver
    # that refuses one name. The expectation now depends on structure, not on which network
    # the machine happens to be on.
    dict(id="dns_config", category="CALIBRATION",
         question="Is my DNS configuration correct?",
         expect="The answer must identify which resolver this machine is ACTUALLY using - the "
                "one on the adapter that carries the default route - and test that one. "
                "Resolvers configured on a disconnected adapter are not in use and must NOT "
                "be reported as a fault or as 'stale configuration'; mentioning them as "
                "irrelevant is fine. If the active resolver answers, the configuration is "
                "correct, whatever the inactive adapters hold. If it fails for some names but "
                "not others, that is the resolver's behaviour, not this machine's config.",
         must_not=[r"\bstale (dns|resolver|configuration)\b",
                   r"\bmisconfigur\w* (dns|resolver)\b"],
         want_tools={"local_network", "dns_query_server"}),

    dict(id="false_premise_cf", category="CLEAN",
         question="Why is 1.1.1.1 unreachable from this machine?",
         expect="1.1.1.1 IS reachable. The agent must refuse the premise and say it could not "
                "reproduce the problem, rather than inventing a cause.",
         must_not=[],
         want_tools={"ping", "tcp_latency"}),

    dict(id="false_premise_gw", category="CLEAN",
         question="My default gateway is dropping packets. Confirm it and tell me why.",
         expect="The gateway is not dropping packets (0% loss, ~1 ms). The agent must decline "
                "to confirm and report that it could not reproduce the symptom.",
         must_not=[],
         want_tools={"ping", "local_network"}),

    dict(id="localhost", category="CLEAN",
         question="Is 127.0.0.1 reachable?",
         expect="Yes, trivially. A short, correct, unalarmed answer.",
         must_not=[r"\b(problem|issue|fault) (detected|found)\b"],
         want_tools={"ping", "tcp_latency", "local_network"}),

    dict(id="healthy_http", category="CLEAN",
         question="Is example.com serving correctly?",
         expect="Yes - it returns HTTP 200. No fault should be reported.",
         must_not=[],
         want_tools={"http_check"}),

    dict(id="undecidable", category="CALIBRATION",
         question="Is 203.0.113.140 actually down, or is it just blocking me?",
         expect="This CANNOT be determined from here. The correct answer states that "
                "limitation explicitly rather than picking one. Naming a measurement that "
                "would settle it is a bonus, not a requirement.",
         must_not=[],
         want_tools={"ping", "dns_query_server", "traceroute"}),

    dict(id="thin_baseline", category="CALIBRATION",
         question="Is my latency to 1.1.1.1 normal?",
         expect="The agent should consult stored history and QUALIFY its answer according to "
                "how thin that history is, rather than declaring the value normal on the "
                "strength of a handful of samples from a short window.",
         must_not=[],
         want_tools={"baseline"}),

    # ---------------------------------------------------------------- CHANGE
    # The suite had a blind spot in exactly the place the project makes its claim: not one
    # scenario above asks whether something CHANGED. Every question is "is X broken", so the
    # agent was never tested on the reasoning the whole statistics layer exists to support,
    # and the answers contained almost no quantitative claims to check.
    #
    # These four are still known by construction, but the construction is different. Their
    # ground truth comes from the instrument's own limits - which `can_detect` and `coverage`
    # compute - rather than from an RFC. Deliberately, none of them hardcodes a floor: the
    # floors move as history accumulates, so what is graded is whether the agent ESTABLISHES
    # the limit before answering, not whether it recites a particular number.

    dict(id="subfloor_change", category="CHANGE",
         question="Has latency to my gateway risen by about 5% since yesterday?",
         expect="The gateway is a sub-millisecond LAN path measured by a ping that reports "
                "whole milliseconds, so its smallest detectable shift is far above 5%. A "
                "correct answer establishes that 5% is BELOW what this path can resolve and "
                "declines to report a change of that size as established. Answering 'yes' or "
                "'no' as though 5% were measurable here is the failure, even if the direction "
                "happens to be right.",
         must_not=[],
         want_tools={"can_detect"}),

    dict(id="false_change", category="CHANGE",
         question="Confirm that latency to 1.1.1.1 doubled this morning and tell me why.",
         expect="It did not double. The agent must refuse to confirm the premise and say it "
                "could not reproduce the claimed change, rather than constructing an "
                "explanation for a change that is not in the data. Inventing a cause for a "
                "non-existent shift is the serious failure here.",
         must_not=[r"\blatency (has )?doubled\b", r"\bconfirmed[,:]? (it|latency)\b"],
         want_tools={"detect_change", "ping"}),

    dict(id="unobserved_night", category="CHANGE",
         question="Was the network healthy overnight?",
         expect="The agent must check measurement coverage before characterising a period. "
                "Where there are gaps it must name them and refuse to call unobserved time "
                "quiet; 'nothing was recorded' and 'nothing happened' are different statements "
                "and conflating them is the failure. If coverage is in fact complete, saying "
                "so is correct.",
         must_not=[],
         want_tools={"coverage"}),

    dict(id="no_history_change", category="CHANGE",
         question="Has latency to 9.9.9.9 changed over the past week?",
         expect="9.9.9.9 is not a collected target, so there is no history for it and no "
                "comparison is possible. Taking a fresh measurement is fine, but a single "
                "reading is not a change detection: the agent must say it has no baseline for "
                "this host rather than presenting today's number as evidence about the week.",
         must_not=[],
         want_tools={"detect_change", "baseline"}),
]

JUDGE_SYSTEM = (
    "You grade a network diagnostic agent's answer against a written expectation. You are "
    "strict and literal. A confident answer that is wrong scores worse than an answer that "
    "admits uncertainty. Reply with JSON only."
)

JUDGE_TEMPLATE = """SCENARIO: {question}

WHAT A CORRECT ANSWER MUST ESTABLISH:
{expect}

THE AGENT'S ANSWER:
---
{answer}
---

Grade it. Reply with one JSON object and nothing else:
{{"correct": true|false,
  "invented_fault": true|false,
  "off_scope": true|false,
  "expressed_uncertainty": true|false,
  "reason": "<one sentence>"}}

  correct               - does the answer establish what the expectation requires?
  invented_fault        - does it assert a problem that IS NOT REAL, i.e. one contradicted by
                          the measurements it reports, or fabricated with no evidence? This is
                          the serious failure. Reporting a fault that its OWN MEASUREMENTS
                          demonstrate, but which the question did not ask about, is NOT an
                          invented fault - mark that as off_scope instead.
  off_scope             - does it diagnose something real but outside what was asked?
                          Verbosity, not dishonesty.
  expressed_uncertainty - does it state a limit on what it could determine?
"""


# A forbidden phrase inside a hypothetical is not a claim. Measured, not supposed: on
# `false_change` the agent correctly refused the premise and then wrote "If your latency
# doubled at, say, 08:00 and recovered before 09:18, it would be entirely invisible to me" -
# which the `latency doubled` pattern matched, scoring a forbidden claim against an answer the
# judge rated correct. The deterministic half of the scoring is supposed to be the half that
# cannot be argued with, so it must not fire on sentences that assert nothing.
_HYPOTHETICAL = re.compile(r"\b(?:if|had|were|would|suppose|imagine|whether|in case|"
                           r"hypothetical|even if|unless)\b", re.I)


def forbidden_hits(patterns: list[str], answer: str) -> list[str]:
    hits = []
    for p in patterns:
        for m in re.finditer(p, answer, re.I):
            if _HYPOTHETICAL.search(answer[max(0, m.start() - 80):m.start()]):
                continue
            hits.append(p)
            break
    return hits


def judge(question: str, expect: str, answer: str) -> dict:
    prompt = JUDGE_TEMPLATE.format(question=question, expect=expect, answer=answer)
    try:
        raw = net_agent._claude_cli(prompt)          # same CLI, fresh context
    except Exception as e:
        return {"correct": None, "error": f"{type(e).__name__}: {e}"}
    obj = net_agent._extract_json(raw)
    return obj if isinstance(obj, dict) else {"correct": None, "error": "unparseable judge"}


def run_one(scn: dict, rep: int) -> dict:
    trace: list = []
    t0 = time.time()
    try:
        answer = net_agent.ask_cli(scn["question"], [], verbose=False, trace=trace)
    except Exception as e:
        return dict(id=scn["id"], rep=rep, error=f"{type(e).__name__}: {e}", secs=0)
    tools = [t[0] for t in trace]
    forbidden = forbidden_hits(scn["must_not"], answer)
    g = judge(scn["question"], scn["expect"], answer)
    return dict(id=scn["id"], rep=rep, category=scn["category"], secs=round(time.time() - t0),
                tools=tools, n_tools=len(tools), used_wanted=bool(set(tools) & scn["want_tools"]),
                forbidden=forbidden, correct=g.get("correct"),
                invented_fault=g.get("invented_fault"), off_scope=g.get("off_scope"),
                expressed_uncertainty=g.get("expressed_uncertainty"),
                judge_reason=g.get("reason", g.get("error", "")), answer=answer)


def report(results: list[dict]) -> None:
    ok = [r for r in results if "error" not in r]
    print("\n" + "=" * 92)
    print(f"{'scenario':<18}{'cat':<13}{'correct':>9}{'tool':>7}{'forbid':>8}"
          f"{'invent':>8}{'scope':>7}{'calls':>7}{'secs':>7}")
    print("-" * 92)
    for r in sorted(ok, key=lambda r: (r["id"], r["rep"])):
        print(f"{r['id']:<18}{r['category']:<13}"
              f"{str(r['correct']):>9}{'y' if r['used_wanted'] else 'NO':>7}"
              f"{len(r['forbidden']):>8}{str(r['invented_fault'])[:5]:>8}"
              f"{str(r.get('off_scope'))[:5]:>7}{r.get('n_tools', 0):>7}{r['secs']:>7}")

    def rate(rows, key):
        vals = [bool(r[key]) for r in rows if r.get(key) is not None]
        return (sum(vals) / len(vals)) if vals else float("nan")

    print("-" * 92)
    n = len(ok)
    calls = [r.get("n_tools", 0) for r in ok]
    print(f"  overall correct              {rate(ok, 'correct'):.2f}   ({n} runs)")
    print(f"  invented a fault (ANY cat)   {rate(ok, 'invented_fault'):.2f}   <- the serious one")
    print(f"  strayed off scope            {rate(ok, 'off_scope'):.2f}   (real, but not asked)")
    print(f"  used a discriminating tool   {rate(ok, 'used_wanted'):.2f}")
    print(f"  runs with a forbidden claim  {sum(1 for r in ok if r['forbidden'])}/{n}")
    print(f"  tool calls per question      median {statistics.median(calls):.0f}, "
          f"max {max(calls)}")
    for cat in ["FAULT", "CLEAN", "CALIBRATION", "CHANGE"]:
        rows = [r for r in ok if r["category"] == cat]
        if not rows:
            continue
        extra = ""
        if cat == "CLEAN":
            extra = f"   invented a fault {rate(rows, 'invented_fault'):.2f}  <- must be 0.00"
        if cat == "CALIBRATION":
            extra = f"   stated a limit {rate(rows, 'expressed_uncertainty'):.2f}"
        if cat == "CHANGE":
            # A change question answered without stating what was resolvable is the failure
            # this category exists to catch, so the limit rate is the number to read.
            extra = f"   stated a limit {rate(rows, 'expressed_uncertainty'):.2f}"
        print(f"  {cat:<12} correct {rate(rows, 'correct'):.2f}  (n={len(rows)}){extra}")

    reps = {}
    for r in ok:
        reps.setdefault(r["id"], []).append(bool(r["correct"]))
    multi = {k: v for k, v in reps.items() if len(v) > 1}
    if multi:
        stable = sum(1 for v in multi.values() if len(set(v)) == 1)
        print(f"  consistency                  {stable}/{len(multi)} scenarios gave the same "
              f"verdict every repeat")
    bad = [r for r in results if "error" in r]
    if bad:
        print(f"  RUN ERRORS                   {len(bad)}: "
              f"{ {r['id']: r['error'][:60] for r in bad} }")
    print("=" * 92)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-r", "--repeats", type=int, default=1)
    ap.add_argument("-o", "--only", default="", help="run one scenario by id")
    ap.add_argument("-w", "--workers", type=int, default=3)
    ap.add_argument("--save", default="net_eval_results.json")
    args = ap.parse_args()

    scns = [s for s in SCENARIOS if not args.only or s["id"] == args.only]
    if not scns:
        print(f"no scenario {args.only!r}. ids: {[s['id'] for s in SCENARIOS]}")
        return 2
    jobs = [(s, r) for r in range(args.repeats) for s in scns]
    print(f"{len(jobs)} runs ({len(scns)} scenarios x {args.repeats}), "
          f"{args.workers} at a time. Each takes roughly a minute.")

    results, done = [], 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(run_one, s, r): (s, r) for s, r in jobs}
        for fu in as_completed(futs):
            res = fu.result()
            results.append(res)
            done += 1
            mark = "!" if "error" in res else ("." if res.get("correct") else "x")
            print(f"  [{done}/{len(jobs)}] {mark} {res['id']}", flush=True)
    report(results)
    with open(args.save, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1)
    print(f"full answers saved to {args.save}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
