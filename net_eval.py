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

    dict(id="dns_config", category="FAULT",
         question="Is my DNS configuration correct?",
         expect="At least one configured resolver is unreachable from this network "
                "(192.168.88.1 is on a different subnet; the 203.0.113.x servers do "
                "not answer). Name resolution still works via fallback.",
         must_not=[],
         want_tools={"local_network"}),

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
    forbidden = [p for p in scn["must_not"] if re.search(p, answer, re.I)]
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
    for cat in ["FAULT", "CLEAN", "CALIBRATION"]:
        rows = [r for r in ok if r["category"] == cat]
        if not rows:
            continue
        extra = ""
        if cat == "CLEAN":
            extra = f"   invented a fault {rate(rows, 'invented_fault'):.2f}  <- must be 0.00"
        if cat == "CALIBRATION":
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
