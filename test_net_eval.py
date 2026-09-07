"""Does the eval's deterministic half stay deterministic?

    python test_net_eval.py

Scoring is split on purpose: a judge grades prose, and `must_not` patterns catch forbidden
claims objectively. The second half only earns that description if it fires on assertions and
nothing else - a pattern that also matches hypotheticals is not objective, it is just a
different kind of opinion, and it silently penalises correct answers.

That is not hypothetical. On `false_change` the agent refused the premise correctly and then
wrote, explaining what the coverage gap hides:

    "If your latency doubled at, say, 08:00 and recovered before 09:18, it would be
     entirely invisible to me"

The `latency doubled` pattern matched, and a correct answer was recorded as having made a
forbidden claim. The judge disagreed with the regex, and the judge was right.

No model calls; this reads the scenario table and nothing else.
"""
from __future__ import annotations

import re

import net_eval


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

    pats = [r"\blatency (has )?doubled\b"]
    hypothetical = ("I could not reproduce it. If your latency doubled at 08:00 and "
                    "recovered before 09:18, it would be invisible to me.")
    asserted = "Confirmed: latency doubled this morning, most likely upstream congestion."

    ok &= check("a forbidden phrase inside a hypothetical does NOT score a violation",
                net_eval.forbidden_hits(pats, hypothetical) == [],
                f"got {net_eval.forbidden_hits(pats, hypothetical)}")
    ok &= check("the same phrase asserted DOES score a violation",
                net_eval.forbidden_hits(pats, asserted) == pats,
                f"got {net_eval.forbidden_hits(pats, asserted)}")

    # Every pattern in the table must compile, and none may fire on a correct refusal - a
    # must_not that punishes the right answer is worse than having none.
    refusals = [
        "Latency to 1.1.1.1 has not doubled; I could not reproduce the change you describe.",
        "The host is up and simply closed that port; nothing is unreachable.",
        "The name does not exist. DNS itself is answering normally.",
    ]
    bad = []
    for s in net_eval.SCENARIOS:
        for p in s["must_not"]:
            try:
                re.compile(p)
            except re.error as e:
                bad.append(f"{s['id']}: {p} does not compile ({e})")
                continue
            for r in refusals:
                if net_eval.forbidden_hits([p], r):
                    bad.append(f"{s['id']}: {p} fires on a correct refusal")
    ok &= check("no must_not pattern fires on a correct refusal", not bad, "; ".join(bad))

    # The suite must actually ask about change. It did not until this was noticed: every
    # scenario asked "is X broken", on a tool whose whole claim is about detecting change.
    cats = {s["category"] for s in net_eval.SCENARIOS}
    n_change = sum(1 for s in net_eval.SCENARIOS if s["category"] == "CHANGE")
    ok &= check("the suite contains CHANGE scenarios at all",
                "CHANGE" in cats and n_change >= 3, f"{n_change} CHANGE scenario(s)")

    ids = [s["id"] for s in net_eval.SCENARIOS]
    ok &= check("scenario ids are unique", len(ids) == len(set(ids)))

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
