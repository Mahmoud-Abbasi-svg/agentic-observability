"""How much of a real answer does the verifier actually see?

    python audit_verify.py net_eval_results.json net_eval_results2.json net_eval_stopping.json

`net_verify` finds claims with regular expressions, so its coverage is an empirical question,
not a design decision. This measures it against agent answers that were written for a different
purpose and therefore cannot have been tuned against - the only kind of text that tests
coverage honestly.

The number that matters is not how many claims were caught. It is **how many numbers were left
behind**, and what they look like. A verifier that reports nothing on an answer full of
percentages is not quiet, it is blind - and its silence reads as a clean bill of health.

So the main output is a sample of the numeric phrases that matched NOTHING. Read them. Each one
is either irrelevant (a timestamp, a sample count, a port) or a claim that slipped through, and
only a human can tell which.

Reads only; writes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

import net_verify

# Anything that looks like a quantity, whether or not it is a claim. The denominator.
NUMBER = re.compile(r"[+-]?\d+(?:\.\d+)?\s*(?:%|percent|ms|milliseconds?|s\b|h\b)", re.I)


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    rows = d if isinstance(d, list) else d.get("results", d)
    return list(rows.values()) if isinstance(rows, dict) else rows


def context(text: str, at: int, width: int = 34) -> str:
    s = text[max(0, at - width):at + width].replace("\n", " ")
    return re.sub(r"\s+", " ", s).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure the verifier's coverage on real answers.")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--show", type=int, default=25, help="unmatched phrases to print")
    a = ap.parse_args()

    answers: list[tuple[str, str, bool]] = []
    for path in a.files:
        try:
            for r in load(path):
                text = r.get("answer") or ""
                if text.strip():
                    answers.append((r.get("id", "?"), text, bool(r.get("correct"))))
        except Exception as e:
            print(f"{path}: {type(e).__name__}: {e}", file=sys.stderr)

    if not answers:
        print("no answers found")
        return 1

    tot_numbers = tot_claims = blind = 0
    verdicts: dict[str, int] = {}
    disagreements: list[tuple[str, str]] = []
    unmatched: list[tuple[str, str]] = []

    for qid, text, judged_correct in answers:
        claims = net_verify.find_claims(text)
        spans = [(c.pos, c.pos + len(c.raw)) for c in claims]
        nums = list(NUMBER.finditer(text.translate(net_verify._DASHES)))
        tot_numbers += len(nums)
        tot_claims += len(claims)

        # The miss signature: numbers present, nothing recognised as a claim about them.
        if nums and not claims:
            blind += 1

        for m in nums:
            if not any(lo <= m.start() < hi for lo, hi in spans):
                unmatched.append((qid, context(text, m.start())))

        for f in (net_verify.verify_claim(c) for c in claims):
            verdicts[f.verdict] = verdicts.get(f.verdict, 0) + 1
            if f.verdict == "UNSUPPORTABLE" and judged_correct:
                disagreements.append((qid, f.detail))

    print(f"{len(answers)} answers, {tot_numbers} numeric phrases, {tot_claims} read as "
          f"claims of change\n")

    print("verdicts")
    for k in sorted(verdicts):
        print(f"  {k:<16}{verdicts[k]:>4}")

    pct = 100.0 * blind / len(answers)
    print(f"\nanswers carrying numbers where NOTHING matched: {blind}/{len(answers)} "
          f"({pct:.0f}%)")
    print("  ^ the failure mode that matters. Each of these got a report implying it was "
          "checked.")

    if disagreements:
        print(f"\n{len(disagreements)} claim(s) the verifier calls unsupportable inside answers "
              f"the judge marked CORRECT.\nEach is either a verifier false positive or "
              f"something the judge missed - both worth knowing:")
        for qid, d in disagreements[:12]:
            print(f"  [{qid}] {d}")

    print(f"\nnumeric phrases that matched no claim: {len(unmatched)}")
    print("read these; each is a timestamp/count (fine) or a claim that slipped through:")
    seen = set()
    shown = 0
    for qid, ctx in unmatched:
        key = re.sub(r"[\d.]+", "#", ctx)[:40]     # one example per phrasing shape
        if key in seen:
            continue
        seen.add(key)
        print(f"  [{qid}] ...{ctx}...")
        shown += 1
        if shown >= a.show:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
