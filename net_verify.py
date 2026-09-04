"""Check the agent's numbers against what the instrument could actually resolve.

    python net_verify.py "latency to 1.1.1.1 rose 4% overnight"
    python net_verify.py --file answer.txt
    echo "..." | python net_verify.py

THE PROBLEM THIS EXISTS TO FIX

`net_memory` can already say that a path's smallest detectable shift is 75%. The SYSTEM prompt
in `net_agent.py` already tells the model never to let "I couldn't see it" read as "it didn't
happen". But a prompt is a request, not a guarantee: nothing stops the model asserting a 4%
rise on a path that cannot resolve anything below 75%, and such an answer is *more* damaging
than silence because it is specific, plausible and wrong.

So the check is moved out of the prompt and into code. Every claim of CHANGE the agent makes
is re-derived against that path's own noise floor before the answer is shown.

WHAT IS AND IS NOT CHECKABLE - the distinction the whole module turns on

    "RTT to 1.1.1.1 is 13.8 ms"      a READING. The instrument reported it. Not checked.
    "RTT to 1.1.1.1 rose 4%"         an INFERENCE about a difference between two windows.
                                     The noise floor governs whether that difference could
                                     have been seen at all. Checked.

Conflating the two would flag every honest measurement as unsupportable, so only claims
carrying an explicit change verb or a signed magnitude are considered.

WHY THE MAGNITUDE IS COMPARED TO THE FLOOR, NOT TO THE MEASURED SHIFT

The agent may be talking about a window this module cannot know (`overnight`, `since the
meeting`). Comparing its number against a shift recomputed over some default window would
produce disagreements that are artefacts of window choice, not errors by the agent.

The floor is different: it is a property of the path's noise, near enough window-independent,
and it supports a claim no window can rescue - *no* comparison over this data could have
resolved something that small. That is a narrow check, and narrow is the point: every flag it
raises is one the agent genuinely cannot defend.

THIS MODULE IS NOT A COMPLETE READER OF ENGLISH, AND SAYS SO

Claims are found with regular expressions. Some phrasings will be missed. A verifier that
quietly misses claims is worse than no verifier, because it converts "unchecked" into "looks
checked" - so every report states how many numbers it saw versus how many it could attribute,
and `unattributed` is printed rather than hidden.
"""
from __future__ import annotations

import argparse
import re
import sys
from typing import NamedTuple, Optional

import net_memory
import net_store

# Words that turn a number into an assertion about a DIFFERENCE. Without one of these (or an
# explicit sign) a number is treated as a reading and left alone.
RISE = r"rose|rise|risen|up|increased?|climbed|grew|jumped|higher|worse|worsened|degraded|slower"
FALL = r"fell|fall|fallen|down|decreased?|dropped|declined|shrank|lower|better|improved|faster"
CHANGE = rf"{RISE}|{FALL}|changed|shifted|moved|differs?|deviated"

# Which stored metric a phrase is talking about. Order matters: the first match wins, so the
# more specific words come first ("handshake time" must not be read as generic latency).
METRIC_WORDS = [
    (r"handshake", "handshake_avg_ms"),
    (r"\bconnect(?:ion)? time\b|\bconnect_ms\b", "connect_ms"),
    (r"\bdns\b|resolver|resolution|\bquery\b|lookup", "query_ms"),
    (r"http|response time|page load|\bttfb\b", "response_ms"),
    (r"packet loss|\bloss\b|dropped packets", "loss_pct"),
    (r"reachab|availab|uptime|packet delivery", "reachable"),
    (r"success rate", "success_rate"),
    (r"latency|\brtt\b|round[- ]trip|ping time|delay", "rtt_avg_ms"),
]
DEFAULT_METRIC = "rtt_avg_ms"

# A claim below this is flagged even when a floor cannot be built, because a sub-1% assertion
# about network latency is not defensible on any consumer path.
IMPLAUSIBLE_ANY_PATH = 0.01


class Claim(NamedTuple):
    raw: str                 # the exact phrase matched, for quoting back
    pos: int                 # offset in the answer, so findings can be shown in order
    target: str
    metric: str
    fraction: Optional[float]   # magnitude as a fraction of baseline; None until resolved
    unit: str                   # "%" or "ms"
    value: float                # as written


class Finding(NamedTuple):
    claim: Claim
    verdict: str             # SUPPORTED | UNSUPPORTABLE | NO FLOOR | UNKNOWN TARGET
    floor: Optional[float]
    detail: str


# --------------------------------------------------------------------------- extraction

def known_targets(days: float = 30.0) -> list[str]:
    """Targets the database has actually seen, longest first so '10.50.16.1' is preferred
    over a substring of it."""
    conn = net_memory.conn()
    rows = conn.execute("SELECT DISTINCT target FROM sample").fetchall()
    return sorted((r[0] for r in rows), key=len, reverse=True)


def _gateway() -> str:
    try:
        return net_store.network_identity().get("gateway") or ""
    except Exception:
        return ""


def _attribute(text: str, pos: int, targets: list[str]) -> str:
    """Which host is this claim about? The nearest target named BEFORE it.

    Prose puts the subject first ('latency to 1.1.1.1 rose 4%'), so scanning backwards from the
    number is right far more often than scanning forwards. When nothing precedes it, the first
    target mentioned anywhere is used - a one-host answer names its host once, at the top.
    """
    before = text[:pos].lower()
    best, best_at = "", -1
    for t in targets:
        at = before.rfind(t.lower())
        if at > best_at:
            best, best_at = t, at
    if best_at >= 0:
        return best
    gw = _gateway()
    if gw and re.search(r"\bgateway\b|\brouter\b|\bdefault gw\b", before):
        return gw
    for t in targets:                       # fall forward: first host named anywhere
        if t.lower() in text.lower():
            return t
    return ""


def _metric_for(text: str, pos: int) -> str:
    """The metric word closest before the claim; window-limited so a metric named three
    sentences ago does not capture an unrelated number."""
    window = text[max(0, pos - 240):pos].lower()
    best, best_at = DEFAULT_METRIC, -1
    for pattern, metric in METRIC_WORDS:
        for m in re.finditer(pattern, window):
            if m.start() > best_at:
                best, best_at = metric, m.start()
    return best


def find_claims(text: str, targets: Optional[list[str]] = None) -> list[Claim]:
    """Every assertion of change carrying a magnitude."""
    targets = known_targets() if targets is None else targets
    out: list[Claim] = []
    seen: set[int] = set()

    patterns = [
        # "rose 15%", "up by 4 %", "degraded 12%"
        rf"(?:{CHANGE})\s+(?:by\s+)?(\d+(?:\.\d+)?)\s*(%|percent)",
        # "15% higher", "4 % slower"
        rf"(\d+(?:\.\d+)?)\s*(%|percent)\s+(?:{CHANGE})",
        # "a +25% shift", "-3.5%"
        r"([+-]\d+(?:\.\d+)?)\s*(%|percent)",
        # "rose 0.6 ms", "up by 12ms"  - an explicit change verb is required, so a plain
        # reading like "RTT is 13.8 ms" is never captured here.
        rf"(?:{CHANGE})\s+(?:by\s+)?(\d+(?:\.\d+)?)\s*(ms|milliseconds?)",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.I):
            if any(abs(m.start() - s) < 4 for s in seen):
                continue                       # same number caught by two patterns
            seen.add(m.start())
            value = abs(float(m.group(1)))
            unit = "ms" if m.group(2).lower().startswith("m") else "%"
            out.append(Claim(
                raw=m.group(0).strip(), pos=m.start(),
                target=_attribute(text, m.start(), targets),
                metric=_metric_for(text, m.start()),
                fraction=value / 100.0 if unit == "%" else None,
                unit=unit, value=value))
    return sorted(out, key=lambda c: c.pos)


def count_numbers(text: str) -> int:
    """Every number with a unit, claim or not. The denominator for honest coverage."""
    return len(re.findall(r"\d+(?:\.\d+)?\s*(?:%|percent|ms|milliseconds?)", text, re.I))


# --------------------------------------------------------------------------- verification

def verify_claim(c: Claim, recent_hours: float = 2.0, baseline_days: float = 7.0) -> Finding:
    if not c.target:
        return Finding(c, "UNKNOWN TARGET", None,
                       "no host could be attributed to this number, so no floor applies to it")

    r = net_memory.assess(c.target, c.metric, recent_hours, baseline_days)

    if r["status"] != "ok":
        if c.fraction is not None and c.fraction < IMPLAUSIBLE_ANY_PATH:
            return Finding(c, "UNSUPPORTABLE", None,
                           f"claims {c.value:g}% on {c.target}/{c.metric}, and no floor could "
                           f"be built to defend it. A shift this small is below what any "
                           f"consumer path resolves")
        return Finding(c, "NO FLOOR", None,
                       f"{c.target}/{c.metric}: no noise floor available, so this number can "
                       f"be neither supported nor refuted here")

    # An absolute claim becomes comparable once divided by the baseline it is a change from.
    frac = c.fraction
    if frac is None:
        base = abs(r.get("baseline_median") or 0.0)
        if base <= 0:
            return Finding(c, "NO FLOOR", None,
                           f"{c.target}/{c.metric}: baseline is zero, cannot express "
                           f"{c.value:g} ms as a relative shift")
        frac = c.value / base

    mde = r.get("mde")
    if mde is None:
        return Finding(c, "UNSUPPORTABLE", None,
                       f"{c.target}/{c.metric} cannot resolve any shift on the tested grid "
                       f"(up to 200%); a {frac * 100:.0f}% claim is not defensible")

    if frac < mde:
        return Finding(c, "UNSUPPORTABLE", mde,
                       f"{c.target}/{c.metric} resolves no better than {mde * 100:.0f}%; a "
                       f"{frac * 100:.0f}% claim is below the floor and could not have been "
                       f"seen whatever window was used")

    return Finding(c, "SUPPORTED", mde,
                   f"{frac * 100:.0f}% is above the {mde * 100:.0f}% floor for "
                   f"{c.target}/{c.metric}")


def verify(text: str, recent_hours: float = 2.0, baseline_days: float = 7.0) -> dict:
    claims = find_claims(text)
    findings = [verify_claim(c, recent_hours, baseline_days) for c in claims]
    bad = [f for f in findings if f.verdict == "UNSUPPORTABLE"]
    return {
        "findings": findings,
        "n_numbers": count_numbers(text),
        "n_claims": len(claims),
        "unattributed": sum(1 for f in findings if f.verdict == "UNKNOWN TARGET"),
        "unsupportable": bad,
        "ok": not bad,
    }


# --------------------------------------------------------------------------- output

def format_report(v: dict) -> str:
    if not v["findings"]:
        return (f"VERIFIER: no claims of change found "
                f"({v['n_numbers']} number(s) in the text, all read as measurements)")

    lines = []
    for f in v["findings"]:
        mark = {"SUPPORTED": "ok", "UNSUPPORTABLE": "!!", "NO FLOOR": "??",
                "UNKNOWN TARGET": "??"}[f.verdict]
        lines.append(f"  {mark}  {f.claim.raw!r:<28} {f.verdict:<15} {f.detail}")

    head = (f"VERIFIER: {v['n_claims']} claim(s) of change checked against the noise floor "
            f"({v['n_numbers']} number(s) seen in total")
    head += f", {v['unattributed']} not attributable to a host)" if v["unattributed"] else ")"

    tail = ""
    if v["unsupportable"]:
        tail = (f"\n  {len(v['unsupportable'])} claim(s) BELOW the floor. The instrument could "
                f"not have seen a change that small,\n  so the answer asserts more than the "
                f"measurements support.")
    return head + "\n" + "\n".join(lines) + tail


def annotate(text: str, v: dict) -> str:
    """The answer with the verifier's report appended. Nothing is deleted - an operator is
    entitled to the model's reasoning; they are just not entitled to see it unchallenged."""
    return text.rstrip() + "\n\n" + "-" * 70 + "\n" + format_report(v)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Check an answer's claims of change against each path's noise floor.")
    ap.add_argument("answer", nargs="*", help="the text to check; omit to read stdin")
    ap.add_argument("--file", help="read the answer from a file")
    ap.add_argument("--recent-hours", type=float, default=2.0)
    ap.add_argument("--days", type=float, default=7.0)
    ap.add_argument("--quiet", action="store_true", help="print only if something is wrong")
    a = ap.parse_args()

    if a.file:
        with open(a.file, encoding="utf-8") as f:
            text = f.read()
    elif a.answer:
        text = " ".join(a.answer)
    else:
        text = sys.stdin.read()
    if not text.strip():
        print("nothing to check")
        return 0

    v = verify(text, a.recent_hours, a.days)
    if not (a.quiet and v["ok"]):
        print(format_report(v))
    return 1 if v["unsupportable"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
