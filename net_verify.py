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


def _pct(x: float) -> str:
    """Percentages small enough to round to zero must not print as '0%' - the report would be
    arguing against a claim of nothing."""
    v = x * 100.0
    return f"{v:.1f}%" if v < 10 else f"{v:.0f}%"


class Claim(NamedTuple):
    raw: str                 # the exact phrase matched, for quoting back
    pos: int                 # offset in the answer, so findings can be shown in order
    target: str
    metric: str
    fraction: Optional[float]   # magnitude as a fraction of baseline; None until resolved
    unit: str                   # "%" or "ms"
    value: float                # as written
    context: str = ""           # the sentence it sits in, for telling assertion from refusal


class Finding(NamedTuple):
    claim: Claim
    verdict: str             # SUPPORTED | UNSUPPORTABLE | AGREED | NO FLOOR | UNKNOWN TARGET
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


# Models write typographic characters, not ASCII. The first real answer this module saw
# contained "a MINUS-SIGN 20% shift" using U+2212, which `[+-]` cannot match, and the report
# then said "no claims of change found" over an answer full of them. Mapped 1:1 so that
# character offsets - and therefore host attribution - stay correct.
_DASHES = {0x2212: "-", 0x2013: "-", 0x2014: "-", 0x2010: "-", 0x2011: "-"}

# A sentence ends only where punctuation is followed by space or end of text. "12.6" and
# "1.1.1.1" must not be treated as three sentences each.
_SENT_END = re.compile(r"[.!?](?=\s|$)")

# Two numbers and a transition between them. This is how a model usually states a change it
# actually measured ("median 2.00 -> 1.60 ms"), and it carries the magnitude implicitly, so
# no baseline lookup is needed: the shift is (b - a) / a.
_PAIR_PATTERNS = [
    # "went from 13 ms to 15 ms", "from 2.0 to 1.6"
    r"from\s+(\d+(?:\.\d+)?)\s*(?:ms|%|percent)?\s+to\s+(\d+(?:\.\d+)?)\s*(?:ms|%|percent)?",
    # "2.00 -> 1.60 ms". The guards keep clock times out: in "13:27 -> 16:26" the left number
    # is preceded by a colon and the right one followed by one, so neither side can match.
    r"(?<![\d:.])(\d+(?:\.\d+)?)\s*(?:→|->)\s*(\d+(?:\.\d+)?)(?![\d:])",
]

# "20-40%" asserts a range whose LOWER end is part of the claim, so the smaller number is what
# gets checked. If the floor sits above it, the claim is partly indefensible and should be said.
_RANGE_PATTERN = r"(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)\s*(?:%|percent)"


def find_claims(text: str, targets: Optional[list[str]] = None) -> list[Claim]:
    """Every assertion of change carrying a magnitude."""
    targets = known_targets() if targets is None else targets
    text = text.translate(_DASHES)
    out: list[Claim] = []
    seen: set[int] = set()

    def add(pos: int, raw: str, frac: Optional[float], shown: float, unit: str) -> None:
        if any(abs(pos - s) < 4 for s in seen):
            return
        seen.add(pos)
        # The sentence around the claim, which is what distinguishes asserting a magnitude
        # from denying one.
        #
        # Splitting on a bare "." is wrong in this domain and was measurably wrong: network
        # text is full of decimals and dotted-quad addresses, so "median 12.0 vs baseline
        # 12.6, a -4.8% shift against a 7.9% noise floor" was cut down to the fragment
        # "6, a -4". The refutation was outside the fragment, so a claim the answer had
        # explicitly denied got flagged as unsupported. A sentence ends at ".!?" only when
        # whitespace or the end of the text follows.
        lo, hi = 0, len(text)
        for m in _SENT_END.finditer(text, 0, pos):
            lo = m.end()
        m = _SENT_END.search(text, pos)
        if m:
            hi = m.start()
        nl = text.rfind("\n", 0, pos)
        if nl + 1 > lo:
            lo = nl + 1
        nl = text.find("\n", pos)
        if 0 <= nl < hi:
            hi = nl
        out.append(Claim(raw=raw.strip(), pos=pos,
                         target=_attribute(text, pos, targets),
                         metric=_metric_for(text, pos),
                         fraction=frac, unit=unit, value=shown,
                         context=text[lo:hi].strip()))

    # Ranges and pairs run FIRST, so that "20-40%" is read as a range rather than letting the
    # signed-percentage pattern below strip "-40%" out of the middle of it.
    for m in re.finditer(_RANGE_PATTERN, text, re.I):
        lo, hi = sorted((float(m.group(1)), float(m.group(2))))
        add(m.start(), m.group(0), lo / 100.0, lo, "%")

    for pat in _PAIR_PATTERNS:
        for m in re.finditer(pat, text, re.I):
            a, b = float(m.group(1)), float(m.group(2))
            if a <= 0 or a == b:
                continue
            add(m.start(), m.group(0), abs(b - a) / a, abs(b - a) / a * 100.0, "ratio")

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
            value = abs(float(m.group(1)))
            unit = "ms" if m.group(2).lower().startswith("m") else "%"
            add(m.start(), m.group(0), value / 100.0 if unit == "%" else None, value, unit)
    return sorted(out, key=lambda c: c.pos)


def count_numbers(text: str) -> int:
    """Every number with a unit, claim or not. The denominator for honest coverage."""
    return len(re.findall(r"\d+(?:\.\d+)?\s*(?:%|percent|ms|milliseconds?)", text, re.I))


# --------------------------------------------------------------------------- verification

# An answer that says "a 5% rise would be undetectable here" is AGREEING with the floor, not
# claiming a 5% rise. Flagging it puts a warning on a correct answer - and warnings that fire
# on correct output get ignored, which is how the real ones stop being read.
#
# Demonstrated, not hypothetical: on the first change-question answer the agent wrote "it is
# *not* an all-clear on a 5% rise" and "a 5% increase ... would be completely undetectable",
# and both were reported as claims the answer could not support.
_LIMIT_WORDS = re.compile(
    r"undetectab|invisibl|unresolvab|indistinguishab|too small|no better than|noise floor|"
    # Phrasings the agent actually used, added after they were missed on real answers:
    # "shows no distinguishable change", "not distinguishable from noise", "within noise".
    r"n[o']?t? distinguishab|no distinguishable|within (?:the )?noise|not significant|"
    r"only resolve|could not resolve|"
    r"below (?:the |its |that )?(?:floor|noise|threshold|resolution)|cannot (?:be )?"
    r"(?:seen|resolved|detected|distinguished)|would (?:not|n't) (?:be )?"
    r"(?:seen|detectable|visible|resolvable)|not (?:be )?(?:detectable|resolvable|measurable)|"
    r"beyond (?:what|the) .{0,20}resolv", re.I)
# Word boundaries are load-bearing: without them "no" matches inside "noise" and "normal",
# so every sentence merely mentioning the noise floor would count as a denial and
# nothing would ever be flagged again.
# Word boundaries are load-bearing. "noisy-path" contains "no", "normal" contains "no", and
# "noise" contains "no" - so without them every sentence mentioning the noise floor counts as
# a denial and nothing is ever flagged again. That is a silent, total disabling of the module,
# which is why it has its own test.
_NEGATION = re.compile(r"\b(?:not|never|cannot|can't|couldn't|wouldn't|no)\b|\*not\*", re.I)


def _is_refuted(context: str, raw: str) -> bool:
    """Is this magnitude being denied or bounded rather than asserted?"""
    if not context:
        return False
    if _LIMIT_WORDS.search(context):
        return True
    at = context.find(raw)
    if at < 0:
        return False
    return bool(_NEGATION.search(context[max(0, at - 60):at]))


# The floor depends on the comparison window, so checking ONE window and then saying "no
# window could have seen this" is an overclaim - the exact move this project exists to stop.
# It was caught on the first real answer: this module reported a 75% floor from its 2 h default
# while the agent had correctly measured 35% over 6 h, and flagged a claim the agent could in
# fact defend. So several windows are tried and the BEST (smallest) floor is used. Being
# generous to the agent is deliberate: it means every surviving flag is unarguable.
_FLOOR_WINDOWS = (1.0, 2.0, 6.0, 12.0, 24.0)
_floor_cache: dict[tuple, tuple] = {}


def best_floor(target: str, metric: str, baseline_days: float) -> tuple:
    """(smallest resolvable shift, the assessment that produced it, its window in hours).

    Returns (None, r, 0.0) when a floor exists nowhere - r is then the last assessment seen,
    for its reason text."""
    key = (target, metric, baseline_days)
    if key in _floor_cache:
        return _floor_cache[key]
    best, best_r, best_h, last = None, None, 0.0, None
    for h in _FLOOR_WINDOWS:
        r = net_memory.assess(target, metric, h, baseline_days)
        last = r
        if r["status"] != "ok":
            continue
        m = r.get("mde")
        if m is not None and (best is None or m < best):
            best, best_r, best_h = m, r, h
    out = (best, best_r if best_r is not None else last, best_h)
    _floor_cache[key] = out
    return out


def verify_claim(c: Claim, recent_hours: float = 2.0, baseline_days: float = 7.0) -> Finding:
    if not c.target:
        return Finding(c, "UNKNOWN TARGET", None,
                       "no host could be attributed to this number, so no floor applies to it")

    mde, r, window_h = best_floor(c.target, c.metric, baseline_days)
    r = r or {"status": "insufficient"}

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

    if mde is None:
        return Finding(c, "UNSUPPORTABLE", None,
                       f"{c.target}/{c.metric} cannot resolve any shift on the tested grid "
                       f"(up to 200%) at any window tried; a {_pct(frac)} claim is not "
                       f"defensible")

    # Tolerance, not tidiness: "2.00 -> 1.60" computes 0.19999999999999998 while the same claim
    # written "-20%" gives exactly 0.20. Without this, one sentence gets two verdicts depending
    # on how the author happened to phrase it, which would make the whole report untrustworthy.
    if frac < mde - 1e-9:
        if _is_refuted(c.context, c.raw):
            return Finding(c, "AGREED", mde,
                           f"the answer already treats this as unresolvable "
                           f"({_pct(mde)} floor); verifier and answer agree")
        return Finding(c, "UNSUPPORTABLE", mde,
                       f"{c.target}/{c.metric} resolves no better than {_pct(mde)} at "
                       f"its most favourable window ({window_h:g} h); a {_pct(frac)} "
                       f"claim is below that floor")

    return Finding(c, "SUPPORTED", mde,
                   f"{_pct(frac)} is above the {_pct(mde)} floor "
                   f"{c.target}/{c.metric} reaches at {window_h:g} h")


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
        # NOT "all read as measurements". The first real answer this ran on contained a -20%
        # shift written with a Unicode minus sign, matched nothing, and got reported as though
        # it had been examined and cleared. An empty result means the patterns found nothing,
        # which is a statement about the patterns, not about the answer.
        return (f"VERIFIER: no claims of change matched a known pattern "
                f"({v['n_numbers']} number(s) present). Claims are found by pattern, so this "
                f"is not evidence the answer makes none.")

    lines = []
    for f in v["findings"]:
        mark = {"SUPPORTED": "ok", "UNSUPPORTABLE": "!!", "NO FLOOR": "??",
                "UNKNOWN TARGET": "??", "AGREED": "=="}[f.verdict]
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
