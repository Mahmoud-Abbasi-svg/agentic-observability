"""Does the verifier catch claims the instrument could not have supported?

    python test_net_verify.py

Two ways this can fail, and they are not symmetric.

A MISS is the dangerous one: an unsupportable claim passes, and the answer now carries a
verifier's endorsement it did not earn. That is worse than having no verifier, because the
operator stops checking.

A FALSE FLAG is merely annoying, but it has its own trap: if plain readings ("RTT is 13.8 ms")
get flagged as unsupportable, every honest answer sprouts warnings, and warnings that fire on
correct output are learned to be ignored - which converts the miss case into the default.

So the suite tests both directions, and the two load-bearing cases are:
  - a small claim on a NOISY path must be flagged
  - a measurement on the SAME path must not be

Writes only to a throwaway database.
"""
from __future__ import annotations

import os
import random
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netverify_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_memory                                                   # noqa: E402
import net_store                                                    # noqa: E402
import net_verify                                                   # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()["net_id"]
STEP = 60


def build(target: str, metric: str, values: list[float]) -> None:
    now = int(time.time())
    n = len(values)
    CONN.execute("DELETE FROM sample WHERE target=? AND metric=?", (target, metric))
    CONN.executemany(
        "INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) VALUES (?,?,?,?,?)",
        [(now - (n - i) * STEP, target, metric, float(v), NET)
         for i, v in enumerate(values)])
    CONN.commit()


def check(name: str, ok, detail: str = "") -> bool:
    # bool(), not the value: callers pass expressions like `a and b and c`, which
    # yield the last truthy operand rather than True. Suites accumulate with
    # `ok &= check(...)`, and `True & 6` is 0 - so every check printed PASS while the
    # suite reported failure. It can only raise a false alarm, never hide a real one,
    # but a suite that cries wolf gets ignored like any other.
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def verdicts(text: str) -> list[tuple[str, str]]:
    return [(f.claim.raw, f.verdict) for f in net_verify.verify(text)["findings"]]


def main() -> int:
    rng = random.Random(5)
    n = 600

    # quiet-path: 1% scatter, so small shifts are genuinely resolvable.
    build("quiet-path", "rtt_avg_ms", [20.0 * (1 + rng.gauss(0, 0.01)) for _ in range(n)])
    # noisy-path: 30% scatter. Nothing small can be seen here whatever window is chosen.
    build("noisy-path", "rtt_avg_ms", [40.0 * (1 + rng.gauss(0, 0.30)) for _ in range(n)])
    # A second metric on the quiet host, to prove metric attribution is not guessed.
    build("quiet-path", "handshake_avg_ms",
          [80.0 * (1 + rng.gauss(0, 0.25)) for _ in range(n)])

    ok = True
    q = net_memory.assess("quiet-path", "rtt_avg_ms")
    nz = net_memory.assess("noisy-path", "rtt_avg_ms")
    print(f"  (floors: quiet-path {q['mde'] and q['mde'] * 100:.0f}%, "
          f"noisy-path {nz['mde'] and nz['mde'] * 100:.0f}%)")

    # --- the miss case ------------------------------------------------------------------
    v = net_verify.verify("Latency to noisy-path rose 4% over the last hour.")
    ok &= check("a small claim on a noisy path is flagged UNSUPPORTABLE",
                not v["ok"] and v["findings"][0].verdict == "UNSUPPORTABLE",
                v["findings"][0].detail if v["findings"] else "no claim found at all")

    # --- the false-flag case ------------------------------------------------------------
    v = net_verify.verify("RTT to noisy-path is 13.8 ms with 0% packet loss.")
    ok &= check("a plain reading is NOT treated as a claim of change",
                v["n_claims"] == 0 and v["n_numbers"] >= 2,
                f"{v['n_claims']} claim(s) from {v['n_numbers']} number(s)")

    # --- a real change on a resolvable path must survive ---------------------------------
    v = net_verify.verify("Latency to quiet-path rose 15% this afternoon.")
    ok &= check("a large claim on a quiet path is SUPPORTED",
                v["ok"] and v["findings"][0].verdict == "SUPPORTED",
                v["findings"][0].detail if v["findings"] else "no claim found")

    # A claim below even a good floor is still unsupportable - the floor is the test, not
    # the path's reputation.
    v = net_verify.verify("Latency to quiet-path rose 0.5% this afternoon.")
    ok &= check("a sub-floor claim on a QUIET path is still flagged",
                not v["ok"], f"{[f.verdict for f in v['findings']]}")

    # --- attribution --------------------------------------------------------------------
    both = ("quiet-path looks normal. However latency to noisy-path increased by 6%.")
    f = net_verify.verify(both)["findings"]
    ok &= check("a claim is attributed to the nearest host named before it",
                len(f) == 1 and f[0].claim.target == "noisy-path",
                f"attributed to {f[0].claim.target!r}" if f else "no claim found")

    txt = "The handshake time to quiet-path rose 6%."
    f = net_verify.verify(txt)["findings"]
    ok &= check("the metric is taken from the sentence, not defaulted to RTT",
                len(f) == 1 and f[0].claim.metric == "handshake_avg_ms",
                f"metric {f[0].claim.metric!r}" if f else "no claim found")

    # handshake_avg_ms has 25% scatter while rtt_avg_ms has 1%; a 6% claim is therefore
    # unsupportable on the handshake but fine on RTT. If metric attribution were broken this
    # pair would come out identical, which is exactly the bug worth catching.
    a = net_verify.verify("The handshake time to quiet-path rose 6%.")["findings"][0]
    b = net_verify.verify("The latency to quiet-path rose 6%.")["findings"][0]
    ok &= check("the same magnitude gets different verdicts on different metrics",
                a.verdict != b.verdict, f"handshake={a.verdict}, rtt={b.verdict}")

    # --- honesty about coverage ----------------------------------------------------------
    v = net_verify.verify("Something rose 9% somewhere.")
    ok &= check("an unattributable claim is reported, not silently passed",
                v["unattributed"] == 1 and v["findings"][0].verdict == "UNKNOWN TARGET")

    v = net_verify.verify("Latency to quiet-path rose 15%, and loss is 0.2%.")
    ok &= check("the report states numbers seen as well as claims checked",
                v["n_numbers"] > v["n_claims"],
                f"{v['n_claims']} claim(s) of {v['n_numbers']} number(s)")

    # --- absolute units ------------------------------------------------------------------
    # 0.1 ms on a 20 ms baseline is 0.5%, below the floor; the module must do that division
    # rather than compare 0.1 against a percentage.
    v = net_verify.verify("Latency to quiet-path rose by 0.1 ms.")
    ok &= check("a millisecond claim is converted using the baseline before comparison",
                v["findings"] and v["findings"][0].verdict == "UNSUPPORTABLE",
                v["findings"][0].detail if v["findings"] else "no claim found")

    # --- a path with no history must not produce a confident verdict ---------------------
    v = net_verify.verify("Latency to quiet-path rose 20%.", baseline_days=0.001)
    ok &= check("with no usable history the verdict is NO FLOOR, not SUPPORTED",
                v["findings"] and v["findings"][0].verdict in ("NO FLOOR", "UNSUPPORTABLE"),
                f"{v['findings'][0].verdict}" if v["findings"] else "no claim found")

    # --- what the first real answer exposed ------------------------------------------------
    # Models write typographic characters. The first live answer contained a U+2212 minus and
    # U+2192 arrows; nothing matched, and the report announced "no claims found" over an answer
    # full of them - the miss case, in production, on day one.
    v = net_verify.verify("Latency to noisy-path fell −15% overnight.")
    ok &= check("a Unicode minus sign is read as a signed percentage",
                v["n_claims"] == 1, f"{v['n_claims']} claim(s)")

    # 40.0 -> 38.0 is 5%, under noisy-path's 20% floor. An earlier version of this case used
    # 40.0 -> 30.0 and expected UNSUPPORTABLE, but that is a 25% change and SUPPORTED was the
    # right answer - the fixture was wrong, not the module.
    v = net_verify.verify("noisy-path median went 40.0 → 38.0 ms.")
    ok &= check("an arrow transition is read as a claim of change",
                v["n_claims"] == 1 and v["findings"][0].verdict == "UNSUPPORTABLE",
                f"{[f.verdict for f in v['findings']]}")

    v = net_verify.verify("quiet-path went from 20 ms to 30 ms.")
    ok &= check("a 'from X to Y' transition is read as a claim of change",
                v["n_claims"] == 1 and v["findings"][0].verdict == "SUPPORTED",
                f"{[f.verdict for f in v['findings']]}")

    # Clock times contain arrows in exactly the same shape and must not become claims.
    v = net_verify.verify("noisy-path had a gap 13:27 → 16:26 (3.0 h).")
    ok &= check("a clock-time range is NOT read as a claim of change",
                v["n_claims"] == 0, f"{v['n_claims']} claim(s)")

    # The same claim written two ways must get the same verdict, or the report is arbitrary.
    a = net_verify.verify("quiet-path latency went 20.0 → 16.0 ms.")["findings"][0]
    b = net_verify.verify("quiet-path latency fell −20%.")["findings"][0]
    ok &= check("the same shift stated two ways gets the same verdict",
                a.verdict == b.verdict, f"arrow={a.verdict}, percent={b.verdict}")

    # The floor depends on the window, so one window is not grounds for "no window could".
    mde, r, h = net_verify.best_floor("noisy-path", "rtt_avg_ms", 7.0)
    single = net_memory.assess("noisy-path", "rtt_avg_ms", 2.0, 7.0)["mde"]
    ok &= check("the floor used is the best across windows, not one default",
                mde is not None and single is not None and mde <= single,
                f"best {mde * 100:.0f}% at {h:g} h vs {single * 100:.0f}% at the 2 h default")

    v = net_verify.verify("Latency to quiet-path rose 15%.")
    ok &= check("the empty-result wording does not claim the answer was cleared",
                "all read as measurements" not in net_verify.format_report(
                    net_verify.verify("RTT to quiet-path is 13.8 ms.")))

    # --- "resolution" is what the instrument has, not what DNS does ----------------------
    # Live: "**Resolution.** This history can only resolve shifts of about 35% or larger.
    # Tonight's -41% clears that bar" was checked against the DNS query floor, because the
    # word list mapped "resolution" to query_ms. The prompt teaches the agent that word in
    # the instrument sense, so the verifier was contradicting its own vocabulary.
    f = net_verify.verify("Latency to quiet-path is down. Resolution: this history can only "
                          "resolve shifts of about 35% or larger. Tonight's -41% clears that "
                          "bar.")["findings"]
    ok &= check("'resolution' in the instrument sense does not switch the metric to DNS",
                f and all(x.claim.metric == "rtt_avg_ms" for x in f),
                f"metrics {[x.claim.metric for x in f]}")
    f = net_verify.verify("Name resolution at quiet-path slowed 30%.")["findings"]
    g = net_verify.verify("quiet-path resolves the name 30% slower.")["findings"]
    ok &= check("resolution bound to a NAME still means the DNS metric",
                f and f[0].claim.metric == "query_ms" and g and g[0].claim.metric == "query_ms",
                f"{[x.claim.metric for x in f + g]}")

    # --- markdown emphasis and "below baseline" ------------------------------------------
    # Live: "The recent window is 30.8% *below* baseline, but that shift is not
    # distinguishable from noise" - and the verifier reported no claims at all. Two misses
    # in one sentence: the asterisks between the number and the word, and "below baseline"
    # not being a change verb. Both fixed; the sentence is a refuted claim, so AGREED.
    v = net_verify.verify("The recent window to noisy-path is 8.4% *below* baseline, but "
                          "that shift is **not distinguishable from noise** (p=0.36).")
    ok &= check("a claim written with markdown emphasis is still found, and its own "
                "refutation still read", v["n_claims"] == 1
                and v["findings"][0].verdict == "AGREED",
                f"{v['n_claims']} claim(s) {[f.verdict for f in v['findings']]}")

    # --- every probe type on one host -----------------------------------------------------
    # Live: asked "is 1.1.1.1 slower than usual", the agent answered from ping alone - "no,
    # if anything faster" - while the TCP handshake and DNS query to the same host were
    # alerting. detect_change(metric="all") puts every probe type side by side.
    vals = [50.0 * (1 + rng.gauss(0, 0.05)) for _ in range(n)]
    build("quiet-path", "query_ms", vals[:-120] + [v * 1.6 for v in vals[-120:]])
    t = net_memory.detect_change("quiet-path", "all")
    ok &= check("metric='all' lists every probe type on the host",
                all(m in t for m in ("rtt_avg_ms", "handshake_avg_ms", "query_ms")))
    ok &= check("and separates the one that moved from the ones that did not",
                "moved beyond their own floor: query_ms (+" in t
                and "within their own noise: rtt_avg_ms" in t
                and "probe types DISAGREE" in t, [l for l in t.splitlines() if "moved" in l][0])

    # --- refuted claims are agreement, not contradiction -----------------------------------
    # Found on the first change-question answer: the agent wrote "a 5% increase would be
    # completely undetectable here", which says exactly what the floor says, and the verifier
    # reported it as a claim the answer could not support. A warning on a correct answer is
    # the failure that makes every later warning ignorable.
    v = net_verify.verify("A 4% increase on noisy-path would be completely undetectable here.")
    ok &= check("a magnitude the answer calls undetectable is AGREED, not flagged",
                v["ok"] and v["findings"][0].verdict == "AGREED",
                f"{[f.verdict for f in v['findings']]}")

    v = net_verify.verify("This is not an all-clear on a 4% rise on noisy-path.")
    ok &= check("a magnitude denied just before it is AGREED, not flagged",
                v["ok"] and v["findings"][0].verdict == "AGREED",
                f"{[f.verdict for f in v['findings']]}")

    v = net_verify.verify("Latency to noisy-path rose 4% since yesterday.")
    ok &= check("the same magnitude ASSERTED is still UNSUPPORTABLE",
                not v["ok"] and v["findings"][0].verdict == "UNSUPPORTABLE",
                f"{[f.verdict for f in v['findings']]}")

    # "noise" contains "no". Without word boundaries the negation test matches every sentence
    # that mentions the noise floor, and nothing is ever flagged again.
    ok &= check("'noise' does not count as a negation",
                not net_verify._is_refuted("noisy-path latency rose 4% in normal noise", "4%"))

    # --- sentence boundaries in a domain full of dots --------------------------------------
    # Splitting on a bare "." cut "median 12.0 vs baseline 12.6, a -4.8% shift against a 7.9%
    # noise floor" down to the fragment "6, a -4". The refutation sat outside the fragment, so
    # a claim the answer had explicitly denied was reported as unsupported. Decimals and
    # dotted-quad addresses are everywhere in this text, so this is not an edge case.
    real = ("For what it is worth, noisy-path itself shows no distinguishable change either: "
            "recent median 12.0 vs baseline 12.6, a −4.8% shift against a 7.9% noise floor "
            "(p=0.249), and this history could only resolve shifts of about 10% or larger.")
    f = net_verify.verify(real)["findings"]
    ok &= check("a decimal point does not end a sentence",
                f and "noise floor" in f[0].claim.context,
                f"context: {' '.join(f[0].claim.context.split())[:70]!r}" if f else "no claim")
    ok &= check("a claim the sentence itself refutes is AGREED, not flagged",
                f and f[0].verdict == "AGREED",
                f"{[x.verdict for x in f]}")

    f = net_verify.find_claims("Latency to 1.1.1.1 is down 4% vs baseline — not "
                               "distinguishable from noise (p=0.31).")
    ok &= check("a dotted-quad address does not end a sentence",
                f and "distinguishable" in f[0].context,
                f"context: {' '.join(f[0].context.split())[:70]!r}" if f else "no claim")

    # --- the report itself ---------------------------------------------------------------
    text = "Latency to noisy-path rose 4%."
    report = net_verify.format_report(net_verify.verify(text))
    ok &= check("the report names the floor that defeats the claim",
                "%" in report and "floor" in report.lower())
    ok &= check("annotate keeps the original answer intact",
                net_verify.annotate(text, net_verify.verify(text)).startswith(text))

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
