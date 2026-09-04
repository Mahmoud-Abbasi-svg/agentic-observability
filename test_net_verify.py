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


def check(name: str, ok: bool, detail: str = "") -> bool:
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
