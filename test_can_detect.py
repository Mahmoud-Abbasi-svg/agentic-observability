"""Does can_detect name the RIGHT limit?

    python test_can_detect.py

Saying "I cannot resolve that" is only useful if the reason is correct, because each reason has
a different remedy and they do not substitute for one another:

    INSTRUMENT-bound  -> more sampling will never help; you need a finer measurement
    STATISTICS-bound  -> more sampling is exactly what helps

An agent that confuses the two sends an operator to collect a week of data that cannot possibly
answer their question, or to swap instruments when the one they have is fine. So the test is
not "does it refuse" but "does it refuse for the right reason".

Three paths are constructed where the binding limit is known by construction, and a fourth
where the answer should simply be yes.

Writes only to a throwaway database.
"""
from __future__ import annotations

import os
import random
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="candetect_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_memory                                                    # noqa: E402
import net_store                                                     # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()["net_id"]
STEP = 60


def build(target: str, values: list[float]) -> None:
    now = int(time.time())
    n = len(values)
    CONN.execute("DELETE FROM sample WHERE target=?", (target,))
    CONN.executemany(
        "INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) VALUES (?,?,?,?,?)",
        [(now - (n - i) * STEP, target, "rtt_avg_ms", float(v), NET)
         for i, v in enumerate(values)])
    CONN.commit()


def main() -> int:
    rng = random.Random(11)
    n = 600

    # coarse-lan: a 2 ms gateway, genuinely stable underneath, measured by an instrument whose
    # smallest step is 0.5 ms - which is what `ping` gives when it averages two whole-
    # millisecond replies. One step is 25% of the baseline, so a 10% change cannot be
    # represented at all and no amount of extra sampling can help. The tool must say
    # INSTRUMENT and must NOT offer a sampling remedy.
    build("coarse-lan", [round((2.0 + rng.gauss(0, 0.35)) * 2) / 2 for _ in range(n)])

    # noisy-wan: continuous values (no lattice), but the path swings widely. The instrument is
    # blameless; the path is the problem, and the tool must say STATISTICS.
    build("noisy-wan", [40.0 * (1 + rng.gauss(0, 0.30)) + rng.random() * 1e-3
                        for _ in range(n)])

    # quiet-wan: continuous and stable. A 10% question should simply be answerable.
    build("quiet-wan", [40.0 * (1 + rng.gauss(0, 0.01)) + rng.random() * 1e-3
                        for _ in range(n)])

    # The asked-about shift for noisy-wan is well below anything a window of this history
    # could reach. An earlier version used 10%, which sat right on the floor and flipped to
    # YES the moment the default window widened - a test that measures the window size rather
    # than the behaviour under test.
    cases = [
        ("coarse-lan", 10.0, "INSTRUMENT", False),
        ("noisy-wan", 3.0, "STATISTICS", False),
        ("quiet-wan", 10.0, None, True),
        ("noisy-wan", 200.0, None, True),
    ]

    ok = True
    for target, want, expect_limit, expect_yes in cases:
        text = net_memory.can_detect(target, "rtt_avg_ms", want)
        binding = next((l.split(":")[1].split(",")[0].strip()
                        for l in text.splitlines() if "BINDING LIMIT" in l), "none")
        yes = "VERDICT: YES" in text
        good = (yes == expect_yes) and (expect_limit is None or binding == expect_limit)
        ok &= good
        print(f"  {'PASS' if good else 'FAIL'}  {target:<12} {want:>5.0f}%  "
              f"binding={binding:<11} verdict={'YES' if yes else 'NO':<3} "
              f"(expected {expect_limit or 'any'}/{'YES' if expect_yes else 'NO'})")
        if not good:
            print("        " + "\n        ".join(text.splitlines()))

    # The remedies must not be interchangeable: an instrument-bound path must never be told
    # that more sampling will fix it.
    coarse = net_memory.can_detect("coarse-lan", "rtt_avg_ms", 10.0)
    no_false_hope = "more samples will not help" in coarse
    ok &= no_false_hope
    print(f"  {'PASS' if no_false_hope else 'FAIL'}  instrument-bound path is NOT told to "
          f"collect more samples")

    noisy = net_memory.can_detect("noisy-wan", "rtt_avg_ms", 3.0)
    names_window = ("widen the comparison window" in noisy) or ("more history" in noisy)
    ok &= names_window
    print(f"  {'PASS' if names_window else 'FAIL'}  statistics-bound path is given a sampling "
          f"remedy")

    # A signal with almost no history must say UNKNOWN rather than guess a floor.
    build("thin", [10.0 + rng.gauss(0, 0.2) for _ in range(12)])
    thin = net_memory.can_detect("thin", "rtt_avg_ms", 10.0)
    unknown = "UNKNOWN" in thin or "not enough" in thin
    ok &= unknown
    print(f"  {'PASS' if unknown else 'FAIL'}  thin history answers UNKNOWN, does not "
          f"invent a limit")

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
