"""Can an outage clear itself by lasting long enough?

    python test_net_selfclear.py

On 2026-09-07 the hotspot went down for 3.5 hours. The monitor fired correctly at 05:04 and
declared CLEAR at 06:25, while the network stayed down until 07:51. Nothing had recovered.
The outage's own 100%-loss samples had flowed into the baseline that the noise floor is
calibrated from; placebo windows began landing inside the outage, the floor rose from 80 to
100, and a +100 shift stopped exceeding it. Measured from the live database:

    05:05  10.2% of the baseline is 100% loss   floor  80
    06:00  19.3%                                floor  80
    06:25  24.4%                                floor 100   <- cleared here
    07:45  37.2%                                floor 100

The evidence lines were honest the whole time - the CLEAR entry itself said "even 200% would
not clear the noise floor". The VERDICT was wrong: it said CLEAR, which reads as recovered.

Two defences, and this suite requires both to work alone, because each covers a case the other
does not:

  BASELINE     the excursion is excluded from the history its own floor is built on. Needs
               enough clean history to predate it.
  RECOVERY     a clear requires the shift to have receded. Covers the case where there is not
  EVIDENCE     enough clean history, and any other reason a floor might grow.

The last check is the one that would have caught this in the first place: a network that
really recovers must still clear, or the fix has only traded a false all-clear for an alert
that never stops.

Writes only to a throwaway database.
"""
from __future__ import annotations

import os
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netselfclear_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_alert                                                     # noqa: E402
import net_memory                                                    # noqa: E402
import net_store                                                     # noqa: E402

CONN = net_store.connect()
NET = net_store.network_identity()["net_id"]
STEP = 60
T, M = "8.8.8.8", "loss_pct"


def check(name: str, ok, detail: str = "") -> bool:
    # bool(), not the value: callers pass expressions like `a and b and c`, which
    # yield the last truthy operand rather than True. Suites accumulate with
    # `ok &= check(...)`, and `True & 6` is 0 - so every check printed PASS while the
    # suite reported failure. It can only raise a false alarm, never hide a real one,
    # but a suite that cries wolf gets ignored like any other.
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def build(now: float, quiet_h: float, outage_h: float, recovered_h: float = 0.0) -> None:
    """quiet_h of 0% loss, then outage_h of 100%, then recovered_h of 0% - ending at `now`."""
    CONN.execute("DELETE FROM sample WHERE target=?", (T,))
    CONN.execute("DELETE FROM heartbeat")
    total = int((quiet_h + outage_h + recovered_h) * 3600 / STEP)
    start = now - total * STEP
    rows, beats = [], []
    for i in range(total):
        ts = start + i * STEP
        age_h = (ts - start) / 3600.0
        down = quiet_h <= age_h < quiet_h + outage_h
        rows.append((ts, T, M, 100.0 if down else 0.0, NET))
        rows.append((ts, T, "reachable", 0.0 if down else 1.0, NET))
        beats.append((int(ts), NET, 0 if down else 2, 2 if down else 0))
    CONN.executemany("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                     "VALUES (?,?,?,?,?)", rows)
    CONN.executemany("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) "
                     "VALUES (?,?,?,?)", beats)
    CONN.commit()


def run(now: float) -> dict:
    rows = {(r["target"], r["metric"]): r for r in
            net_alert.evaluate(CONN, now=now, verbose=False)}
    return rows.get((T, M), {})


def main() -> int:
    ok = True
    now = int(time.time())

    # ---------------------------------------------------------------- the floor really does grow
    build(now, quiet_h=6.0, outage_h=3.5)
    plain = net_memory.assess(T, M, net_alert.RECENT_HOURS, net_alert.BASELINE_DAYS, now=now)
    clean = net_memory.assess(T, M, net_alert.RECENT_HOURS, net_alert.BASELINE_DAYS, now=now,
                              baseline_before=now - 3.5 * 3600)
    ok &= check("with the outage in its own baseline, the floor is inflated",
                plain["noise_floor"] > clean["noise_floor"],
                f"contaminated {plain['noise_floor']:.0f} vs clean {clean['noise_floor']:.0f}")
    ok &= check("contaminated, a +100 shift no longer exceeds the floor - the original bug",
                not plain["exceeds"] and abs(plain["shift"]) >= 100)
    ok &= check("with the excursion excluded, the same +100 shift does exceed it",
                clean["exceeds"] and not clean["baseline_contaminated"])
    ok &= check("and the assessment says which history it calibrated on",
                "excludes everything from" in net_memory.format_assessment(clean))

    # ---------------------------------------------------------------- recovery evidence, alone
    ok &= check("an undiminished shift is not recovery, however wide the floor",
                not net_alert.recovery_is_real(1.00, 1.00)[0]
                and "floor grew" in net_alert.recovery_is_real(1.00, 1.00)[1])
    ok &= check("a shift that has receded IS recovery",
                net_alert.recovery_is_real(0.05, 1.00)[0])
    ok &= check("a shift that reversed direction is recovery, not a continuing excursion",
                net_alert.recovery_is_real(-0.90, 1.00)[0])
    ok &= check("with no peak on record, recovery is allowed - no invented evidence",
                net_alert.recovery_is_real(1.00, None)[0])

    # ---------------------------------------------------------------- the whole loop
    # Walk the evaluator through the real night: quiet, then a 3.5 h outage, minute by minute.
    build(now, quiet_h=6.0, outage_h=3.5)
    states = []
    for back in range(int(3.4 * 60), -1, -10):          # every 10 min through the outage
        states.append(run(now - back * 60).get("state"))
    ok &= check("it fires during the outage", "ALERTING" in states, " -> ".join(states[:6]))
    ok &= check("and NEVER clears while the outage continues",
                states[-1] == "ALERTING" and "OK" not in states[states.index("ALERTING"):],
                f"final {states[-1]}, {states.count('ALERTING')}/{len(states)} passes alerting")

    st = net_alert.get_state(CONN, T, M, NET)
    ok &= check("the excursion's start and peak are on record",
                st["anomaly_since"] is not None and abs(st["peak_shift"]) >= 100)

    # ---------------------------------------------------------------- it must still clear
    build(now, quiet_h=6.0, outage_h=3.5, recovered_h=1.5)
    states = []
    for back in range(85, -1, -5):
        states.append(run(now - back * 60).get("state"))
    ok &= check("once the network really recovers, it clears",
                states[-1] == "OK", " -> ".join(states[-6:]))
    st = net_alert.get_state(CONN, T, M, NET)
    ok &= check("and the excursion record is closed, not left to bias the next one",
                st["anomaly_since"] is None and st["peak_shift"] is None)

    # ---------------------------------------------------------------- an older database
    old = os.path.join(tempfile.mkdtemp(prefix="netold_"), "old.db")
    import sqlite3
    c2 = sqlite3.connect(old)
    c2.executescript("CREATE TABLE alert_state (target TEXT NOT NULL, metric TEXT NOT NULL, "
                     "net_id TEXT NOT NULL, state TEXT NOT NULL, since INTEGER NOT NULL, "
                     "streak INTEGER NOT NULL, last_shift REAL, updated INTEGER NOT NULL, "
                     "PRIMARY KEY (target, metric, net_id));")
    c2.execute("INSERT INTO alert_state VALUES ('h','m','n','ALERTING',1,3,0.5,1)")
    c2.commit()
    c2.close()
    c3 = net_store.connect(old)
    got = net_alert.get_state(c3, "h", "m", "n")
    ok &= check("an existing database gains the columns, keeping its state",
                got["state"] == "ALERTING" and got["last_shift"] == 0.5
                and "anomaly_since" in got,
                f"anomaly_since={got['anomaly_since']}")

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
