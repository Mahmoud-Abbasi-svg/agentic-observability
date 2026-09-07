"""SQLite store for the monitor, and the network identity that keeps baselines honest.

Two jobs, and the second is the one that is easy to skip and expensive to retrofit.

STORAGE. The agent's JSONL history is fine for a session and wrong for something that runs for
months: no indexes, no retention, and deleting anything means rewriting the file. This is
SQLite with a retention policy fixed up front rather than when the disk fills - raw samples for
14 days, hourly aggregates for a year.

NETWORK IDENTITY. A laptop moves, and a baseline from one network is meaningless on another.
This machine already shows the problem: it carries DNS servers from other networks that cannot
be reached here. Pool measurements across networks and walking from home to the office
registers as a catastrophic regression, burying every real alert underneath it.

So every sample is tagged with a net_id, and baselines never cross that boundary. The gateway
MAC is the discriminator that actually works - SSIDs collide ("eduroam" is everywhere) and
subnets repeat (192.168.1.0/24 is in every home). When the MAC cannot be read the identity
degrades to gateway IP plus subnet, which is weaker but still separates most real moves.

net_id CANNOT be added later. Samples collected without it cannot be assigned to a network
after the fact, so every baseline built before it would have to be thrown away.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import socket
import sqlite3
import subprocess
import time
from typing import Optional

IS_WINDOWS = platform.system().lower().startswith("win")
DB_PATH = os.environ.get(
    "NET_MONITOR_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "net_monitor.db"))

RAW_RETENTION_DAYS = 14
HOURLY_RETENTION_DAYS = 365

SCHEMA = """
CREATE TABLE IF NOT EXISTS sample (
    ts     INTEGER NOT NULL,
    target TEXT    NOT NULL,
    metric TEXT    NOT NULL,
    value  REAL    NOT NULL,
    net_id TEXT    NOT NULL,
    PRIMARY KEY (target, metric, ts)
);
CREATE INDEX IF NOT EXISTS sample_lookup ON sample (target, metric, net_id, ts);

-- Absence of samples must be distinguishable from absence of connectivity: a laptop that
-- slept for eight hours did not have an eight-hour outage. The collector writes one of these
-- every cycle whether or not any probe succeeded.
CREATE TABLE IF NOT EXISTS heartbeat (
    ts        INTEGER PRIMARY KEY,
    net_id    TEXT NOT NULL,
    n_ok      INTEGER NOT NULL,
    n_failed  INTEGER NOT NULL
);

-- What survives after raw samples are dropped: one row per hour per signal, kept for a year.
--
-- The columns are named for the statistics they actually hold. They were called
-- median/p05/p95 while the insert below stored AVG/MIN/MAX - a name promising a robust centre
-- and a 90% interval over data that was a mean and its two extremes. Nothing had read the
-- table yet, so the lie had never been quoted; it would have been, the first time an answer
-- said "the p95 last month was". Renamed while the table was still empty.
CREATE TABLE IF NOT EXISTS sample_hourly (
    hour   INTEGER NOT NULL,
    target TEXT    NOT NULL,
    metric TEXT    NOT NULL,
    net_id TEXT    NOT NULL,
    mean   REAL, lo REAL, hi REAL, n INTEGER,
    PRIMARY KEY (target, metric, net_id, hour)
);

-- Alert state lives in the database, not in memory, so a restart resumes where it left off
-- rather than re-announcing every ongoing incident as new.
CREATE TABLE IF NOT EXISTS alert_state (
    target     TEXT NOT NULL,
    metric     TEXT NOT NULL,
    net_id     TEXT NOT NULL,
    state      TEXT NOT NULL,        -- UNKNOWN | OK | SUSPECT | ALERTING | RECOVERING
    since      INTEGER NOT NULL,     -- when this state was entered
    streak     INTEGER NOT NULL,     -- consecutive confirmations in the current direction
    last_shift REAL,
    updated    INTEGER NOT NULL,
    -- When the current excursion began, and the largest shift seen during it. Both exist
    -- because of a real 3.5 h outage that CLEARED itself after 1.2 h: its own samples flowed
    -- into the baseline the noise floor is calibrated on, the floor rose from 80 to 100, and
    -- a +100 shift stopped "exceeding" it. anomaly_since keeps the excursion out of its own
    -- baseline; peak_shift is what a recovery has to be measured against, so a floor that
    -- grows can never be mistaken for a signal that receded.
    anomaly_since INTEGER,
    peak_shift    REAL,
    PRIMARY KEY (target, metric, net_id)
);

-- Every fired alert and clear, kept for review. An alert nobody can look up afterwards cannot
-- be argued with, and the whole claim here is that these fire less often and with reasons.
CREATE TABLE IF NOT EXISTS alert_log (
    ts     INTEGER NOT NULL,
    target TEXT NOT NULL,
    metric TEXT NOT NULL,
    net_id TEXT NOT NULL,
    kind   TEXT NOT NULL,            -- FIRED | CLEARED
    shift  REAL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS alert_log_ts ON alert_log (ts);

CREATE TABLE IF NOT EXISTS net (
    net_id   TEXT PRIMARY KEY,
    label    TEXT,
    gateway  TEXT,
    gw_mac   TEXT,
    ssid     TEXT,
    subnet   TEXT,
    first_seen INTEGER,
    last_seen  INTEGER
);
"""


def connect(path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")       # survives a hard stop mid-write
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


_HOURLY_RENAMES = (("median", "mean"), ("p05", "lo"), ("p95", "hi"))


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring an older database up to the current schema, if it can be done right now.

    CREATE TABLE IF NOT EXISTS does nothing to a table that already exists, so a rename has to
    be applied explicitly or an existing database keeps the old column names for ever.

    It is attempted on every connect and allowed to fail. A column rename is a schema change
    and needs the write lock, which the collector holds most of the time; on the live database
    the first attempt raised "database is locked" and, unguarded, that turned a background
    housekeeping step into a crash in every tool that merely wanted to read. Migrations that
    can fail must never be on the path of a reader, so this gives up quietly and `hourly_cols`
    keeps the old names working until an attempt lands.
    """
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(sample_hourly)")}
        pending = [(o, n) for o, n in _HOURLY_RENAMES if o in cols and n not in cols]
        state_cols = {r[1] for r in conn.execute("PRAGMA table_info(alert_state)")}
        adds = [(n, t) for n, t in (("anomaly_since", "INTEGER"), ("peak_shift", "REAL"))
                if n not in state_cols]
        if not pending and not adds:
            return
        for old, new in pending:
            conn.execute(f"ALTER TABLE sample_hourly RENAME COLUMN {old} TO {new}")
        for name, typ in adds:
            conn.execute(f"ALTER TABLE alert_state ADD COLUMN {name} {typ}")
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Whether a column exists right now, since the migration above is allowed to fail.

    Readers ask rather than assume: a database that was locked when its writer started still
    has to answer correctly, with the older behaviour, instead of raising "no such column".
    """
    try:
        return any(r[1] == column for r in conn.execute(f"PRAGMA table_info({table})"))
    except sqlite3.Error:
        return False


def hourly_cols(conn: sqlite3.Connection) -> tuple[str, str, str]:
    """The centre/low/high column names this particular database is currently using.

    Resolved per query rather than assumed, because the rename above is best-effort: a
    database that was busy when its readers started still has to answer them correctly.
    """
    cols = {r[1] for r in conn.execute("PRAGMA table_info(sample_hourly)")}
    return ("mean", "lo", "hi") if "mean" in cols else ("median", "p05", "p95")


# --------------------------------------------------------------------- network identity

# See net_tools: suppress the console window Windows opens for every child process.
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}


def _run(cmd: list[str], timeout: float = 8.0) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           encoding="utf-8", errors="replace", **_NO_WINDOW)
        return ((p.stdout or "") + (p.stderr or ""))
    except Exception:
        return ""


def default_gateway() -> Optional[str]:
    """The gateway address for the interface currently carrying traffic."""
    if IS_WINDOWS:
        out = _run(["route", "print", "-4"])
        # the 0.0.0.0/0 row: "0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>"
        best, best_metric = None, None
        for line in out.splitlines():
            f = line.split()
            if len(f) >= 5 and f[0] == "0.0.0.0" and f[1] == "0.0.0.0":
                try:
                    metric = int(f[4])
                except ValueError:
                    continue
                if best_metric is None or metric < best_metric:
                    best, best_metric = f[2], metric
        if best and re.match(r"^\d+\.\d+\.\d+\.\d+$", best):
            return best
        m = re.search(r"(?:Default Gateway|Puerta de enlace)[^\d]*"
                      r"((?:\d{1,3}\.){3}\d{1,3})", _run(["ipconfig"]))
        return m.group(1) if m else None
    m = re.search(r"default via ((?:\d{1,3}\.){3}\d{1,3})", _run(["ip", "route"]))
    return m.group(1) if m else None


def gateway_mac(gateway: str) -> Optional[str]:
    """MAC of the gateway, read from the ARP cache. The strongest identity signal available
    without privileges: it differs between two networks that share a subnet."""
    if not gateway:
        return None
    out = _run(["arp", "-a", gateway] if IS_WINDOWS else ["arp", "-n", gateway])
    for line in out.splitlines():
        if gateway in line:
            m = re.search(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", line, re.I)
            if m:
                return m.group(0).lower().replace("-", ":")
    return None


def wifi_ssid() -> Optional[str]:
    if IS_WINDOWS:
        out = _run(["netsh", "wlan", "show", "interfaces"])
        for line in out.splitlines():
            # "SSID" also matches "BSSID"; require the line to start with SSID
            s = line.strip()
            if re.match(r"^SSID\s*[:.]", s, re.I):
                v = s.split(":", 1)[-1].strip()
                return v or None
        return None
    out = _run(["iwgetid", "-r"]).strip()
    return out or None


def local_subnet() -> Optional[str]:
    """The /24 of this machine's primary address - a coarse but useful fallback signal."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("1.1.1.1", 80))          # no packet is sent; picks the routing interface
        ip = s.getsockname()[0]
        s.close()
        return ".".join(ip.split(".")[:3]) + ".0/24"
    except Exception:
        return None


_CACHE: dict = {"at": 0.0, "info": None}
_CACHE_TTL = 30.0


# A replayed capture is not this laptop's network, and must never borrow its identity -
# baselines are per-network precisely so that one path's normal is never compared against
# another's. When NET_REPLAY_ID names a net_id already recorded in the database, the identity
# is read from that row instead of probed from the machine, so every analysis tool operates on
# the capture without a single change to its code.
REPLAY_ENV = "NET_REPLAY_ID"


def _identity_from_db(net_id: str) -> dict:
    # DB_PATH is read from the environment once, when this module is imported. Anything that
    # sets NET_MONITOR_DB afterwards - a test, or a caller switching databases mid-process -
    # would be silently ignored if that frozen value were used here, and the lookup would fail
    # against the wrong file while reporting the right net_id.
    path = os.environ.get("NET_MONITOR_DB", DB_PATH)
    row = connect(path).execute(
        "SELECT net_id,label,gateway,gw_mac,ssid,subnet FROM net WHERE net_id=?",
        (net_id,)).fetchone()
    if not row:
        raise SystemExit(
            f"{REPLAY_ENV}={net_id} but no such network is recorded in {path}.\n"
            f"Ingest a capture first, or unset {REPLAY_ENV} to use the live network.")
    return dict(net_id=row[0], label=row[1], gateway=row[2], gw_mac=row[3],
                ssid=row[4], subnet=row[5], strength="replay", assumed=False)


def network_identity(force: bool = False) -> dict:
    """Identify the network this machine is currently on.

    Cached briefly: it is consulted every collection cycle and shelling out to `route` and
    `arp` each time would cost more than the measurements do. 30 s is short enough that a
    move is noticed almost immediately.
    """
    replay = os.environ.get(REPLAY_ENV, "").strip()
    if replay:
        return _identity_from_db(replay)

    now = time.time()
    if not force and _CACHE["info"] and (now - _CACHE["at"]) < _CACHE_TTL:
        return _CACHE["info"]

    gw = default_gateway()
    mac = gateway_mac(gw) if gw else None
    ssid = wifi_ssid()
    subnet = local_subnet()

    # Prefer the MAC; fall back to gateway+subnet, which still separates most real moves.
    if mac:
        basis, strength = f"mac:{mac}|{subnet or ''}", "strong"
    else:
        # The link is down or degraded. Losing the gateway MAC is evidence about the LINK,
        # not about which network this machine is attached to - you do not move house because
        # your router stopped answering ARP. Minting a new net_id here is therefore wrong, and
        # a deliberate outage on 2026-09-06 showed how wrong: identity fragmented in stages as
        # the link died, 929d15ad (mac+ssid) -> 484c3993 (subnet only) -> "offline", and the
        # 33 minutes of the outage landed under a network that had never existed.
        #
        # Three failures followed from that one, and none of them announced itself:
        #   * no alert fired, because a brand-new net_id has no history to compare against, so
        #     the monitor watched the network die and said nothing;
        #   * `coverage` reported the outage as an UNOBSERVED gap on the real network - the
        #     tool disowning 151 samples it had correctly taken, which is the exact inversion
        #     of the honesty it is built for;
        #   * "offline" hashes to one constant, so every outage on every network would have
        #     accumulated in a single shared bucket for ever.
        #
        # So a degraded reading now sticks to the last strongly-identified network, provided
        # nothing observable contradicts it and it was seen recently enough to still be true.
        prev = _last_strong_identity(IDENTITY_STICKY_S)
        if prev and not _contradicts(prev, gw, ssid, subnet):
            info = dict(net_id=prev["net_id"], label=prev["label"], gateway=prev["gateway"],
                        gw_mac=prev["gw_mac"], ssid=prev["ssid"], subnet=prev["subnet"],
                        strength="assumed", assumed=True)
            _CACHE.update(at=now, info=info)
            return info
        # Nothing recent to attach to, so the network genuinely is unknown. Say that rather
        # than guessing: an "offline" bucket is not a network and must never be read as one.
        if gw or subnet:
            basis, strength = f"gw:{gw or ''}|{subnet or ''}|{ssid or ''}", "weak"
        else:
            basis, strength = "offline", "none"
    net_id = hashlib.sha1(basis.encode()).hexdigest()[:12]
    label = ssid or gw or subnet or "offline"

    info = dict(net_id=net_id, label=label, gateway=gw, gw_mac=mac, ssid=ssid,
                subnet=subnet, strength=strength, assumed=False)
    _CACHE.update(at=now, info=info)
    return info


# How long a strong identity stays usable as the answer to "which network is this?" once the
# link degrades. An hour covers an outage, a reboot and a suspend; beyond that the machine may
# genuinely have moved while it could not see, and attributing an unreachable period to the
# wrong network would poison that network's availability baseline with someone else's outage.
IDENTITY_STICKY_S = 3600.0


def _last_strong_identity(within: float) -> Optional[dict]:
    """The most recent MAC-identified network, if it was seen inside `within` seconds.

    Opened read-only and separately from connect(): this runs on the identity path, which the
    collector hits every cycle, and it must never create a file, run a migration or take a
    write lock. Any failure means "no candidate", never an exception - degraded identity is
    already the unhappy path and must not become a crash.
    """
    path = os.environ.get("NET_MONITOR_DB", DB_PATH)     # read at call time, never frozen
    if not os.path.exists(path):
        return None
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
        try:
            row = c.execute(
                "SELECT net_id,label,gateway,gw_mac,ssid,subnet FROM net "
                "WHERE gw_mac IS NOT NULL AND last_seen>=? ORDER BY last_seen DESC LIMIT 1",
                (int(time.time() - within),)).fetchone()
        finally:
            c.close()
    except sqlite3.Error:
        return None
    keys = ("net_id", "label", "gateway", "gw_mac", "ssid", "subnet")
    return dict(zip(keys, row)) if row else None


def _contradicts(prev: dict, gw: Optional[str], ssid: Optional[str],
                 subnet: Optional[str]) -> bool:
    """Does what can still be read rule out being on `prev`?

    Only positive evidence counts. A field that cannot be read says nothing - that is the
    whole situation being handled - so absence never contradicts. A field that CAN be read and
    disagrees is a real move, and then a new identity is correct.
    """
    for seen, before in ((subnet, prev["subnet"]), (gw, prev["gateway"]), (ssid, prev["ssid"])):
        if seen and before and seen != before:
            return True
    return False


def remember_net(conn: sqlite3.Connection, info: dict) -> None:
    now = int(time.time())
    conn.execute(
        "INSERT INTO net (net_id,label,gateway,gw_mac,ssid,subnet,first_seen,last_seen) "
        "VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT(net_id) DO UPDATE SET last_seen=excluded.last_seen, "
        "label=excluded.label",
        (info["net_id"], info["label"], info["gateway"], info["gw_mac"],
         info["ssid"], info["subnet"], now, now))


# --------------------------------------------------------------------- writes and reads

def add_samples(conn: sqlite3.Connection, target: str, metrics: dict[str, float],
                net_id: str, ts: Optional[int] = None) -> int:
    # Sub-second precision is kept, and that is not cosmetic. The primary key is
    # (target, metric, ts), so truncating to whole seconds makes every measurement taken
    # within the same second overwrite the previous one - silently, because INSERT OR REPLACE
    # reports success either way.
    #
    # The live collector polls at 60 s and never met this. A real industrial capture did
    # immediately: six RTUs polled in bursts of three transactions inside one second, every
    # ten seconds, lost exactly two thirds of their data on the way into the table. Nothing
    # reported a problem, and a noise floor was then computed confidently on the third that
    # survived - which is precisely the failure this project exists to make impossible.
    #
    # Rounded to microseconds: finer than any capture clock, and it keeps the key exact rather
    # than at the mercy of float representation.
    ts = round(float(ts if ts is not None else time.time()), 6)
    rows = [(ts, target, k, float(v), net_id) for k, v in metrics.items()]
    conn.executemany("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                     "VALUES (?,?,?,?,?)", rows)
    return len(rows)


def add_heartbeat(conn: sqlite3.Connection, net_id: str, n_ok: int, n_failed: int) -> None:
    conn.execute("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) VALUES (?,?,?,?)",
                 (int(time.time()), net_id, n_ok, n_failed))


def series(conn: sqlite3.Connection, target: str, metric: str, net_id: str,
           days: float = 7.0) -> list[tuple[int, float]]:
    """Samples for one (target, metric) ON THIS NETWORK ONLY. The net_id filter is the point."""
    cutoff = int(time.time() - days * 86400)
    return list(conn.execute(
        "SELECT ts, value FROM sample WHERE target=? AND metric=? AND net_id=? AND ts>=? "
        "ORDER BY ts", (target, metric, net_id, cutoff)))


def coverage(conn: sqlite3.Connection, net_id: str, hours: float = 24.0) -> dict:
    """How complete is the record - did we measure, or were we asleep?"""
    cutoff = int(time.time() - hours * 3600)
    beats = conn.execute("SELECT COUNT(*), MIN(ts), MAX(ts) FROM heartbeat "
                         "WHERE net_id=? AND ts>=?", (net_id, cutoff)).fetchone()
    n, lo, hi = beats
    return dict(heartbeats=n, first=lo, last=hi,
                span_h=((hi - lo) / 3600.0) if (lo and hi) else 0.0)


# --------------------------------------------------------------------- retention

def aggregate_and_prune(conn: sqlite3.Connection, now: Optional[int] = None) -> dict:
    """Roll raw samples older than the raw window into hourly rows, then delete them.

    Run nightly. Without this the database grows without bound, which is the failure mode that
    turns a monitor into a disk-space incident three months after everyone forgot about it.
    """
    now = int(now if now is not None else time.time())
    raw_cutoff = now - RAW_RETENTION_DAYS * 86400
    # AVG/MIN/MAX, stored under those names. A real median and real percentiles would need the
    # values in Python; the mean and the two extremes are what SQLite can aggregate directly,
    # and calling them that is the difference between a summary and a misquote later.
    c_mean, c_lo, c_hi = hourly_cols(conn)
    conn.execute(f"""
        INSERT OR REPLACE INTO sample_hourly (hour,target,metric,net_id,{c_mean},{c_lo},{c_hi},n)
        SELECT (ts/3600)*3600, target, metric, net_id,
               AVG(value), MIN(value), MAX(value), COUNT(*)
        FROM sample WHERE ts < ? GROUP BY (ts/3600), target, metric, net_id
    """, (raw_cutoff,))
    dropped = conn.execute("DELETE FROM sample WHERE ts < ?", (raw_cutoff,)).rowcount
    hourly_cutoff = now - HOURLY_RETENTION_DAYS * 86400
    conn.execute("DELETE FROM sample_hourly WHERE hour < ?", (hourly_cutoff,))
    conn.execute("DELETE FROM heartbeat WHERE ts < ?", (hourly_cutoff,))
    conn.commit()
    return {"raw_rows_dropped": dropped}


def stats(conn: sqlite3.Connection) -> dict:
    q = lambda s: conn.execute(s).fetchone()[0]                              # noqa: E731
    return dict(samples=q("SELECT COUNT(*) FROM sample"),
                hourly=q("SELECT COUNT(*) FROM sample_hourly"),
                heartbeats=q("SELECT COUNT(*) FROM heartbeat"),
                targets=q("SELECT COUNT(DISTINCT target) FROM sample"),
                networks=q("SELECT COUNT(*) FROM net"),
                db_mb=round(os.path.getsize(DB_PATH) / 1e6, 2)
                if os.path.exists(DB_PATH) else 0.0)


if __name__ == "__main__":
    info = network_identity()
    print("network identity")
    for k, v in info.items():
        print(f"  {k:10} {v}")
    if info["strength"] == "weak":
        print("  NOTE: gateway MAC unreadable, so two networks sharing a gateway IP and "
              "subnet would collide. Baselines are still separated for most real moves.")
    conn = connect()
    remember_net(conn, info)
    conn.commit()
    print(f"\ndatabase: {DB_PATH}")
    for k, v in stats(conn).items():
        print(f"  {k:12} {v}")
    print("\nknown networks:")
    for row in conn.execute("SELECT net_id,label,gateway,gw_mac,subnet FROM net"):
        print("  " + "  ".join(str(x) for x in row))
