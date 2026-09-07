"""Which network is this, when the network is down?

    python test_net_identity.py

Found by a deliberate outage on 2026-09-06, not by reasoning. As the link died the identity
was re-read every 30 s from whatever could still be observed, and each poorer reading hashed
to a different net_id:

    929d15ad  mac + ssid + subnet     the real network
    484c3993  subnet only             the MAC stopped answering ARP
    d1ffda5d  "offline"               nothing readable at all

Thirty-three minutes of correctly-recorded failure landed under 484c3993, a network that had
never existed. No alert fired, because a new net_id has no history to compare against. And
`coverage` on the real network reported the outage as an UNOBSERVED gap: the tool disowned
151 samples it had taken. Every prediction that depended on identity failed for that one
reason.

The rule this suite pins down: losing the gateway MAC is evidence about the LINK, not about
which network the machine is on. A degraded reading sticks to the last MAC-identified network
unless something still readable contradicts it, or that identity is too old to trust.

Every case runs against a throwaway database with the probing functions replaced, so it
neither touches the network nor depends on which one the test machine happens to be on.
"""
from __future__ import annotations

import os
import tempfile
import time

DB = os.path.join(tempfile.mkdtemp(prefix="netident_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_store                                                     # noqa: E402

CONN = net_store.connect()

# Invented, deliberately. A gateway MAC plus an SSID is a wifi-geolocation key, so no real one
# belongs in a file that is published; the locally-administered range (02:xx) cannot collide
# with hardware.
OFFICE = dict(gw="10.0.0.1", mac="02:00:5e:00:00:01", ssid="Office", subnet="10.0.0.0/24")
HOME = dict(gw="192.168.1.1", mac="02:00:5e:00:00:02", ssid="Home", subnet="192.168.1.0/24")


def check(name: str, ok, detail: str = "") -> bool:
    # bool(), not the value: callers pass expressions like `a and b and c`, which
    # yield the last truthy operand rather than True. Suites accumulate with
    # `ok &= check(...)`, and `True & 6` is 0 - so every check printed PASS while the
    # suite reported failure. It can only raise a false alarm, never hide a real one,
    # but a suite that cries wolf gets ignored like any other.
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def observe(gw=None, mac=None, ssid=None, subnet=None) -> dict:
    """Make the probes report exactly this, bypass the cache, and record what was decided."""
    net_store.default_gateway = lambda: gw
    net_store.gateway_mac = lambda _g: mac
    net_store.wifi_ssid = lambda: ssid
    net_store.local_subnet = lambda: subnet
    info = net_store.network_identity(force=True)
    net_store.remember_net(CONN, info)
    CONN.commit()
    return info


def age_last_seen(net_id: str, seconds: float) -> None:
    CONN.execute("UPDATE net SET last_seen=? WHERE net_id=?",
                 (int(time.time() - seconds), net_id))
    CONN.commit()


def main() -> int:
    ok = True

    office = observe(**OFFICE)
    ok &= check("a full reading gives a strong identity",
                office["strength"] == "strong" and not office["assumed"], office["net_id"])

    # The outage, replayed exactly as it was recorded: the MAC goes first, then everything.
    degraded = observe(gw=OFFICE["gw"], subnet=OFFICE["subnet"])
    ok &= check("MAC unreadable, subnet unchanged: STILL the office",
                degraded["net_id"] == office["net_id"] and degraded["assumed"],
                f"strength={degraded['strength']}")
    dark = observe()
    ok &= check("nothing readable at all: STILL the office",
                dark["net_id"] == office["net_id"] and dark["assumed"])
    ok &= check("the assumed identity keeps the office's label, so answers name the right place",
                dark["label"] == "Office")

    back = observe(**OFFICE)
    ok &= check("the link returns: same net_id, strong again, nothing was split",
                back["net_id"] == office["net_id"] and back["strength"] == "strong")
    ok &= check("only ONE network was ever recorded through the whole outage",
                CONN.execute("SELECT COUNT(*) FROM net").fetchone()[0] == 1)

    # A real move must still be a real move. Same failure to read the MAC, but the subnet
    # that CAN be read is a different one - that is positive evidence, and it wins.
    moved = observe(gw=HOME["gw"], subnet=HOME["subnet"])
    ok &= check("MAC unreadable but a DIFFERENT subnet is readable: a new network, not the office",
                moved["net_id"] != office["net_id"] and not moved["assumed"],
                f"strength={moved['strength']}")
    home = observe(**HOME)
    ok &= check("a strong reading at the new place is its own identity",
                home["net_id"] not in (office["net_id"], moved["net_id"])
                and home["strength"] == "strong")

    # Stickiness must expire. The machine may have travelled while it could not see, and
    # pinning a week-old identity onto an unreachable period would put someone else's outage
    # into that network's availability baseline.
    age_last_seen(home["net_id"], net_store.IDENTITY_STICKY_S + 60)
    age_last_seen(office["net_id"], net_store.IDENTITY_STICKY_S + 60)
    stale = observe()
    ok &= check("with no recent strong identity, offline is NOT attributed to anyone",
                not stale["assumed"] and stale["strength"] == "none"
                and stale["net_id"] not in (office["net_id"], home["net_id"]),
                f"label={stale['label']!r}")

    # And the most recent strong identity is the one that wins, not the first ever seen.
    age_last_seen(home["net_id"], 30)
    recent = observe()
    ok &= check("when several are known, the one seen most recently is assumed",
                recent["net_id"] == home["net_id"] and recent["assumed"])

    # The identity lookup opens the database read-only and must never raise on the collector's
    # hot path - not even when there is no database yet.
    os.environ["NET_MONITOR_DB"] = os.path.join(tempfile.mkdtemp(prefix="netnone_"), "x.db")
    try:
        fresh = observe()
        ok &= check("no database at all: degrades quietly instead of raising",
                    fresh["strength"] == "none" and not fresh["assumed"])
    finally:
        os.environ["NET_MONITOR_DB"] = DB

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
