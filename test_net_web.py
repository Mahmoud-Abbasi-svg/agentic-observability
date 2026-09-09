"""Does the live view stay honest once it starts implying "now"?

    python test_net_web.py

A snapshot is stamped and obviously past. A page that refreshes itself asserts the present
by existing, and that creates failure modes net_report.py cannot have. Every check here is
one of them, plus the exposure a listening socket adds that a file does not.

Pre-registered before the server was written:

  C1   a non-loopback bind address is refused, not warned about
  C2   a request arriving under a foreign Host name is rejected; a loopback one is served
  C3   no endpoint reaches a tool that emits a packet
  C4   ages are of the DATA, and a collector past its heartbeat window is called dead
  C5   unobserved time is labelled not-measured and never carries the reachable class
  C6   a target named like an injection survives as text and is never written as markup
  C7   the server's own connection is read-only
  C8   the page makes no external request
  C9   an unknown target is answered "no data", never invented
  C10  the window asked for is the window returned, and every timeline names its network
  C11  there is no write path at all

Runs a real server against a throwaway database over a real socket. Never touches the store.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.request

DB = os.path.join(tempfile.mkdtemp(prefix="netweb_"), "test.db")
os.environ["NET_MONITOR_DB"] = DB

import net_store                                                     # noqa: E402

NET, OTHER = "aaaaaaaaaaaa", "bbbbbbbbbbbb"
IDENTITY = dict(net_id=NET, label="lab-wifi", gateway="10.9.0.1",
                gw_mac="00:11:22:33:44:55", ssid="lab-wifi", subnet="10.9.0.0/24",
                strength="strong", assumed=False)
# Hermetic: the real one shells out to route/arp/netsh and would make this test depend on
# whatever network the machine happens to be on.
net_store.network_identity = lambda force=False: dict(IDENTITY)      # noqa: E731

import net_report                                                    # noqa: E402
import net_tools                                                     # noqa: E402
import net_web                                                       # noqa: E402

CONN = net_store.connect()
STEP, NOW = 60, int(time.time()) // 60 * 60
EVIL = '<img src=x onerror="alert(1)">'
GONE = "never-probed.invalid"


def check(name: str, ok, detail: str = "") -> bool:
    ok = bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def seed() -> None:
    """300..181 min ago measured with a 30-min outage, 180..11 on another network,
    10..0 measured again. The same shape test_net_report.py uses."""
    for m in range(300, 180, -1):
        down = 250 >= m >= 221
        for t in ("gw", EVIL):
            CONN.execute("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                         "VALUES (?,?,?,?,?)",
                         (NOW - m * STEP, t, "reachable", 0.0 if down else 1.0, NET))
        CONN.execute("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                     "VALUES (?,?,?,?,?)", (NOW - m * STEP, "gw", "rtt_avg_ms", 12.0, NET))
        CONN.execute("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) "
                     "VALUES (?,?,?,?)", (NOW - m * STEP + 5, NET, 2, 0))
    for m in range(10, -1, -1):
        for t in ("gw", EVIL):
            CONN.execute("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                         "VALUES (?,?,?,?,?)", (NOW - m * STEP, t, "reachable", 1.0, NET))
        CONN.execute("INSERT OR REPLACE INTO sample (ts,target,metric,value,net_id) "
                     "VALUES (?,?,?,?,?)", (NOW - m * STEP, "gw", "rtt_avg_ms", 12.0, NET))
        CONN.execute("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) "
                     "VALUES (?,?,?,?)", (NOW - m * STEP + 5, NET, 2, 0))
    CONN.execute("INSERT OR REPLACE INTO net (net_id,label,gateway,gw_mac,ssid,subnet,"
                 "first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
                 (OTHER, "office-wifi", "10.0.0.1", "aa", "office-wifi", "10.0.0.0/24",
                  NOW - 99999, NOW))
    CONN.executemany("INSERT OR REPLACE INTO heartbeat (ts,net_id,n_ok,n_failed) "
                     "VALUES (?,?,?,?)",
                     [(NOW - m * STEP + 7, OTHER, 2, 0) for m in range(179, 11, -1)])
    CONN.executemany(
        "INSERT OR REPLACE INTO alert_state (target,metric,net_id,state,since,streak,"
        "last_shift,updated) VALUES (?,?,?,?,?,?,?,?)",
        [("gw", "loss_pct", NET, "ALERTING", NOW - 600, 3, 1.0, NOW - 30),
         ("far", "rtt_avg_ms", OTHER, "ALERTING", NOW - 90000, 3, 0.4, NOW - 80000),
         ("gw", "reachable", NET, "OK", NOW - 600, 0, 0.0, NOW - 30)])
    CONN.commit()


PORT = 0


def get(path: str, host: str = "", method: str = "GET", timeout: float = 60.0):
    url = f"http://127.0.0.1:{PORT}{path}"
    req = urllib.request.Request(url, method=method,
                                 data=b"x" if method == "POST" else None)
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def main() -> int:
    global PORT
    seed()
    ok = True

    # ------------------------------------------------------------------ C1  the bind refusal
    refused = []
    for h in ("0.0.0.0", "::", "192.168.1.20", "10.9.0.5"):
        try:
            net_web.serve(h, 0).server_close()
            refused.append((h, "BOUND"))
        except ValueError:
            pass
        except OSError:
            pass            # not our address to bind; the refusal we care about is ValueError
    ok &= check("C1  a non-loopback bind address is refused, not warned about",
                not refused, str(refused))
    try:
        net_web.serve("0.0.0.0", 0)
        why = ""
    except ValueError as exc:
        why = str(exc)
    ok &= check("C1  and the refusal says why, naming what would be exposed",
                "loopback" in why.lower() and ("ssid" in why.lower() or "locate" in why),
                why[:80])

    srv = net_web.serve("127.0.0.1", 0)
    PORT = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)

    # ------------------------------------------------------------------ C2  the Host guard
    code_ok, _ = get("/api/overview?hours=6")
    code_evil, body_evil = get("/api/overview?hours=6", host="attacker.example")
    ok &= check("C2  a loopback request is served", code_ok == 200, f"got {code_ok}")
    ok &= check("C2  a request under a foreign Host name is refused (DNS rebinding)",
                code_evil == 403, f"got {code_evil}")
    ok &= check("C2  and the refusal explains itself rather than 404-ing",
                "loopback" in body_evil.lower())
    for h in ("localhost", "127.0.0.1", f"127.0.0.1:{PORT}", "[::1]"):
        c, _ = get("/api/overview?hours=6", host=h)
        ok &= check(f"C2  loopback name {h!r} is accepted", c == 200, f"got {c}")

    # ------------------------------------------------------------------ C3  no packets
    probes = {f.__name__ for f in net_tools.ALL_TOOLS}
    leaked = probes & set(net_web.READ_ONLY_TOOLS)
    ok &= check("C3  no endpoint exposes a tool that emits a packet",
                not leaked, str(sorted(leaked)) or f"{len(probes)} probe tools, none exposed")
    ok &= check("C3  the upstream map is pinned to the scope that reads stored traces",
                'scope="upstream"' in net_web.upstream.__doc__.lower()
                or "no new packets" in net_web.upstream.__doc__.lower())
    src = open(net_web.__file__, encoding="utf-8").read()
    ok &= check("C3  and the LAN sweep scope is never taken from the query string",
                'scope="lan"' not in src and 'q.get("scope"' not in src)

    # ------------------------------------------------------------------ C4  ages, and death
    _, raw = get("/api/overview?hours=6")
    d = json.loads(raw)
    ok &= check("C4  the response carries the age of the DATA, not of the request",
                d["newest_sample"] is not None and d["collector"]["last_beat"] is not None
                and d["now"] >= d["newest_sample"])
    ok &= check("C4  a collector beating seconds ago is alive", d["collector"]["alive"])
    # A FIXED cutoff, not one derived from COLLECTOR_STALE_S. Deriving it meant that raising
    # the threshold - the exact bug this check exists to catch - also widened the DELETE until
    # it removed every heartbeat, and "no heartbeat at all" is not alive either. The check
    # passed while the collector could never be called dead. So: leave a real heartbeat in
    # place, three hours old, and require it to still be there when the verdict is read.
    CONN.execute("DELETE FROM heartbeat WHERE ts > ?", (NOW - 900,))
    CONN.commit()
    _, raw2 = get("/api/overview?hours=6")
    d2 = json.loads(raw2)
    beat2 = d2["collector"]["last_beat"]
    ok &= check("C4  the stale case still HAS a heartbeat, so absence cannot pass for age",
                beat2 is not None and (d2["now"] - beat2) > net_web.COLLECTOR_STALE_S,
                f"last beat {d2['now'] - beat2:.0f}s ago" if beat2 else "no heartbeat at all")
    ok &= check("C4  once the heartbeat is older than the window, it is called NOT COLLECTING",
                beat2 is not None and not d2["collector"]["alive"],
                f"last beat {d2['now'] - (beat2 or 0):.0f}s ago")
    ok &= check("C4  and the page shows the collector's own state, not a fetch timestamp",
                "NOT COLLECTING" in get("/")[1] and "serverNow" in get("/")[1])

    # ------------------------------------------------------------------ C5  the colour rule
    segs = [s for n in d["networks"] for t in n["targets"] for s in t["segments"]]
    kinds = {k: sum(s["kind"] == k for s in segs) for k in ("up", "down", "gap", "else")}
    ok &= check("C5  all the states are present, so the window really is mixed",
                kinds["up"] and kinds["down"] and (kinds["gap"] or kinds["else"]), str(kinds))
    unob = [s for s in segs if s["kind"] in ("gap", "else")]
    ok &= check("C5  every unobserved segment says not measured",
                unob and all("not measured" in s["title"] for s in unob))
    ok &= check("C5  and none of them is described as quiet, healthy or fine",
                not any(w in s["title"].lower() for s in unob
                        for w in ("healthy", "quiet", "fine")))
    ok &= check("C5  unobserved time never carries the reachable class",
                all(s["kind"] != "up" for s in unob))
    ok &= check("C5  the time on another network is attributed to it by name",
                any(s["kind"] == "else" and "office-wifi" in s["title"] for s in segs))
    ok &= check("C5  a window that is mostly unobserved is not reported as no-failure-seen",
                net_report._bar_state({"gap": 3600.0}, 0, 3600.0)[1] == "mostly unobserved")

    # ------------------------------------------------------------------ C6  injection
    names = [t["target"] for n in d["networks"] for t in n["targets"]]
    ok &= check("C6  the injection-shaped target round-trips as data, unaltered",
                EVIL in names, str([x[:30] for x in names]))
    page = get("/")[1]
    ok &= check("C6  the page never embeds target text as markup",
                "innerHTML" not in page and "outerHTML" not in page
                and "insertAdjacentHTML" not in page and "document.write" not in page)
    ok &= check("C6  target text reaches the DOM only through textContent",
                "textContent" in page)
    ok &= check("C6  and no sample data is baked into the page at all",
                EVIL not in page and "gw" not in re.sub(r"[a-z]gw|gw[a-z]", "", page))

    # ------------------------------------------------------------------ C7  read-only
    c = net_web._ro_conn()
    try:
        c.execute("INSERT INTO sample (ts,target,metric,value,net_id) VALUES (1,'x','y',1,'z')")
        wrote = True
    except sqlite3.OperationalError:
        wrote = False
    finally:
        c.close()
    ok &= check("C7  the server's own connection cannot write to the store", not wrote)

    # ------------------------------------------------------------------ C8  self-contained
    ok &= check("C8  the page makes no external request",
                not re.search(r'(src|href)="(?!#)(?!data:)', page))
    ok &= check("C8  no CDN, font service or remote script is referenced",
                not re.search(r"https?://(?!127\.0\.0\.1|localhost)", page))

    # ------------------------------------------------------------------ C9  unknown target
    _, raw3 = get(f"/api/detail?target={GONE}&hours=6")
    d3 = json.loads(raw3)
    ok &= check("C9  an unknown target is answered 'no data', not invented",
                d3["known"] is False and not d3["panels"] and "No sample" in d3["note"])
    _, raw4 = get("/api/detail?target=gw&hours=6")
    d4 = json.loads(raw4)
    tools = [p["tool"] for p in d4["panels"]]
    ok &= check("C9  a known target gets the history tools, named and timed",
                d4["known"] and "availability" in tools and "route_history" in tools,
                str(tools))
    ok &= check("C9  a tool that fails is reported as failed, never dropped",
                all("text" in p and "failed" in p and "ms" in p for p in d4["panels"]))
    # next(..., None) rather than next(...): a missing panel must FAIL this check, not raise
    # and abandon the eleven checks below it.
    rh = next((p for p in d4["panels"] if p["tool"] == "route_history"), None)
    ok &= check("C9  with no stored trace it says so, and does not claim the route is stable",
                rh is not None and "No traceroute has been stored" in rh["text"]
                and "stable" not in rh["text"].lower().replace("being stable", ""),
                "no route_history panel at all" if rh is None else "")
    ok &= check("C9  a missing target is an answer, not a 500", get("/api/detail")[0] == 400)

    # ------------------------------------------------------------------ C10  window and names
    _, raw5 = get("/api/overview?hours=48")
    d5 = json.loads(raw5)
    ok &= check("C10  the window asked for is the window returned",
                abs(d5["hours"] - 48) < 1e-9
                and abs((d5["now"] - d5["since"]) - 48 * 3600) < 5,
                f"{(d5['now'] - d5['since']) / 3600:.2f} h")
    ok &= check("C10  an absurd window is clamped, not obeyed",
                json.loads(get("/api/overview?hours=99999")[1])["hours"] == net_web.MAX_HOURS)
    ok &= check("C10  a non-numeric window falls back instead of erroring",
                json.loads(get("/api/overview?hours=banana")[1])["hours"] == 24.0)
    ok &= check("C10  every timeline names the network it belongs to",
                all(n.get("net_id") and n.get("label") for n in d5["networks"]))
    ok &= check("C10  the current network is marked as current, exactly once",
                sum(bool(n["current"]) for n in d5["networks"]) == 1)

    # ------------------------------------------------------------------ C11  no write path
    ok &= check("C11  POST is not implemented", get("/", method="POST")[0] in (400, 501))
    ok &= check("C11  the handler defines no write verb",
                not any(hasattr(net_web.Handler, f"do_{v}")
                        for v in ("POST", "PUT", "DELETE", "PATCH")))
    ok &= check("C11  and no endpoint can trust a network or edit config",
                "set_trusted" not in src and "confirm=True" not in src)

    # ------------------------------------------------------------------ exposure of the MAC
    ok &= check("the gateway MAC never crosses the socket",
                IDENTITY["gw_mac"] not in raw and IDENTITY["gw_mac"] not in page,
                "it is the strongest geolocation key the store holds")

    srv.shutdown()
    srv.server_close()
    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
