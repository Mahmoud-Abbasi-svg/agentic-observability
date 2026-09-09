"""A live local view of the store, in a browser.

    python net_web.py                      # http://127.0.0.1:8787
    python net_web.py --port 9000 --open
    python net_web.py --hours 48           # the window the page opens on

WHAT THIS ADDS OVER net_report.py, AND WHAT IT REFUSES TO BE. The report answers "what
happened", writes a file and stops. Two things it cannot do:

  LIVE        it is a snapshot. To see the last five minutes you regenerate it. A page that
              keeps itself current is the difference between a record and an instrument.
  THE TOOLS   the report draws reachability and nothing else. Everything this project is
              actually good at - route changes, per-hop latency, change detection against a
              measured noise floor, coverage, the upstream map - has no visual surface at
              all and is reachable only from a command line or the agent.

So this serves the SAME run logic as the report (net_report.timeline, shared rather than
reimplemented, so the two surfaces cannot disagree about which time was observed) and puts
the history-reading tools one click away from the target they describe.

FOUR THINGS A LIVE PAGE CAN GET WRONG THAT A SNAPSHOT CANNOT, and what is done about each:

  IT IMPLIES "NOW" BY EXISTING.  A snapshot is stamped and obviously past. A live page that
      keeps displaying after the collector dies, or after the browser loses this server, is
      asserting the present about the past. So every age shown is the age of the DATA, never
      of the request; the collector is called NOT COLLECTING the moment its heartbeat is
      older than COLLECTOR_STALE_S; and a page that cannot reach the server says so across
      the top and dims everything below it rather than sitting there looking current.

  IT COULD MEASURE.  A dashboard that probes on a timer emits measurements nobody asked for,
      into the same history the baselines are computed from - a tab left open overnight
      quietly rewriting the record it is displaying. No endpoint here reaches a tool that
      sends a packet. READ_ONLY_TOOLS is the whole surface and test_net_web.py checks it
      against net_tools.ALL_TOOLS.

  REFRESH LOOKS LIKE CHANGE.  Polling every 15 s against a 60 s collector means three
      refreshes in four show identical data. Nothing animates on a poll, and the age counter
      is of the newest sample, so a stalled collector shows a rising number rather than a
      page that looks busy.

  THE COLOUR RULE.  Measured-good, measured-bad and NOT MEASURED are three states, never
      two. Inherited from the report by sharing its code, not by copying its intent.

IT IS LOOPBACK ONLY, AND THAT IS NOT A DEFAULT. The database holds the SSID and the gateway
MAC. Those two together are a wifi-geolocation key: they place this machine on a street. The
report file is gitignored for that reason and a listening socket is a wider hole than a file,
so a non-loopback bind address is REFUSED rather than warned about, and a request whose Host
header is not a loopback name is rejected - otherwise any site the operator visits could
point a hostname at 127.0.0.1 and read this dashboard from the page they were browsing.

It has no write path. It cannot trust a network, edit the config, or delete a row.
"""
from __future__ import annotations

import argparse
import html
import ipaddress
import json
import os
import sqlite3
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

import net_memory
import net_report
import net_store
import net_topology

COLLECTOR_STALE_S = 300.0     # no heartbeat for this long and the collector is not running
MAX_HOURS = 720.0             # 30 d; beyond the raw retention there is nothing to draw

# The entire tool surface reachable from the browser. Every one of these reads the stored
# history and returns text; none of them opens a socket. net_tools' probes are deliberately
# absent and test_net_web.py fails if any of them appears here - the frontend must never be
# able to put a measurement into the history it is displaying.
#
# net_topology.topology is included at scope="upstream" ONLY, fixed in code below rather than
# taken from the query string: that scope stitches together traceroutes already in the store,
# while "lan" sweeps the subnet and would emit packets on a network the operator may not
# administer. The gate in net_topology would refuse it anyway; this is the second lock.
READ_ONLY_TOOLS = {
    "availability": net_memory.availability,
    "detect_change": net_memory.detect_change,
    "baseline": net_memory.baseline,
    "route_history": net_memory.route_history,
    "can_detect": net_memory.can_detect,
    "coverage": net_memory.coverage,
    "topology": net_topology.topology,
}

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "ip6-localhost"}


def _is_loopback(host: str) -> bool:
    """True only for an address that cannot be reached from another machine."""
    h = (host or "").strip().strip("[]")
    if h.lower() in {x.strip("[]") for x in LOOPBACK_HOSTS}:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _ro_conn() -> sqlite3.Connection:
    """The store, opened read-only. The collector owns this file; nothing served from a
    browser may hold a write lock on it, and no bug in a request handler may change it."""
    path = os.environ.get("NET_MONITOR_DB") or net_store.DB_PATH
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)


# ------------------------------------------------------------------------------- the payloads

def overview(hours: float) -> dict:
    """Everything the page draws without being asked: health, alerts, and the timelines."""
    conn = _ro_conn()
    try:
        now = time.time()
        since = now - hours * 3600
        cur = net_store.network_identity()
        beat = conn.execute("SELECT MAX(ts) FROM heartbeat").fetchone()[0]
        newest = conn.execute("SELECT MAX(ts) FROM sample").fetchone()[0]

        labels = {r[0]: r[1] for r in conn.execute("SELECT net_id,label FROM net")}
        alerts = []
        for t, m, nid, st, sn, upd in conn.execute(
                "SELECT target,metric,net_id,state,since,updated FROM alert_state "
                "WHERE state NOT IN ('OK','UNKNOWN') ORDER BY updated DESC"):
            alerts.append({
                "target": t, "metric": m, "state": st, "since": sn, "updated": upd,
                "network": labels.get(nid, nid), "current": nid == cur["net_id"],
                "stale": (now - upd) > net_report.STALE_AFTER_S})

        # Driven by the data, not the catalogue: a network can hold samples with no row in
        # `net`, which is exactly what the phantom identities of 2026-09-07 were, and listing
        # catalogue rows would draw nothing for them.
        nets = []
        for nid, label in conn.execute(
                "SELECT d.nid, COALESCE(n.label, d.nid) FROM ("
                "  SELECT DISTINCT net_id AS nid FROM heartbeat WHERE ts>=?"
                "  UNION SELECT DISTINCT net_id FROM sample WHERE ts>=?) d "
                "LEFT JOIN net n ON n.net_id = d.nid "
                "ORDER BY (d.nid=?) DESC, COALESCE(n.last_seen, 0) DESC",
                (since, since, cur["net_id"])):
            tl = net_report.timeline(conn, nid, since, now)
            if not tl["targets"] and not tl["beats"]:
                continue
            tl.update(label=label, current=nid == cur["net_id"])
            nets.append(tl)

        return {
            "now": now, "since": since, "hours": hours,
            # The gateway MAC is deliberately not here. It is the strongest identity signal
            # the store holds and the one that geolocates the machine; the page has no use
            # for it, so it never crosses the socket.
            "network": {"net_id": cur["net_id"], "label": cur["label"],
                        "gateway": cur["gateway"], "strength": cur["strength"],
                        "assumed": cur["assumed"]},
            "collector": {"last_beat": beat, "alive": bool(beat)
                          and (now - beat) < COLLECTOR_STALE_S,
                          "stale_after": COLLECTOR_STALE_S},
            "newest_sample": newest,
            "raw_days": net_memory.RAW_DAYS,
            "alerts": alerts,
            "networks": nets,
        }
    finally:
        conn.close()


def _has_paths(target: str) -> bool:
    conn = _ro_conn()
    try:
        return bool(conn.execute("SELECT 1 FROM path WHERE target=? LIMIT 1",
                                 (target,)).fetchone())
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def _run(name: str, **kw) -> dict:
    """One tool, its output as text. A tool that fails is reported, never dropped: a missing
    panel would read as 'nothing to say here', which is a different claim from 'this could
    not be computed'."""
    fn = READ_ONLY_TOOLS[name]
    t0 = time.time()
    try:
        out = fn(**kw)
        return {"tool": name, "args": kw, "text": str(out).rstrip(),
                "ms": round((time.time() - t0) * 1000), "failed": False}
    except Exception as exc:                                   # noqa: BLE001 - reported, not raised
        return {"tool": name, "args": kw,
                "text": f"{type(exc).__name__}: {exc}",
                "ms": round((time.time() - t0) * 1000), "failed": True}


def detail(target: str, hours: float) -> dict:
    """What the history-reading tools say about one target, in the order an operator asks:
    was it up, has anything changed, what is normal, and did the path move."""
    conn = _ro_conn()
    try:
        known = conn.execute("SELECT 1 FROM sample WHERE target=? LIMIT 1",
                             (target,)).fetchone()
    finally:
        conn.close()
    if not known:
        return {"target": target, "known": False, "panels": [],
                "note": "No sample has ever been stored for this target."}

    panels = [
        _run("availability", target=target, hours=hours),
        _run("detect_change", target=target, metric="all"),
        _run("baseline", target=target),
    ]
    if _has_paths(target):
        panels.append(_run("route_history", target=target))
    else:
        panels.append({"tool": "route_history", "args": {"target": target}, "ms": 0,
                       "failed": False,
                       "text": "No traceroute has been stored for this target, so there is "
                               "no route history to show. That is a statement about what "
                               "was collected, not about the route being stable."})
    return {"target": target, "known": True, "panels": panels}


def upstream(days: float = 7.0) -> dict:
    """The router-level map beyond the gateway, stitched from stored traces. No new packets."""
    return {"panels": [_run("topology", scope="upstream", days=days)]}


# ------------------------------------------------------------------------------------ the page

EXTRA_CSS = """
body { padding:20px 18px 48px }
main { max-width:1180px }
.bar { cursor:pointer }
.row.sel .name { font-weight:700 }
.row.sel .bar { outline:2px solid var(--else); outline-offset:2px }
.topbar { display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin:0 0 6px }
.spacer { flex:1 }
.btn { font:inherit; font-size:12px; padding:3px 10px; border-radius:6px; cursor:pointer;
  border:1px solid var(--line); background:var(--card); color:var(--fg) }
.btn[aria-pressed="true"] { border-color:var(--else); color:var(--else); font-weight:600 }
.lost { background:var(--down); color:#fff; padding:9px 13px; border-radius:7px;
  margin:0 0 14px; font-size:13px }
.dim { opacity:.42; filter:saturate(.35) }
pre { white-space:pre-wrap; word-break:break-word; font:12px/1.5 ui-monospace,
  "Cascadia Mono",Consolas,monospace; margin:0; color:var(--fg) }
.panel { border-top:1px solid var(--line); padding:12px 0 2px }
.panel:first-child { border-top:0 }
.ph { display:flex; align-items:baseline; gap:9px; margin:0 0 7px }
.ph b { font-size:12.5px } .ph span { color:var(--dim); font-size:11.5px }
.detail { position:sticky; top:12px }
.grid { display:grid; grid-template-columns:1fr; gap:14px }
@media (min-width:1000px) { .grid { grid-template-columns:minmax(0,1fr) minmax(0,440px) } }
.age { font-variant-numeric:tabular-nums }
.empty { color:var(--dim); font-size:12.5px }
.fail { color:var(--down) }
"""

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network observability</title>
<style>/*BASE*//*EXTRA*/</style></head>
<body><main>
<div class="topbar">
  <h1 style="margin:0">Network observability <span id="health"></span></h1>
  <span class="spacer"></span>
  <span id="win"></span>
</div>
<p class="sub" id="sub">loading&hellip;</p>
<div id="lost"></div>
<div class="legend">
  <span><i class="key" style="background:var(--up)"></i>measured, reachable</span>
  <span><i class="key" style="background:var(--down)"></i>measured, failing</span>
  <span><i class="key seg gap" style="background:var(--gap)"></i>NOT MEASURED &ndash; unknown,
    not quiet</span>
  <span><i class="key seg else" style="background:var(--else)"></i>not measured here; the
    collector was on another network</span>
</div>
<div id="body">
  <h2 style="margin-top:8px">Alerts not at rest</h2>
  <div id="alerts"></div>
  <div class="grid">
    <div id="nets"></div>
    <div><div class="detail" id="detail"></div></div>
  </div>
</div>
<footer>
Click any bar for what the history tools say about that target. Hover a segment for its exact
span and reason. Hatched time was <b>not observed</b>, which is different from observed and
quiet, and nothing here should be read as a claim about it. A bar is one target's reachability
on one network; histories are never mixed across networks, so a machine that moved shows a gap
on the network it left, not an outage.
<b>This page never measures anything.</b> It reads the store the collector writes and runs
only tools that read stored history, so leaving it open adds nothing to the record it is
showing. Every age below is the age of the data, not of the last refresh. It serves on
loopback only and holds the database open read-only.
</footer>
</main>
<script>
const $ = (s, r) => (r || document).querySelector(s);
const S = { hours: HOURS0, data: null, at: 0, lost: false, sel: null, detail: null,
            busy: false };

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}
function dur(s) {
  s = Math.max(0, s);
  if (s < 60) return Math.round(s) + "s";
  if (s < 5400) return (s / 60).toFixed(0) + "m";
  if (s < 172800) return (s / 3600).toFixed(1) + "h";
  return (s / 86400).toFixed(1) + "d";
}
// Server clock at fetch time, advanced by the client's own elapsed time. Ages therefore keep
// counting up between polls instead of freezing at whatever the last response happened to say.
function serverNow() {
  return S.data ? S.data.now + (Date.now() / 1000 - S.at) : Date.now() / 1000;
}
function pill(cls, text) { const p = el("span", "pill " + cls, text); return p; }

async function poll() {
  try {
    const r = await fetch("/api/overview?hours=" + S.hours, { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    S.data = await r.json();
    S.at = Date.now() / 1000;
    S.lost = false;
  } catch (e) {
    S.lost = true;                      // keep the last payload, but stop calling it current
  }
  render();
}

function renderHead() {
  const d = S.data, now = serverNow();
  const beat = d.collector.last_beat;
  const alive = beat && (now - beat) < d.collector.stale_after;
  $("#health").replaceChildren(
    pill(alive ? "p-ok" : "p-bad", alive ? "collecting" : "NOT COLLECTING"));
  const parts = [];
  parts.push("last " + (+d.hours) + " h");
  parts.push(beat ? "last heartbeat " + dur(now - beat) + " ago"
                  : "no heartbeat ever recorded");
  parts.push(d.newest_sample ? "newest sample " + dur(now - d.newest_sample) + " ago"
                             : "no samples");
  parts.push("currently on " + d.network.label
             + (d.network.assumed ? " (assumed - the link is degraded)" : ""));
  parts.push("raw samples kept " + d.raw_days + " days");
  const sub = $("#sub");
  sub.replaceChildren();
  sub.className = "sub age";
  parts.forEach((p, i) => {
    if (i) sub.appendChild(el("span", null, "  \\u00b7  "));
    sub.appendChild(el("span", null, p));
  });
}

function renderLost() {
  const box = $("#lost");
  box.replaceChildren();
  $("#body").classList.toggle("dim", S.lost);
  if (!S.lost) return;
  const when = new Date(S.at * 1000).toLocaleTimeString();
  box.appendChild(el("div", "lost",
    "This page cannot reach the server. Everything below is from " + when +
    " and is NOT live \\u2014 it is the last answer received, not the current state."));
}

function renderAlerts() {
  const box = $("#alerts"), d = S.data, now = serverNow();
  box.replaceChildren();
  const card = el("div", "card");
  if (!d.alerts.length) {
    card.appendChild(el("p", "note",
      "No signal is in SUSPECT, ALERTING or RECOVERING on any network."));
    box.appendChild(card); return;
  }
  const tb = el("table");
  const hr = el("tr");
  ["target", "metric", "state", "since", "freshness", "network"]
    .forEach(h => hr.appendChild(el("th", null, h)));
  tb.appendChild(hr);
  let stale = 0;
  d.alerts.forEach(a => {
    const tr = el("tr");
    tr.appendChild(el("td", null, a.target));
    tr.appendChild(el("td", null, a.metric));
    const td = el("td");
    td.appendChild(pill(a.state === "ALERTING" ? "p-bad" : "p-warn", a.state));
    tr.appendChild(td);
    tr.appendChild(el("td", "num", dur(now - a.since) + " ago"));
    const f = el("td", "num");
    if (a.stale) { stale++; f.appendChild(pill("p-warn",
      "last evaluated " + dur(now - a.updated) + " ago")); }
    else f.textContent = "evaluated " + dur(now - a.updated) + " ago";
    tr.appendChild(f);
    tr.appendChild(el("td", null, a.network + (a.current ? "" : " (not the current one)")));
    tb.appendChild(tr);
  });
  card.appendChild(tb);
  if (stale) card.appendChild(el("p", "note",
    stale + " of these has not been re-evaluated recently. A held state is correct \\u2014 " +
    "nothing clears without evidence \\u2014 but it describes when it was last checked, not " +
    "now. A signal on a network this machine has left cannot be re-evaluated until it " +
    "returns."));
  box.appendChild(card);
}

function renderNets() {
  const box = $("#nets"), d = S.data;
  box.replaceChildren();
  if (!d.networks.length) {
    const c = el("div", "card");
    c.appendChild(el("p", "note", "No reachability data on any network in this window."));
    box.appendChild(c); return;
  }
  d.networks.forEach(n => {
    const h = el("h2", null, n.label + " ");
    h.appendChild(pill("p-dim", n.net_id));
    box.appendChild(h);
    const card = el("div", "card");
    if (!n.targets.length) {
      card.appendChild(el("p", "note",
        "Heartbeats but no reachability samples in this window."));
      box.appendChild(card); return;
    }
    n.targets.forEach(t => {
      const row = el("div", "row" + (S.sel === t.target ? " sel" : ""));
      const nm = el("div", "name", t.target); nm.title = t.target;
      const bar = el("div", "bar");
      bar.setAttribute("role", "button");
      bar.setAttribute("tabindex", "0");
      bar.title = "click for the history tools on " + t.target;
      t.segments.forEach(s => {
        const g = el("div", "seg " + s.kind);
        g.style.left = s.left.toFixed(4) + "%";
        g.style.width = s.width.toFixed(4) + "%";
        g.title = s.title;
        bar.appendChild(g);
      });
      const open = () => select(t.target);
      bar.addEventListener("click", open);
      bar.addEventListener("keydown", ev => {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); }
      });
      const meta = el("div", "meta");
      meta.appendChild(pill(t.state_class, t.state));
      row.append(nm, bar, meta);
      card.appendChild(row);
    });
    const ticks = el("div", "ticks");
    ticks.appendChild(el("span", null, new Date(d.since * 1000)
      .toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit",
                            minute: "2-digit" })));
    ticks.appendChild(el("span", null, "now"));
    card.appendChild(ticks);
    box.appendChild(card);
  });
}

function renderDetail() {
  const box = $("#detail");
  box.replaceChildren();
  if (!S.sel) {
    const c = el("div", "card");
    c.appendChild(el("p", "empty",
      "Select a target to read what the stored history says about it: availability, whether " +
      "any metric has changed against its own noise floor, its baselines, and the route. " +
      "Nothing here sends a packet."));
    const b = el("button", "btn", "upstream map from stored traces");
    b.addEventListener("click", () => select("\\u0000upstream"));
    c.appendChild(b);
    box.appendChild(c);
    return;
  }
  const card = el("div", "card");
  const head = el("div", "ph");
  head.appendChild(el("b", null, S.sel === "\\u0000upstream"
    ? "upstream map" : S.sel));
  const close = el("button", "btn", "close");
  close.addEventListener("click", () => { S.sel = null; S.detail = null; render(); });
  head.appendChild(el("span", null, S.busy ? "reading stored history\\u2026" : ""));
  const sp = el("span", "spacer"); head.appendChild(sp);
  head.appendChild(close);
  card.appendChild(head);
  if (S.detail && S.detail.note) card.appendChild(el("p", "note", S.detail.note));
  (S.detail ? S.detail.panels : []).forEach(p => {
    const d = el("div", "panel");
    const ph = el("div", "ph");
    ph.appendChild(el("b", null, p.tool));
    ph.appendChild(el("span", null, p.ms + " ms" + (p.failed ? " \\u2014 failed" : "")));
    d.appendChild(ph);
    const pre = el("pre", p.failed ? "fail" : null, p.text);
    d.appendChild(pre);
    card.appendChild(d);
  });
  box.appendChild(card);
}

async function select(target) {
  S.sel = target; S.detail = null; S.busy = true; render();
  try {
    const url = target === "\\u0000upstream"
      ? "/api/upstream"
      : "/api/detail?hours=" + S.hours + "&target=" + encodeURIComponent(target);
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    S.detail = await r.json();
  } catch (e) {
    S.detail = { panels: [{ tool: "request", ms: 0, failed: true,
                            text: "Could not reach the server: " + e.message }] };
  }
  S.busy = false; render();
}

function renderWindow() {
  const box = $("#win");
  if (box.childElementCount) {
    box.querySelectorAll("button").forEach(b =>
      b.setAttribute("aria-pressed", String(+b.dataset.h === +S.hours)));
    return;
  }
  [6, 24, 48, 168].forEach(h => {
    const b = el("button", "btn", h < 48 ? h + " h" : (h / 24) + " d");
    b.dataset.h = h;
    b.setAttribute("aria-pressed", String(h === S.hours));
    b.addEventListener("click", () => { S.hours = h; renderWindow(); poll(); });
    box.appendChild(b);
  });
}

function render() {
  renderWindow();
  if (!S.data) return;
  renderHead(); renderLost(); renderAlerts(); renderNets(); renderDetail();
}

renderWindow();
poll();
setInterval(poll, 15000);
setInterval(() => { if (S.data) { renderHead(); renderAlerts(); } }, 1000);
</script>
</body></html>
"""


def page(hours: float) -> str:
    return (PAGE.replace("/*BASE*/", net_report.CSS)
                .replace("/*EXTRA*/", EXTRA_CSS)
                .replace("HOURS0", f"{hours:g}"))


# ---------------------------------------------------------------------------------- the server

class Handler(BaseHTTPRequestHandler):
    server_version = "net_web"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):                      # quiet by default; --verbose opts in
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    # ------------------------------------------------------------------------------- plumbing
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # Nothing here is meant to be embedded anywhere, and there is no third-party code.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'; "
                         "frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj: dict, code: int = 200) -> None:
        self._send(code, json.dumps(obj, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _text(self, code: int, msg: str) -> None:
        self._send(code, f"<!doctype html><meta charset=utf-8><title>{code}</title>"
                         f"<p>{html.escape(msg)}".encode("utf-8"),
                   "text/html; charset=utf-8")

    def _host_ok(self) -> bool:
        """Reject a request that reached us under a foreign name.

        A site the operator is browsing can resolve its own hostname to 127.0.0.1 and have
        the browser fetch this page from within that origin - DNS rebinding. The socket being
        on loopback does not prevent it; checking the name the request arrived under does.
        """
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        if host.startswith("[") and "]" in (self.headers.get("Host") or ""):
            host = (self.headers.get("Host") or "").split("]")[0] + "]"
        return _is_loopback(host)

    # --------------------------------------------------------------------------------- routes
    def do_HEAD(self):                                                       # noqa: N802
        self.do_GET()

    def do_GET(self):                                                        # noqa: N802
        if not self._host_ok():
            self._text(403, "This server answers on loopback only. The request arrived "
                            "under a different host name and was refused.")
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)

        def hours() -> float:
            try:
                return max(0.1, min(MAX_HOURS, float(q.get("hours", ["24"])[0])))
            except (TypeError, ValueError):
                return 24.0

        try:
            if u.path in ("/", "/index.html"):
                self._send(200, page(hours()).encode("utf-8"), "text/html; charset=utf-8")
            elif u.path == "/api/overview":
                self._json(overview(hours()))
            elif u.path == "/api/detail":
                t = (q.get("target") or [""])[0]
                if not t:
                    self._json({"error": "target is required"}, 400)
                else:
                    self._json(detail(t, hours()))
            elif u.path == "/api/upstream":
                self._json(upstream())
            else:
                self._text(404, "No such path.")
        except sqlite3.OperationalError as exc:
            self._json({"error": f"the store could not be read: {exc}"}, 503)
        except Exception as exc:                       # noqa: BLE001 - never kill the server
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)


DEFAULT_PORT = 8420      # 8787 is inside Hyper-V's reserved range on some Windows machines


def serve(host: str = "127.0.0.1", port: int = DEFAULT_PORT,
          verbose: bool = False) -> ThreadingHTTPServer:
    """Bind and return the server. Refuses any address reachable from another machine."""
    if not _is_loopback(host):
        raise ValueError(
            f"refusing to bind {host!r}: this serves the SSID, the gateway address and this "
            f"machine's local addresses, which locate it. Loopback only. If you need it from "
            f"another machine, forward the port over ssh rather than opening it here.")
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.verbose = verbose
    srv.daemon_threads = True
    return srv


def serve_auto(host: str, port: Optional[int],
               verbose: bool = False) -> ThreadingHTTPServer:
    """As `serve`, but when no port was asked for, find one that works.

    Windows reserves whole ranges for Hyper-V and WSL, and a machine can have the chosen port
    inside one - 8787 is excluded on the machine this was written on. An explicit --port is
    obeyed and its failure reported; an unspecified one walks a few candidates and then lets
    the OS choose, and main() prints whichever it actually got rather than the one it wanted.
    """
    if port is not None:
        return serve(host, port, verbose)
    last: Optional[OSError] = None
    for cand in (DEFAULT_PORT, DEFAULT_PORT + 1, DEFAULT_PORT + 2, 8901, 0):
        try:
            return serve(host, cand, verbose)
        except OSError as exc:
            last = exc
    raise last if last else OSError("no port available")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1", help="loopback only; anything else is "
                                                        "refused")
    ap.add_argument("--port", type=int, default=None,
                    help=f"default {DEFAULT_PORT}; without this, another is tried if it is "
                         f"taken, and the one actually bound is printed")
    ap.add_argument("--hours", type=float, default=24.0, help="the window the page opens on")
    ap.add_argument("--open", action="store_true", help="open a browser at it")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every request")
    a = ap.parse_args()
    try:
        srv = serve_auto(a.host, a.port, a.verbose)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    except OSError as exc:
        print(f"error: cannot bind {a.host}:{a.port if a.port else DEFAULT_PORT} - {exc}")
        return 2
    url = f"http://{a.host}:{srv.server_address[1]}/?hours={a.hours:g}"
    print(f"serving {url}")
    print("Loopback only. It shows the SSID and local addresses - do not forward this port.")
    print("Read-only: it never measures anything and never writes to the store. Ctrl-C stops.")
    if a.open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
