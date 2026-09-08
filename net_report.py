"""Render the store as one self-contained HTML page.

    python net_report.py                  # last 24 h -> net_report.html
    python net_report.py --hours 72 --open

WHY THIS EXISTS, AND WHAT IT DELIBERATELY IS NOT. Everything this project knows is already
available as text, and a dashboard that re-renders numbers is decoration. Two things, though,
are genuinely hard to see in prose and easy to see in a picture:

  SHAPE       a contiguous hour of failure and sixty scattered failures read identically in a
              summary - "p95 loss 100%" - and completely differently on a timeline. The agent
              made exactly that mistake on a real outage before `availability` existed.
  STALENESS   an alert holds its state when there is no new evidence, which is correct. But
              'ALERTING' with no date beside it reads as 'ALERTING now'. One in this database
              had been frozen for 31 hours on a network the machine had left, and nothing
              anywhere said so.

So this is a report, not an interface: no server, no live connection, no state of its own.
It reads the database once and writes a file. Anything it shows can be re-derived from the
CLI tools, and where it cannot show something honestly it says so instead.

THE OUTPUT IS LOCAL AND STAYS LOCAL. It necessarily contains the SSID, the gateway address
and this machine's local addresses - the identifiers net_monitor.db is kept out of the repo
for. net_report.html is in .gitignore. Do not publish it.

The colour rule is the whole design: measured-good, measured-bad and NOT MEASURED are three
states, never two. Unobserved time is never drawn as healthy, and is visually distinct from
both - because the single most common way this kind of tool misleads is by rendering a gap
in the same colour as a quiet period.
"""
from __future__ import annotations

import argparse
import html
import os
import sqlite3
import time
import webbrowser

import net_alert
import net_memory
import net_store

STALE_AFTER_S = 900.0            # an evaluation older than this is not describing "now"

CSS = """
:root {
  --bg:#fbfbfa; --fg:#26241f; --dim:#6b675e; --line:#e3e0d8; --card:#fff;
  --up:#4a8f5f; --down:#c0453c; --gap:#b9b4a8; --else:#5a7d9a; --warn:#b5761f;
}
@media (prefers-color-scheme: dark) {
  :root { --bg:#1a1917; --fg:#e8e5de; --dim:#9a958a; --line:#33312d; --card:#232220;
          --up:#5fa876; --down:#d4605a; --gap:#575349; --else:#6f93b0; --warn:#d09033; }
}
* { box-sizing:border-box }
body { margin:0; padding:28px 20px 60px; background:var(--bg); color:var(--fg);
  font:14px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:1080px; margin:0 auto }
h1 { font-size:20px; margin:0 0 2px } h2 { font-size:15px; margin:34px 0 10px }
.sub { color:var(--dim); font-size:13px; margin:0 0 24px }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px;
  padding:14px 16px; margin-bottom:14px }
.row { display:flex; align-items:center; gap:12px; margin:9px 0 }
.name { width:210px; flex:none; font-size:12.5px; overflow:hidden; text-overflow:ellipsis;
  white-space:nowrap; font-variant-numeric:tabular-nums }
.bar { position:relative; flex:1; height:19px; border-radius:3px; overflow:hidden;
  background:var(--gap); min-width:180px }
.seg { position:absolute; top:0; bottom:0 }
.seg.up { background:var(--up) } .seg.down { background:var(--down) }
.seg.gap { background:repeating-linear-gradient(45deg,var(--gap),var(--gap) 4px,
  transparent 4px,transparent 8px) }
.seg.else { background:repeating-linear-gradient(45deg,var(--else),var(--else) 4px,
  transparent 4px,transparent 8px) }
.meta { width:190px; flex:none; text-align:right; color:var(--dim); font-size:12px;
  font-variant-numeric:tabular-nums }
.legend { display:flex; gap:16px; flex-wrap:wrap; color:var(--dim); font-size:12px;
  margin:6px 0 18px }
.key { display:inline-block; width:22px; height:10px; border-radius:2px;
  vertical-align:middle; margin-right:5px }
table { border-collapse:collapse; width:100% } th,td { text-align:left; padding:6px 10px;
  border-bottom:1px solid var(--line); font-size:12.5px; vertical-align:top }
th { color:var(--dim); font-weight:600 } td.num { font-variant-numeric:tabular-nums }
.pill { display:inline-block; padding:1px 7px; border-radius:99px; font-size:11px;
  font-weight:600; border:1px solid }
.p-ok { color:var(--up); border-color:var(--up) }
.p-bad { color:var(--down); border-color:var(--down) }
.p-warn { color:var(--warn); border-color:var(--warn) }
.p-dim { color:var(--dim); border-color:var(--line) }
.note { color:var(--dim); font-size:12.5px; margin:8px 0 0 }
.ticks { display:flex; margin:2px 0 0 222px; color:var(--dim); font-size:11px;
  justify-content:space-between }
footer { color:var(--dim); font-size:12px; margin-top:40px; border-top:1px solid var(--line);
  padding-top:14px; max-width:70ch }
"""


def e(s) -> str:
    return html.escape(str(s), quote=True)


def dur(s: float) -> str:
    if s < 60:
        return "<1m"
    if s < 5400:
        return f"{s / 60:.0f}m"
    if s < 172800:
        return f"{s / 3600:.1f}h"
    return f"{s / 86400:.1f}d"


def ago(ts: float, now: float) -> str:
    return f"{dur(now - ts)} ago"


def _segments(conn, target: str, net_id: str, since: float, now: float,
              beats: list, cadence: float, other: list) -> tuple[list, dict]:
    """Runs for one target, as (kind, left%, width%, title) plus a small summary."""
    rows = list(conn.execute(
        "SELECT ts, value FROM sample WHERE target=? AND metric='reachable' AND net_id=? "
        "AND ts>=? ORDER BY ts", (target, net_id, since)))
    if not rows:
        return [], {}
    runs = net_memory._runs(rows, since, now, beats, cadence, other)
    span = max(1e-9, now - since)
    segs, tot = [], {"up": 0.0, "down": 0.0, "gap": 0.0}
    for r in runs:
        a, b = max(r["start"], since), min(r["end"], now)
        if b <= a:
            continue
        kind = r["kind"]
        tot[kind] = tot.get(kind, 0.0) + (b - a)
        css, why = kind, ""
        if kind == "gap":
            why = net_memory._gap_reason(r, now)
            if r.get("elsewhere") and net_memory._elsewhere_share(
                    r["elsewhere"], r["start"], r["end"])[2] >= 0.8:
                css = "else"
        elif kind == "down":
            why = (f"{r['n']} consecutive failure(s)"
                   + ("; END UNKNOWN - measurement stopped while still down"
                      if r.get("open_end") else ""))
        else:
            why = f"{r['n']} successful probe(s)"
        label = {"up": "up", "down": "DOWN", "gap": "not measured",
                 "else": "not measured here"}[css]
        segs.append((css, 100.0 * (a - since) / span, 100.0 * (b - a) / span,
                     f"{time.strftime('%d %b %H:%M', time.localtime(a))} - "
                     f"{time.strftime('%d %b %H:%M', time.localtime(b))}  "
                     f"({dur(b - a)})  {label}: {why}"))
    longest = max((r for r in runs if r["kind"] == "down"),
                  key=lambda r: r["end"] - r["start"], default=None)
    return segs, {"tot": tot, "longest": longest, "probes": len(rows)}


def _network_section(conn, net: dict, since: float, now: float) -> str:
    nid = net["net_id"]
    beats = [r[0] for r in conn.execute(
        "SELECT ts FROM heartbeat WHERE net_id=? AND ts>=? ORDER BY ts", (nid, since))]
    bd = [b - a for a, b in zip(beats, beats[1:]) if b > a]
    cadence = sorted(bd)[len(bd) // 2] if bd else 0.0
    other = list(conn.execute(
        "SELECT h.ts, COALESCE(n.label, h.net_id) FROM heartbeat h "
        "LEFT JOIN net n ON n.net_id=h.net_id WHERE h.ts>=? AND h.net_id!=? ORDER BY h.ts",
        (since, nid)))
    targets = [r[0] for r in conn.execute(
        "SELECT target FROM sample WHERE net_id=? AND metric='reachable' AND ts>=? "
        "GROUP BY target HAVING COUNT(*)>=3 ORDER BY target", (nid, since))]
    if not targets and not beats:
        return ""

    out = [f'<h2>{e(net["label"])} <span class="pill p-dim">{e(nid)}</span></h2>',
           '<div class="card">']
    if not targets:
        out.append('<p class="note">Heartbeats but no reachability samples in this '
                   'window.</p></div>')
        return "\n".join(out)

    for t in targets:
        segs, sm = _segments(conn, t, nid, since, now, beats, cadence, other)
        if not segs:
            continue
        bars = "".join(
            f'<div class="seg {c}" style="left:{l:.4f}%;width:{w:.4f}%" title="{e(ti)}"></div>'
            for c, l, w, ti in segs)
        down, gap = sm["tot"].get("down", 0), sm["tot"].get("gap", 0)
        if down > 0:
            meta = f'<span class="pill p-bad">down {dur(down)}</span>'
        elif gap > 0.5 * (now - since):
            meta = '<span class="pill p-dim">mostly unobserved</span>'
        else:
            meta = '<span class="pill p-ok">no failure seen</span>'
        out.append(f'<div class="row"><div class="name" title="{e(t)}">{e(t)}</div>'
                   f'<div class="bar">{bars}</div><div class="meta">{meta}</div></div>')
    lo = time.strftime("%d %b %H:%M", time.localtime(since))
    hi = time.strftime("%d %b %H:%M", time.localtime(now))
    out.append(f'<div class="ticks"><span>{lo}</span><span>{hi}</span></div>')
    out.append("</div>")
    return "\n".join(out)


def _alerts_table(conn, now: float, current_net: str) -> str:
    labels = {r[0]: r[1] for r in conn.execute("SELECT net_id,label FROM net")}
    rows = list(conn.execute(
        "SELECT target,metric,net_id,state,since,updated FROM alert_state "
        "WHERE state NOT IN ('OK','UNKNOWN') ORDER BY updated DESC"))
    if not rows:
        return ('<div class="card"><p class="note">No signal is in SUSPECT, ALERTING or '
                'RECOVERING on any network.</p></div>')
    body, stale_n = [], 0
    for t, m, nid, st, since, updated in rows:
        stale = (now - updated) > STALE_AFTER_S
        stale_n += stale
        where = labels.get(nid, nid) + ("" if nid == current_net else " (not the current one)")
        pill = "p-bad" if st == "ALERTING" else "p-warn"
        age = (f'<span class="pill p-warn">last evaluated {ago(updated, now)}</span>'
               if stale else f'evaluated {ago(updated, now)}')
        body.append(f'<tr><td>{e(t)}</td><td>{e(m)}</td>'
                    f'<td><span class="pill {pill}">{e(st)}</span></td>'
                    f'<td class="num">{e(ago(since, now))}</td><td class="num">{age}</td>'
                    f'<td>{e(where)}</td></tr>')
    note = ""
    if stale_n:
        note = (f'<p class="note"><b>{stale_n} of these has not been re-evaluated recently.</b> '
                f'A held state is correct - nothing clears without evidence - but it describes '
                f'when it was last checked, not now. A signal on a network this machine has '
                f'left cannot be re-evaluated until it returns.</p>')
    return ('<div class="card"><table><tr><th>target</th><th>metric</th><th>state</th>'
            '<th>since</th><th>freshness</th><th>network</th></tr>'
            + "".join(body) + "</table>" + note + "</div>")


def build(hours: float = 24.0, db: str = "") -> str:
    path = db or os.environ.get("NET_MONITOR_DB") or net_store.DB_PATH
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        now = time.time()
        since = now - hours * 3600
        cur = net_store.network_identity()
        hb = conn.execute("SELECT MAX(ts) FROM heartbeat").fetchone()[0]
        alive = hb is not None and (now - hb) < 300
        cls = "p-ok" if alive else "p-bad"
        word = "collecting" if alive else "NOT COLLECTING"
        health = f'<span class="pill {cls}">{word}</span>'
        beat = f"last heartbeat {ago(hb, now)}" if hb else "no heartbeats ever recorded"

        # Driven by the DATA, not by the net catalogue, with the catalogue joined on only for
        # a label. A network can hold samples without a row in `net` - that is precisely what
        # the phantom identities of 2026-09-07 were - and a report that lists catalogue rows
        # would draw nothing at all for them, hiding the very data worth looking at.
        nets = [dict(net_id=r[0], label=r[1]) for r in conn.execute(
            "SELECT d.nid, COALESCE(n.label, d.nid) FROM ("
            "  SELECT DISTINCT net_id AS nid FROM heartbeat WHERE ts>=?"
            "  UNION SELECT DISTINCT net_id FROM sample WHERE ts>=?) d "
            "LEFT JOIN net n ON n.net_id = d.nid "
            "ORDER BY (d.nid=?) DESC, COALESCE(n.last_seen, 0) DESC",
            (since, since, cur["net_id"]))]
        sections = "\n".join(filter(None, (_network_section(conn, n, since, now)
                                           for n in nets)))
        if not sections:
            sections = ('<div class="card"><p class="note">No reachability data on any '
                        'network in this window.</p></div>')

        legend = ('<div class="legend">'
                  '<span><i class="key" style="background:var(--up)"></i>measured, reachable'
                  '</span>'
                  '<span><i class="key" style="background:var(--down)"></i>measured, failing'
                  '</span>'
                  '<span><i class="key seg gap" style="background:var(--gap)"></i>'
                  'NOT MEASURED - unknown, not quiet</span>'
                  '<span><i class="key seg else" style="background:var(--else)"></i>'
                  'not measured here; the collector was on another network</span></div>')
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network observability - {e(cur['label'])}</title><style>{CSS}</style></head>
<body><main>
<h1>Network observability {health}</h1>
<p class="sub">Last {hours:g} h &middot; generated {time.strftime('%d %b %Y %H:%M')} &middot;
{e(beat)} &middot; currently on <b>{e(cur['label'])}</b>
&middot; raw samples kept {net_memory.RAW_DAYS:g} days</p>
{legend}
<h2 style="margin-top:8px">Alerts not at rest</h2>
{_alerts_table(conn, now, cur['net_id'])}
{sections}
<footer>Hover any segment for its exact span and reason. Hatched time was
<b>not observed</b>: that is different from observed and quiet, and nothing here should be
read as a claim about it. A bar is one target's reachability on one network - histories are
never mixed across networks, so a machine that moved shows a gap on the network it left, not
an outage. Down periods whose end was never observed are labelled END UNKNOWN in their
tooltip. This file is a snapshot of a database, not a live view.</footer>
</main></body></html>"""
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hours", type=float, default=24.0)
    ap.add_argument("-o", "--out", default="net_report.html")
    ap.add_argument("--open", action="store_true", help="open it in a browser afterwards")
    a = ap.parse_args()
    page = build(a.hours)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(page)
    full = os.path.abspath(a.out)
    print(f"wrote {full}  ({len(page) / 1024:.0f} kB)")
    print("Contains the SSID and local addresses - keep it local; it is in .gitignore.")
    if a.open:
        webbrowser.open(f"file:///{full.replace(os.sep, '/')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
