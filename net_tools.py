"""Read-only network diagnostic tools for the observability agent.

Every tool here is a MEASUREMENT, never a change: nothing reconfigures an interface, opens a
listener, or writes to the network beyond the probe itself. That boundary is deliberate - an
agent that can only observe cannot break the thing it is diagnosing.

Design notes that matter when reading the code:

* No `shell=True` anywhere, and every host argument goes through `_check_host()`. Arguments are
  passed as a list, so a hostname cannot smuggle in a second command.
* Windows `ping`/`tracert` print in the system language, so nothing here depends on parsing
  English words. Numbers are pulled with permissive regexes and the raw output is returned
  alongside, letting the model read what the parser could not.
* Counts, hop limits and timeouts are capped. These are diagnostics for hosts the operator
  names - the caps keep a mistyped argument from turning one into a scan.

Runnable on its own: `python net_tools.py` exercises every tool once against a public host.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from typing import Optional

IS_WINDOWS = platform.system().lower().startswith("win")

MAX_PING_COUNT = 20
MAX_HOPS = 30
MAX_TIMEOUT_S = 10.0
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]{1,253}$")


class ToolError(Exception):
    """Raised for input the tool refuses. The agent sees the message and can correct itself."""


def _check_host(host: str) -> str:
    host = (host or "").strip()
    if not host:
        raise ToolError("host is empty")
    if not _HOST_RE.match(host):
        raise ToolError(
            f"refusing host {host!r}: only letters, digits, dots, hyphens, colons and "
            "brackets are allowed (this blocks argument injection)"
        )
    return host


# Windows pops a console window for every child process. The collector runs several a minute,
# so without this the screen flashes constantly and the machine is unusable while it monitors.
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}


def _run(cmd: list[str], timeout: float) -> tuple[int, str]:
    """Run a diagnostic binary and return (returncode, combined output). Never uses a shell."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           encoding="utf-8", errors="replace", **_NO_WINDOW)
    except FileNotFoundError:
        raise ToolError(f"{cmd[0]!r} is not available on this machine")
    except subprocess.TimeoutExpired:
        return 124, f"(timed out after {timeout:.0f}s)"
    return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()


def _numbers_after(pattern: str, text: str) -> list[float]:
    return [float(m.replace(",", ".")) for m in re.findall(pattern, text)]


# --------------------------------------------------------------------------- tools

def ping(host: str, count: int = 5) -> str:
    """Measure ICMP round-trip time and packet loss to a host.

    Use this first for "is X reachable" and "is X slow". If it reports 100% loss, that does not
    prove the host is down - many networks drop ICMP while still serving traffic, so follow up
    with tcp_latency on a port the host actually serves.

    Args:
        host: Hostname or IP address, e.g. "1.1.1.1" or "example.com".
        count: Number of echo requests to send, 1-20. More gives a steadier average.
    """
    host = _check_host(host)
    count = max(1, min(int(count), MAX_PING_COUNT))
    if IS_WINDOWS:
        cmd = ["ping", "-n", str(count), "-w", "2000", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]
    rc, out = _run(cmd, timeout=count * 3 + 10)

    # Locale-independent RTT parsing. Take samples ONLY from per-reply lines, identified by
    # the "TTL=" token - which is not translated in any locale. Matching "<number> ms" across
    # the whole output also catches the trailing "Minimum/Maximum/Average" summary, which
    # double-counts every packet and skews the mean.
    reply_lines = [l for l in out.splitlines() if re.search(r"ttl\s*=", l, re.I)]
    pat = r"[=<]\s*([0-9]+(?:[.,][0-9]+)?)\s*ms"
    rtts = _numbers_after(pat, "\n".join(reply_lines)) or _numbers_after(pat, out)
    losses = _numbers_after(r"([0-9]+(?:[.,][0-9]+)?)\s*%", out)
    lines = [f"host={host}  packets_sent={count}  exit_code={rc}"]
    if rtts:
        lines.append(f"rtt_ms: min={min(rtts):.1f} avg={sum(rtts)/len(rtts):.1f} "
                     f"max={max(rtts):.1f} samples={len(rtts)}")
    if losses:
        lines.append(f"loss_percent_reported={max(losses):.0f}")
    if not rtts:
        lines.append("no RTT samples parsed - read the raw output below")
    lines.append("--- raw ---")
    lines.append(out[:2000])
    return "\n".join(lines)


def tcp_latency(host: str, port: int = 443, attempts: int = 5) -> str:
    """Measure TCP handshake latency to a host and port, in pure Python.

    This is the reliable fallback when ping shows loss: it uses ordinary TCP, so it works
    wherever the service itself works, and it measures what a real client would experience.
    A success here alongside 100% ICMP loss means the network is filtering ping, not broken.

    Args:
        host: Hostname or IP address.
        port: TCP port to connect to, e.g. 443 for HTTPS, 80 for HTTP, 53 for DNS.
        attempts: How many connections to time, 1-20.
    """
    host = _check_host(host)
    port = int(port)
    if not 1 <= port <= 65535:
        raise ToolError(f"port {port} out of range 1-65535")
    attempts = max(1, min(int(attempts), MAX_PING_COUNT))

    times, errors = [], []
    for _ in range(attempts):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=5.0):
                times.append((time.perf_counter() - t0) * 1000.0)
        except Exception as e:
            errors.append(e)
    out = [f"host={host} port={port} attempts={attempts} "
           f"succeeded={len(times)} failed={len(errors)}"]
    if times:
        out.append(f"handshake_ms: min={min(times):.1f} avg={sum(times)/len(times):.1f} "
                   f"max={max(times):.1f}")
    if errors:
        # Say what KIND of failure, not just that there were failures. "failed=5" with a
        # timeout and "failed=5" with a refusal are opposite findings about the host.
        kinds: dict[str, tuple[int, str]] = {}
        for e in errors:
            label, meaning = _connect_failure(e)
            n, _m = kinds.get(label, (0, meaning))
            kinds[label] = (n + 1, meaning)
        out.append("failures: " + ", ".join(f"{k} x{n}" for k, (n, _m) in kinds.items()))
        for k, (_n, meaning) in kinds.items():
            out.append(f"  {k}: {meaning}")
        uniq = sorted({f"{type(e).__name__}: {e}" for e in errors})
        out.append("raw errors: " + "; ".join(uniq[:3]))
    return "\n".join(out)


def traceroute(host: str, max_hops: int = 20) -> str:
    """Trace the network path to a host, hop by hop.

    Use this when latency is high or a route looks wrong, to find WHERE the problem is rather
    than just that it exists. Hops showing "*" are not necessarily broken - many routers
    decline to answer probes while still forwarding traffic normally. What matters is whether
    latency jumps at a hop and stays high for every hop after it.

    Probes are ICMP on every platform, so the whole trace is one flow and its hops belong
    to one path. (UDP traceroute makes each hop a different flow, and over load balancing
    the hops it lists can come from different routes.)

    Args:
        host: Hostname or IP address to trace toward.
        max_hops: Stop after this many hops, 1-30. Lower is much faster.
    """
    host = _check_host(host)
    max_hops = max(1, min(int(max_hops), MAX_HOPS))
    note = ""
    if IS_WINDOWS:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1500", host]
        rc, out = _run(cmd, timeout=max_hops * 4 + 20)
    elif shutil.which("traceroute"):
        # ICMP, not the UDP default. UDP traceroute gives every hop's probes a different
        # destination port, so under per-flow load balancing hop 2 and hop 3 are answered
        # by DIFFERENT flows and the "path" is stitched from two routes: in the lab, 1836
        # traces drew r1 -> r3 -> r4's r2-side interface, a link that does not exist, and
        # nothing in the output could show it - every hop line carried one address. ICMP
        # keeps one flow key for the whole trace, so the hops belong to one path. It needs
        # a raw socket; where that is refused, UDP is used and the caveat is attached.
        cmd = ["traceroute", "-I", "-n", "-m", str(max_hops), "-w", "2", host]
        rc, out = _run(cmd, timeout=max_hops * 4 + 20)
        if rc != 0 and re.search(r"permitted|permission|raw socket|must be root", out, re.I):
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "2", host]
            rc, out = _run(cmd, timeout=max_hops * 4 + 20)
            note = ("\nNOTE: UDP probes (ICMP needs a raw socket this user lacks). Each hop's "
                    "probes are a separate flow, so over per-flow load balancing consecutive "
                    "hops may belong to different paths.")
    else:
        raise ToolError("no traceroute binary found")
    return f"host={host} max_hops={max_hops} exit_code={rc}{note}\n--- raw ---\n{out[:4000]}"


def dns_lookup(name: str, record_type: str = "A") -> str:
    """Resolve a DNS name and report what the resolver returned, with timing.

    Use this to separate "the name does not resolve" from "the host does not answer" - a very
    common confusion when something is unreachable. Slow resolution here, with fast pings to
    the resulting IP, points at the DNS server rather than the network.

    Args:
        name: The domain name to resolve, e.g. "example.com".
        record_type: A, AAAA, CNAME, MX, NS, TXT or SOA.
    """
    name = _check_host(name)
    record_type = (record_type or "A").upper().strip()
    if record_type not in {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"}:
        raise ToolError(f"unsupported record type {record_type!r}")
    try:
        import dns.resolver  # dnspython
    except ImportError:
        # Fall back to the stdlib, which only knows addresses
        if record_type not in ("A", "AAAA"):
            raise ToolError(f"{record_type} lookups need dnspython (pip install dnspython)")
        fam = socket.AF_INET if record_type == "A" else socket.AF_INET6
        t0 = time.perf_counter()
        try:
            infos = socket.getaddrinfo(name, None, fam)
        except socket.gaierror as e:
            return f"name={name} type={record_type} FAILED: {e}"
        ms = (time.perf_counter() - t0) * 1000
        addrs = sorted({i[4][0] for i in infos})
        return (f"name={name} type={record_type} resolved_in_ms={ms:.1f}\n"
                + "\n".join(addrs))

    resolver = dns.resolver.Resolver()
    # Ask the servers the OS asks. Left to itself, dnspython on Windows collects the resolvers
    # of every adapter - a disconnected Ethernet port's included - and walks them in order.
    # An earlier version of this tool did exactly that, timed out on three servers the OS
    # never uses, and then TOLD the agent, in the text below, that the machine's DNS was
    # misconfigured. The agent repeated it twice on live data. The machine was fine.
    active = _active_resolvers()
    if active:
        resolver.nameservers = active
    resolver.timeout, resolver.lifetime = 2.0, 6.0
    t0 = time.perf_counter()
    try:
        ans = resolver.resolve(name, record_type)
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        note = (f"name={name} type={record_type} failed_after_ms={ms:.1f}\n"
                f"{type(e).__name__}: {e}\n"
                f"resolvers_asked={resolver.nameservers}"
                + ("" if active else "  (library default: may include adapters not in use)"))
        # Compare with the OS resolver and report the difference as an observation, not a
        # verdict. When both used the same servers, the OS succeeding usually means its cache
        # answered; when this tool fell back to the library default, the difference says
        # nothing about the machine's configuration at all.
        if record_type in ("A", "AAAA"):
            fam = socket.AF_INET if record_type == "A" else socket.AF_INET6
            try:
                t1 = time.perf_counter()
                infos = socket.getaddrinfo(name, None, fam)
                ms2 = (time.perf_counter() - t1) * 1000
                addrs = sorted({i[4][0] for i in infos})
                note += (f"\n\nBUT the OS resolver SUCCEEDED in {ms2:.1f} ms: {addrs}\n"
                         "=> the name resolves on this machine. The difference is the OS "
                         "cache, or a resolver this tool did not ask; it is NOT evidence of "
                         "a misconfiguration. Use local_network to see which resolver the "
                         "routed adapter uses, and dns_query_server to test it directly.")
            except socket.gaierror as e2:
                note += (f"\n\nOS resolver also failed: {e2}\n"
                         "=> the name does not resolve on this machine right now. Test the "
                         "routed adapter's resolver directly with dns_query_server, and a "
                         "public one, to separate 'this resolver refuses it' from 'the name "
                         "does not exist'.")
        return note
    ms = (time.perf_counter() - t0) * 1000
    recs = [r.to_text() for r in ans]
    return (f"name={name} type={record_type} resolved_in_ms={ms:.1f} "
            f"ttl={ans.rrset.ttl} resolver={resolver.nameservers[:2]}\n" + "\n".join(recs))


def dns_query_server(server: str, name: str = "example.com", record_type: str = "A",
                     protocol: str = "udp") -> str:
    """Send a DNS query to ONE named server over UDP or TCP, and report what came back.

    This is the tool that separates "the DNS server is unreachable" from "UDP port 53 is
    filtered" - a distinction none of the other tools can make, because check_port and
    tcp_latency only ever speak TCP. Many networks (universities and hotels especially) permit
    ping and TCP to a public resolver while dropping or hijacking outbound UDP/53, to force
    clients onto the local resolver. The signature of that is this tool succeeding with
    protocol="tcp" and timing out with protocol="udp" against the same server.

    Query the same server both ways when a resolver looks broken but the host answers ping.

    Args:
        server: IP address of the DNS server to query directly, e.g. "8.8.8.8".
        name: The domain name to ask about. Any well-known name works as a probe.
        record_type: A, AAAA, CNAME, MX, NS, TXT or SOA.
        protocol: "udp" (what resolvers use by default) or "tcp" (the fallback path).
    """
    server = _check_host(server)
    name = _check_host(name)
    record_type = (record_type or "A").upper().strip()
    protocol = (protocol or "udp").lower().strip()
    if protocol not in ("udp", "tcp"):
        raise ToolError("protocol must be 'udp' or 'tcp'")
    if record_type not in {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"}:
        raise ToolError(f"unsupported record type {record_type!r}")
    try:
        import dns.message
        import dns.query
        import dns.rcode
    except ImportError:
        raise ToolError("this tool needs dnspython (pip install dnspython)")

    query = dns.message.make_query(name, record_type)
    t0 = time.perf_counter()
    try:
        send = dns.query.udp if protocol == "udp" else dns.query.tcp
        resp = send(query, server, timeout=5.0)
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        return (f"server={server} protocol={protocol} name={name} type={record_type} "
                f"FAILED after_ms={ms:.1f} ({type(e).__name__}: {e})\n"
                f"hint: if this server answers over tcp but not udp, outbound UDP/53 is "
                f"being filtered rather than the server being down")
    ms = (time.perf_counter() - t0) * 1000
    rcode = dns.rcode.to_text(resp.rcode())
    answers = [r.to_text() for rrset in resp.answer for r in rrset] or ["(no answer records)"]
    return (f"server={server} protocol={protocol} name={name} type={record_type} "
            f"rcode={rcode} elapsed_ms={ms:.1f}\n" + "\n".join(answers[:10]))


def _connect_failure(e: Exception) -> tuple[str, str]:
    """(label, meaning) for a failed TCP connect. Three outcomes, and they mean OPPOSITE things.

    Until this existed, check_port reported every one of them as CLOSED_OR_FILTERED with the
    exception name in parentheses - so a refusal (the host is alive and said no), a timeout
    (a firewall dropped it, or the host is gone; indistinguishable from here) and a name that
    never resolved (the port was never tested at all) all carried the same verdict. On a
    hotspot whose resolver refuses example.com, "check_port example.com 9999" answered
    CLOSED_OR_FILTERED: a DNS failure reported as a port status. Same shape as dns_lookup and
    http_check - the instrument's own limitation, presented as a fact about the target.
    """
    if isinstance(e, socket.gaierror):
        return "UNRESOLVED", ("the name did not resolve, so the port was never tested; this "
                              "says nothing about the port or the host. Resolve the name "
                              "first (dns_lookup, dns_query_server)")
    if isinstance(e, (ConnectionRefusedError, ConnectionResetError)):
        return "REFUSED", ("the host is UP and answered - nothing is listening on this port, "
                           "or something there rejects connections")
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "NO_ANSWER", ("no reply at all. Either a firewall silently drops this port, or "
                             "the host is unreachable - those cannot be told apart from here. "
                             "Test a port the host is known to serve to separate them")
    return "UNREACHABLE", f"failed below TCP, at the network layer ({type(e).__name__})"


def check_port(host: str, port: int) -> str:
    """Check whether a single TCP port accepts a connection, and read any banner offered.

    Use this to confirm a specific service is listening, as opposed to the host merely being
    up. One port per call - this is a diagnostic, not a scanner.

    A failure is one of four things and the result says which, because they mean different
    things: REFUSED proves the host is up; NO_ANSWER cannot distinguish a firewall from a dead
    host; UNRESOLVED means the port was never tested; UNREACHABLE is a routing failure.

    Args:
        host: Hostname or IP address.
        port: The TCP port to test, 1-65535.
    """
    host = _check_host(host)
    port = int(port)
    if not 1 <= port <= 65535:
        raise ToolError(f"port {port} out of range 1-65535")
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=5.0) as s:
            ms = (time.perf_counter() - t0) * 1000
            banner = ""
            try:
                s.settimeout(1.5)
                banner = s.recv(200).decode("utf-8", "replace").strip()
            except Exception:
                pass
            return (f"host={host} port={port} OPEN connect_ms={ms:.1f}"
                    + (f"\nbanner: {banner[:200]}" if banner else ""))
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        label, meaning = _connect_failure(e)
        return (f"host={host} port={port} {label} after_ms={ms:.1f}\n"
                f"  {meaning} ({type(e).__name__}: {e})")


def _http_context():
    """The system trust store plus certifi's bundle, when certifi is installed.

    Python on Windows enumerates the local ROOT store, and this machine's OpenSSL 1.1.1 could
    not build a chain for Let's Encrypt's 2026 intermediates from it: "certificate has
    expired" for cloudflare.com and wikipedia.org, both valid to November. Windows verified
    them - SChannel fetches a missing intermediate on demand, OpenSSL does not. Adding
    certifi's maintained bundle ON TOP of the system store closes the gap without dropping
    any CA an organisation installed locally.
    """
    import ssl
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    return ctx


def _schannel_check(url: str) -> Optional[tuple[int, int, float]]:
    """(http_code, ssl_verify_result, seconds) from Windows' own TLS stack.

    Via the curl.exe that ships in System32 - that one specifically, not whichever curl is
    first on PATH, because Git's curl uses OpenSSL with its own bundle and would only repeat
    the question. None when unavailable, so the caller falls back to a plain failure.
    """
    if not IS_WINDOWS:
        return None
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "curl.exe")
    if not os.path.exists(exe):
        return None
    rc, raw = _run([exe, "-sS", "-o", os.devnull, "-w",
                    "%{http_code} %{ssl_verify_result} %{time_total}",
                    "-I", "--max-time", "10", url], timeout=15)
    m = re.search(r"(\d{3}) (\d+) ([\d.]+)\s*$", raw)
    if rc != 0 or not m:
        return None
    return int(m.group(1)), int(m.group(2)), float(m.group(3))


def http_check(url: str) -> str:
    """Fetch just the headers of an HTTP(S) URL and report status and timing.

    Use this to tell "the server is reachable" from "the server is working" - a host can ping
    fine, accept TCP on 443, and still return 502. Only the headers are fetched, so this is
    cheap and reads no page content.

    A TLS verification failure is checked against Windows' own TLS stack before being
    reported. If Windows verifies the certificate, the failure was this tool's trust store,
    not the site, and the result says so - the status Windows got is reported as the
    measurement. Only when both fail is the certificate reported as untrusted.

    Args:
        url: Full URL including scheme, e.g. "https://example.com".
    """
    import ssl
    import urllib.error
    import urllib.request

    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ToolError("url must start with http:// or https://")
    req = urllib.request.Request(url, method="HEAD",
                                headers={"User-Agent": "net-observability-agent/1.0"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10, context=_http_context()) as r:
            ms = (time.perf_counter() - t0) * 1000
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            keep = {k: hdrs[k] for k in ("server", "content-type", "location", "cache-control")
                    if k in hdrs}
            return (f"url={url} status={r.status} elapsed_ms={ms:.1f}\n"
                    + "\n".join(f"{k}: {v}" for k, v in keep.items()))
    except urllib.error.HTTPError as e:
        ms = (time.perf_counter() - t0) * 1000
        return f"url={url} status={e.code} elapsed_ms={ms:.1f} (HTTP error, host responded)"
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        cause = e.reason if isinstance(e, urllib.error.URLError) else e
        if isinstance(cause, socket.gaierror):
            # The name did not resolve, so the site was never contacted. This was reported as
            # FAILED like any other failure, and the store filed it as reachable=0: on the
            # hotspot, whose resolver refuses example.com, the 48 h report then showed
            # "https://example.com down 2.0 h" for a site that had never been asked. The DNS
            # probes carry the resolution failure; this one says nothing about the site.
            return (f"url={url} UNRESOLVED after_ms={ms:.1f} (the name did not resolve, so the "
                    f"site was never contacted; this says nothing about whether it is up. "
                    f"Check dns_lookup for the name and local_network for which resolver "
                    f"answered. {cause})")
        if isinstance(cause, ssl.SSLCertVerificationError):
            # The first version reported this as "FAILED ... certificate has expired" for
            # certificates that were valid, because the failure was in the local store. An
            # instrument that cannot tell its own limitation from the thing it measures
            # will be believed about the thing it measures.
            alt = _schannel_check(url)
            if alt and alt[1] == 0 and alt[0] > 0:
                return (f"url={url} status={alt[0]} elapsed_ms={alt[2] * 1000:.1f} "
                        f"(verified by Windows SChannel; this tool's own trust store could not "
                        f"build the certificate chain - a local CA gap on THIS machine, not a "
                        f"fault of the site. {cause})")
            if alt:
                return (f"url={url} FAILED after_ms={ms:.1f} (TLS verification failed in BOTH "
                        f"this tool's trust store and Windows' - the certificate presented is "
                        f"not trusted here. Interception, or a bad certificate. {cause})")
        return f"url={url} FAILED after_ms={ms:.1f} ({type(e).__name__}: {e})"


def _as_list(v) -> list[str]:
    """The adapter fields arrive as comma-joined strings; split, and drop empties/nulls."""
    if not v or not isinstance(v, str):
        return []
    return [x.strip() for x in v.split(",") if x.strip()]


def _windows_adapters() -> list[dict]:
    """Every adapter with its status, address, gateway and resolvers, from PowerShell.

    PowerShell rather than `ipconfig /all` because the cmdlet's property values are not
    localised, and this machine prints ipconfig in whichever language Windows was installed
    in. A fixed command with no user input, run as an argument list - no shell.

    Lists are joined into strings on the PowerShell side on purpose. Windows PowerShell 5.1
    serialises a nested collection as {"value": [...], "Count": n} rather than as an array,
    and the first version printed "dns value, Count" for the one adapter that had several
    resolvers - which was the adapter the whole fix was about.
    """
    now = time.time()
    if now - _ADAPTERS["at"] < 30:                 # a question makes several lookups; one launch
        return list(_ADAPTERS["data"])
    script = ("Get-NetIPConfiguration -All | Select-Object InterfaceAlias,"
              "@{n='status';e={[string]$_.NetAdapter.Status}},"
              "@{n='ip';e={@($_.IPv4Address.IPAddress) -join ','}},"
              "@{n='gw';e={@($_.IPv4DefaultGateway.NextHop) -join ','}},"
              "@{n='dns';e={@(($_.DNSServer | Where-Object AddressFamily -eq 2)"
              ".ServerAddresses) -join ','}} | ConvertTo-Json -Compress")
    rc, raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                   timeout=25)
    start = min((i for i in (raw.find("["), raw.find("{")) if i >= 0), default=-1)
    data: list[dict] = []
    if rc == 0 and start >= 0:
        try:
            parsed = json.loads(raw[start:])
            data = [parsed] if isinstance(parsed, dict) else list(parsed)
        except ValueError:
            data = []
    _ADAPTERS.update(at=now, data=data)
    return list(data)


_ADAPTERS: dict = {"at": 0.0, "data": []}


def _active_resolvers() -> list[str]:
    """The DNS servers of the adapter(s) that carry a default route - what the OS actually
    uses for internet names. Empty when that cannot be established (non-Windows, or
    PowerShell unavailable), in which case the resolver library's own default stands.

    This exists because dnspython on Windows gathers the resolvers of EVERY adapter, unplugged
    ones included, and tries them in order. On this machine that meant three unreachable
    servers from a disconnected Ethernet port, six seconds of timeouts, and a diagnosis of
    "stale DNS configuration" for a laptop whose OS was resolving names in 8 ms.
    """
    out: list[str] = []
    for a in _windows_adapters():
        if str(a.get("status")).lower() == "up" and _as_list(a.get("gw")):
            out.extend(d for d in _as_list(a.get("dns")) if d not in out)
    return out


def local_network() -> str:
    """Report this machine's own network configuration, PER ADAPTER: status, address, default
    gateway and DNS resolvers, with the adapter that carries the default route marked.

    Use this to establish the baseline before blaming anything remote - a machine with no
    default gateway, an APIPA 169.254.x.x address, or an unreachable DNS server will look like
    "the internet is down" from every other tool.

    Read the adapter, not just the list. Resolvers on a DISCONNECTED adapter are not in use:
    an earlier version printed every adapter's resolvers in one flat list, and given
    "192.168.88.1, 212.128.130.140, 172.20.10.1" plus a failed lookup, the natural reading was
    "stale resolvers from another network". The machine was correctly configured; the first
    two belonged to an unplugged Ethernet port, and the hotspot's own resolver was refusing
    one name. Only the adapter marked as carrying the default route decides what this machine
    uses.
    """
    out: list[str] = []
    adapters = _windows_adapters() if IS_WINDOWS else []
    if adapters:
        # Live adapters first, and only the ones that say something.
        adapters.sort(key=lambda a: (str(a.get("status")) != "Up", not _as_list(a.get("gw"))))
        for a in adapters:
            status = str(a.get("status") or "?").lower()
            ips = [ip for ip in _as_list(a.get("ip")) if not ip.startswith("169.254.")]
            gws, dns = _as_list(a.get("gw")), _as_list(a.get("dns"))
            if status != "up" and not dns:
                continue                                  # a dead adapter with nothing to say
            line = f"{a.get('InterfaceAlias', '?')}: {status}"
            line += f" {', '.join(ips)}" if ips else " (no usable address)"
            if gws:
                line += f"  gateway {', '.join(gws)}  <- CARRIES THE DEFAULT ROUTE"
            if dns:
                line += f"\n    dns {', '.join(dns)}"
                if status != "up":
                    line += "  (adapter is down: these resolvers are NOT in use)"
                elif not gws:
                    line += "  (no default route here: not what internet lookups use)"
            out.append(line)
        out.append(f"hostname: {socket.gethostname()}")
        return "\n".join(out)

    try:
        import psutil
        stats = psutil.net_if_stats()
        for nic, addrs in psutil.net_if_addrs().items():
            st = stats.get(nic)
            if not st or not st.isup:
                continue
            ips = [a.address for a in addrs
                   if a.family in (socket.AF_INET, socket.AF_INET6)
                   and not a.address.startswith(("fe80", "::1", "127."))]
            if ips:
                out.append(f"{nic}: up speed={st.speed}Mbps mtu={st.mtu} {', '.join(ips)}")
    except ImportError:
        out.append("(psutil not installed - interface list unavailable)")

    try:
        import dns.resolver
        out.append(f"dns_servers: {dns.resolver.Resolver().nameservers}")
    except Exception:
        pass

    rc, raw = _run(["ipconfig"] if IS_WINDOWS else ["ip", "route"], timeout=15)
    gw = re.findall(r"(?:Gateway|Puerta de enlace|default via)[^\d]*"
                    r"((?:\d{1,3}\.){3}\d{1,3})", raw)
    if gw:
        out.append(f"default_gateway_candidates: {sorted(set(gw))}")
    out.append(f"hostname: {socket.gethostname()}")
    return "\n".join(out) if out else "(no network information available)"


ALL_TOOLS = [ping, tcp_latency, traceroute, dns_lookup, dns_query_server,
             check_port, http_check, local_network]


if __name__ == "__main__":
    print("=" * 70, "\nlocal_network()\n", "=" * 70, sep="")
    print(local_network())
    for label, fn, args in [
        ("dns_lookup('one.one.one.one')", dns_lookup, ("one.one.one.one",)),
        ("ping('1.1.1.1', 3)", ping, ("1.1.1.1", 3)),
        ("tcp_latency('1.1.1.1', 443, 3)", tcp_latency, ("1.1.1.1", 443, 3)),
        ("check_port('1.1.1.1', 443)", check_port, ("1.1.1.1", 443)),
        ("http_check('https://example.com')", http_check, ("https://example.com",)),
        ("traceroute('1.1.1.1', 8)", traceroute, ("1.1.1.1", 8)),
    ]:
        print("\n" + "=" * 70, f"\n{label}\n", "=" * 70, sep="")
        try:
            print(fn(*args))
        except Exception as e:
            print(f"FAILED: {type(e).__name__}: {e}")
