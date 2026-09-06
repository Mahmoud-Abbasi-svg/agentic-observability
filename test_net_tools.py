"""Does local_network say WHICH adapter a resolver belongs to, and does dns_lookup ask the
right one?

    python test_net_tools.py

The failure this guards against was made on live data, twice. local_network printed every
adapter's resolvers in one flat list, dns_lookup queried all of them, timed out on the three
that belonged to an unplugged Ethernet port, and its own failure text then told the agent the
machine's DNS was misconfigured. The laptop was fine: its routed adapter had one resolver, the
hotspot's, which answered in milliseconds and refused exactly one name.

Runs offline. The PowerShell adapter query is replaced with fixtures shaped exactly like what
Windows PowerShell 5.1 returns after the -join fix - comma-joined strings, empty for none.
"""
from __future__ import annotations

import net_tools

FIXTURE = [
    {"InterfaceAlias": "vEthernet (Default Switch)", "status": "Up",
     "ip": "172.28.192.1", "gw": "", "dns": ""},
    {"InterfaceAlias": "Wi-Fi", "status": "Up",
     "ip": "10.0.0.7", "gw": "10.0.0.1", "dns": "10.0.0.1"},
    {"InterfaceAlias": "Ethernet", "status": "Disconnected",
     "ip": "169.254.141.255", "gw": "", "dns": "192.168.88.1,203.0.113.140,203.0.113.141"},
    {"InterfaceAlias": "Local Area Connection* 1", "status": "Disconnected",
     "ip": "169.254.20.233", "gw": "", "dns": ""},
]


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    return ok


def main() -> int:
    ok = True
    net_tools.IS_WINDOWS = True
    net_tools._windows_adapters = lambda: [dict(a) for a in FIXTURE]

    ok &= check("comma-joined fields split; empties and nulls become nothing",
                net_tools._as_list("a, b,,c") == ["a", "b", "c"]
                and net_tools._as_list("") == [] and net_tools._as_list(None) == [])

    text = net_tools.local_network()
    print(text, "\n")
    lines = text.splitlines()
    wifi = [l for l in lines if l.startswith("Wi-Fi")][0]
    ok &= check("the adapter with the default route is marked as carrying it",
                "CARRIES THE DEFAULT ROUTE" in wifi and "gateway 10.0.0.1" in wifi)
    ok &= check("and only that adapter is marked",
                text.count("CARRIES THE DEFAULT ROUTE") == 1)
    eth_i = next(i for i, l in enumerate(lines) if l.startswith("Ethernet"))
    ok &= check("a disconnected adapter's resolvers are shown AND labelled not in use",
                "disconnected" in lines[eth_i]
                and "192.168.88.1" in lines[eth_i + 1]
                and "NOT in use" in lines[eth_i + 1])
    ok &= check("its APIPA 169.254 address is not presented as an address",
                "169.254" not in text)
    ok &= check("a dead adapter with nothing to say is left out",
                "Local Area Connection" not in text)
    ok &= check("the live adapter comes first",
                lines[0].startswith("Wi-Fi"))
    ok &= check("an up adapter with no default route says its resolvers are not what "
                "internet lookups use, if it has any",
                "vEthernet" in text and "not what internet lookups use" not in text)

    ok &= check("dns_lookup will ask ONLY the routed adapter's resolver",
                net_tools._active_resolvers() == ["10.0.0.1"])

    # Two adapters with routes (a VPN alongside Wi-Fi): both resolver sets, no duplicates.
    net_tools._windows_adapters = lambda: [dict(a) for a in FIXTURE] + [
        {"InterfaceAlias": "VPN", "status": "Up", "ip": "10.8.0.2", "gw": "10.8.0.1",
         "dns": "10.8.0.1,10.0.0.1"}]
    ok &= check("with two routed adapters, both resolver sets are used, deduplicated",
                net_tools._active_resolvers() == ["10.0.0.1", "10.8.0.1"])

    # No adapter information at all: the library default must stand, not an empty list that
    # would make every lookup fail.
    net_tools._windows_adapters = lambda: []
    ok &= check("with no adapter information, no resolver override is attempted",
                net_tools._active_resolvers() == [])

    print("\n" + ("ALL PASS" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
