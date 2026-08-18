#!/usr/bin/env python3
"""
network_discovery.py -- Module A1 (Discovery) of the offline network
diagnostic app.

VERSION: 0.13.0
CHANGELOG:
  0.13.0 - Wires A1 into A6 (Encrypted Local Cache) directly, the "small
          plumbing change" CLAUDE.md flagged once A6 existed. New
          `--cache` flag: after a scan, writes the discovery dict
          straight into A6 via write_scan() instead of only a JSON
          file. `--json` still works exactly as before and is
          unaffected -- `--cache` is additive, not a replacement, so
          existing scripts/workflows don't break.

          A1 still doesn't hardcode an import of a specific A6 file
          version, for the same reason it already avoids importing A2
          directly (see A2's own changelog): a hardcoded
          `import a6_encrypted_cache_v0_1_0` would break the moment A6
          bumps its version and gets renamed, same fragility problem.
          `_import_a6()` instead globs for `a6_encrypted_cache_v*.py`
          next to this file and loads whichever one has the highest
          (major, minor, patch) version number, so A6 can keep bumping
          its own filename with zero changes needed here -- exactly the
          same reasoning, just applied one hop further down the chain.

          `cryptography` (A6's dependency) is only ever imported lazily,
          inside `_import_a6()`, and only when `--cache` is actually
          used -- A1 itself stays standard-library-only and runs fine
          with zero pip installs if you never pass `--cache`. If A6
          can't be found or `cryptography` isn't installed, `--cache`
          reports the actual error and the scan still completes and
          prints/exports normally -- caching is a secondary feature,
          not something that should take down a scan.

          Verified: ran with --cache against this sandbox's network,
          confirmed a new row appeared in A6 with get_scans(), and that
          --json export still worked unchanged in the same run.

  0.12.0 - check_firewall_rules() only ever recognized rules scoped to
          one of the five named ports -- a rule that blocks everything
          (no protocol/port restriction at all) matched none of those
          checks and was silently invisible, even though it's the
          single most consequential kind of rule there is: it explains
          every connectivity symptom at once, not just one. Ammar's
          specific example: a Windows rule blocking all remote ports
          (Protocol=Any or RemotePort=Any) -- the parser's own first
          gate, `protocol in ("tcp", "udp")`, rejected it before ever
          looking at the port field.

          Every platform parser now also recognizes a blanket rule and
          labels it service "ALL" instead of one of the five named
          services, since it isn't really the same category as "blocks
          one specific service" -- it's evidence against every symptom
          A2 tracks simultaneously:
            - Windows: an enabled, outbound Block rule with
              Protocol=Any or RemotePort=Any.
            - Linux (iptables): a rule with protocol "all" (no -p given),
              AND separately, a chain's own default policy (`Chain
              OUTPUT (policy DROP)`) -- a genuinely different mechanism
              from an individual rule, previously invisible for a
              second, unrelated reason: the chain-header regex only
              extracted the chain name, never the policy verdict sitting
              right next to it.
            - Linux (nft): a bare `drop`/`reject` statement mentioning
              neither `dport` nor `icmp`, and separately a chain's
              `policy drop;`/`policy reject;` line.
            - macOS (pfctl): a `block` line naming neither `udp` nor
              `tcp` -- correct pf semantics, not a heuristic guess: pf
              rules apply to all protocols by default when `proto` is
              omitted.

          New _windows_firewall_profile_policy(): reads whether the
          active Windows Firewall profile's default outbound action is
          Block (`netsh advfirewall show currentprofile`) -- a
          policy-level setting, not a rule, so _firewall_windows()'s
          per-rule parsing could never have seen it regardless of the
          fix above. Surfaced as the same synthetic "ALL" suspect rule
          if the currently active profile is outbound-block-by-default.

          A2's check_firewall_blocking() (a2_rule_engine v0.6.0) gets a
          matching "ALL" branch: fires if *any* of the four existing
          broken conditions is true (not just one), since a blanket
          block is consistent with all of them regardless of which
          symptom happens to be visible right now.

          Re-verified against a real iptables ruleset in this sandbox: a
          bare `-j DROP` rule (no -p) and a chain default policy of DROP
          are both now caught; the previous five-service detections
          (udp/53, tcp/80, tcp/443, udp/67, icmp) are unaffected.
          Windows/macOS paths remain unverified against real hardware.
  0.11.0 - check_firewall_rules() only ever checked DNS (port 53) and
          ICMP -- too narrow. A firewall rule silently dropping HTTP or
          HTTPS looks identical to "internet is down" but never got
          flagged, and a rule blocking DHCP is arguably the single most
          foundational way to break connectivity (no IP, no gateway, no
          DNS server -- nothing works), also never flagged. Replaced the
          single hardcoded DNS-port check with a small, named table,
          _CONNECTIVITY_PORTS: DNS (53, tcp/udp), HTTP (80, tcp), HTTPS
          (443, tcp/udp -- udp for HTTP/3-QUIC, increasingly common),
          DHCP server (67, udp), DHCP client (68, udp). Each suspect rule
          now carries a "service" label (e.g. "HTTPS") instead of just a
          bare port number, for plain-language findings later.

          Deliberately still a small, curated set, not "every port" --
          the whole point of only returning DNS/ICMP-matching rules in
          v0.10.0 was to avoid dumping the full ruleset on A2/downstream;
          widening that to every possible port would mean flagging a
          customer's legitimate custom rule (blocking some unrelated
          app's port) as if it explains a connectivity problem it has
          nothing to do with. Every port in this table maps to a symptom
          A1/A2 can already detect and correlate against: DNS -> DNS not
          resolving, HTTP/HTTPS -> internet unreachable (A1's own
          reachability check tests port 443 specifically), DHCP -> no
          gateway found at all. That correlation logic lives in A2's
          check_firewall_blocking() (a2_rule_engine v0.5.0) -- A1 still
          only gathers, it doesn't decide anything matters.

          Re-verified against this sandbox's real iptables (rules for
          udp/53, tcp/80, tcp/443, and icmp all correctly caught; an
          unrelated tcp/8080 rule still correctly ignored).
  0.10.0 - check_firewall_rules(): reads the actual local firewall
          ruleset (netsh advfirewall on Windows, iptables/nft on Linux,
          pfctl on macOS) for any rule that blocks DNS (port 53) or ICMP
          specifically. Pure data gathering, same as every other A1
          function -- this reports what rules exist, it doesn't decide
          whether they explain anything. A2's check_firewall_blocking()
          (new in a2_rule_engine v0.4.0) is what correlates a matching
          rule against an actual DNS/internet failure and calls it a
          likely cause -- that split (A1 gathers, A2 decides) is the
          same one CLAUDE.md already draws for every other module.
          Only returns the small subset of rules that block DNS/ICMP,
          not a full ruleset dump -- nobody downstream needs the rest.
          Known limitation, flagged rather than hidden: reading the full
          ruleset needs root on Linux (iptables/nft) and macOS (pfctl);
          without it, the errors list explains why instead of silently
          returning "no blocking rules found" -- an empty result has to
          be distinguishable from "couldn't check," same reasoning as
          every other error-surfacing fix in this file. Windows' netsh
          advfirewall doesn't need elevation to read rules. Verified
          against this sandbox's real iptables output (both a genuine
          DNS-block rule and a clean ruleset); Windows/macOS parsing is
          unverified against real hardware, same caveat as the UPnP
          traffic counters and Wi-Fi radio state parsing before it.
          Skippable with --no-firewall.
  0.9.0 - check_dns_resolution(): tests whether each *configured* DNS
          server actually resolves names, instead of just reading the
          config and assuming it works. This is the "internet is
          reachable but DNS is broken" case -- ISP DNS server down, DNS
          hijacked/misconfigured, captive portal -- which looks
          identical to "internet is down" to a non-technical user but
          has a completely different fix. Sends a raw DNS query directly
          to each server (not through the OS resolver, which can't be
          pointed at one specific server) for example.com -- IANA-
          reserved for documentation/testing, about as stable a target
          as exists. This is A1's second deliberate exception to "only
          A7 touches the internet" (see check_internet_reachability());
          gated under the same --no-internet flag since both are the
          same category of operation.
  0.8.0 - query_upnp_gateway() was printing whatever the router's UPnP
          stack returned as if it were trustworthy, and on Ammar's real
          Tenda router it wasn't: external_ip came back as a *private*
          address (192.168.100.2 -- a real WAN IP can't be private,
          this means the router is itself behind another router/NAT,
          common with FTTH ONT/modem combos), uptime_seconds came back
          as ~26.6 years (impossible, a firmware counter bug), and
          total_bytes_received came back as exactly 2^32-1 (the classic
          signature of an overflowed/wrapped 32-bit counter, or a
          "not really supported" sentinel value). None of these were
          flagged -- they just got printed next to the genuinely good
          data (external IP format, connection status) as if all of it
          were equally trustworthy. Added _upnp_sanity_notes(), which
          checks for exactly these three patterns and surfaces them as
          plain-language notes instead of silently trusting whatever
          the router's firmware says.
  0.7.0 - query_upnp_gateway(): talks to the router itself via UPnP IGD
          (Internet Gateway Device) -- a real, standardized protocol
          most consumer routers (Tenda/TP-Link included) support, and
          one that's normally unauthenticated on the LAN by design (it
          exists so any app can request port-forwarding without a login
          prompt). No router credentials needed, unlike the admin panel.
          SSDP-discovers the device, fetches its description XML, finds
          the WANIPConnection/WANPPPConnection service, and calls
          GetExternalIPAddress / GetStatusInfo over SOAP; also tries
          WANCommonInterfaceConfig for traffic byte counters if present
          (best-effort -- not verified against real hardware, wrapped so
          a failure there doesn't affect the rest). Skippable with
          --no-upnp.
          This does NOT get the DHCP client list or the router's actual
          configured DHCP range -- UPnP doesn't expose that. Getting it
          would need logging into the router's own web admin panel and
          scraping undocumented, per-model endpoints -- flagged, not
          built, see CLAUDE.md's "Flagged / open decisions."
  0.6.0 - Three additions Claude suggested and Ammar approved:
            - check_gateway_latency(): pings the gateway a handful of
              times (not just once) for real signal on connection
              quality -- packet loss and average round-trip time, not
              just alive/dead. Deliberately separate from the one-shot
              _ping_once() used for the subnet sweep; running 4-5 pings
              against every host in the subnet would be far too slow, so
              this only ever targets the single gateway IP.
            - MTU per interface, folded into get_interface_status()'s
              existing per-interface dict (`ip link show` / `ifconfig`
              already report it; Windows needed a second netsh command,
              `netsh interface ipv4 show subinterfaces`, merged in by
              interface name).
            - check_internet_reachability(): a lightweight TCP-connect
              test (not ICMP) to a couple of well-known IPs on port 443.
              This is A1's one deliberate, documented exception to "only
              A7 touches the internet" -- see CLAUDE.md's Architecture
              section for the reasoning. It's a reachability TEST, not a
              dependency: nothing else in A1 needs it to succeed, and the
              whole rest of the file still works fully offline. Skippable
              with --no-internet.
  0.5.0 - Two more items from Ammar's list:
            - get_interface_status() now reports admin_enabled and
              connected as two separate fields instead of one collapsed
              "up" bool -- an adapter can be enabled but not connected
              (cable unplugged, nothing in range), which is a different
              situation from being disabled outright, and worth telling
              apart. This is also what answers "were the adapters set to
              on or off in Windows" directly, using data this file was
              already fetching.
            - get_wifi_radio_state(): hardware/software Wi-Fi radio kill
              state (netsh on Windows, rfkill on Linux). Deliberately
              does NOT claim to read Windows' actual system-wide
              "Airplane Mode" flag -- see the function's docstring for
              why (no reliable stdlib-only way to do that without either
              fragile PowerShell/WinRT interop or an unverified registry
              key). Software-off is the mechanism Airplane Mode and
              Fn-key Wi-Fi toggles both actually use, so this answers the
              practical question even without reading the OS flag
              directly. Not applicable on macOS -- no OS-level Airplane
              Mode exists there.
  0.4.0 - Fixed the same silent-failure bug from v0.2.0, this time in the
          v0.3.0 additions: Ammar tested on real Windows hardware and
          get_interface_status() came back completely empty (no Ethernet,
          no Wi-Fi, nothing) with zero explanation. Root cause was the
          same pattern -- exceptions caught and swallowed with `pass`, so
          a command failure looked identical to "no interfaces found."
          get_dns_servers(), get_interface_status(), and
          get_ip_assignment_mode() now all return (result, errors) same
          as scan_wifi_networks(), and each one also flags it when the
          command *succeeds* but nothing matches the expected output
          format (including a short raw-output snippet), since that's a
          second, quieter way to end up with an empty list that isn't an
          exception at all.
          Also: the Wi-Fi scan error Ammar hit --
          "The wireless local area network interface is powered down and
          doesn't support the requested operation" -- is netsh's real
          answer, not a bug, but it reads like an error dump, not a
          diagnosis. Added a plain-language hint underneath it, and
          get_interface_status() now reports the same "Wi-Fi: DOWN"
          finding directly, so it doesn't only show up buried in a scan
          error.
  0.3.0 - Added five discovery items from Ammar's list:
            - get_dns_servers(): configured DNS server(s), offline (reads
              local config, doesn't query DNS itself)
            - calculate_pool_usage(): rough IP pool usage for the scanned
              subnet (used/free/percent) -- known gap, see docstring: this
              is usage across the whole subnet, not the router's actual
              configured DHCP range, which we have no way to know without
              asking the router
            - get_interface_status(): which network interfaces exist and
              whether each is up or down, with a best-effort ethernet/wifi
              guess (exact on macOS via hardware-port lookup, name-based
              guess elsewhere)
            - get_ip_assignment_mode(): whether this machine's IP looks
              like DHCP or static -- known gap: Linux detection needs
              NetworkManager (nmcli); returns "unknown" rather than
              guessing wrong if it's not present
            - get_arp_table() was already built (v0.1.0)
          CDP and LLDP (from the same list) are deliberately NOT here --
          see CLAUDE.md's "Flagged / open decisions" section for why
          (raw Layer-2 capture needs root/admin everywhere, and has no
          viable path at all on iOS, or on a non-rooted Android phone).
  0.2.0 - Wi-Fi scanning was silently failing: every error inside
          scan_wifi_networks() was caught and swallowed with `pass`, so a
          failed scan looked identical to "zero networks found" -- you'd
          just see the "Scanning Wi-Fi networks..." line and nothing
          after it. Fixed by making every command report its actual error
          instead of hiding it. Also added `iw` as a Linux fallback
          between nmcli and iwlist, since `iwlist` (wireless-tools) is
          missing by default on a lot of current distros -- `iw`
          (iproute2) is the modern replacement and more likely to exist.
          New: channel/signal values are now parsed into real numbers
          during scanning (not left as raw strings), and a new
          suggest_best_channel() looks at every network we saw and
          recommends the least congested 2.4GHz and 5GHz channel.
  0.1.0 - First version in this repo. Implements everything listed under
          "Current state" in CLAUDE.md: local IP/subnet + gateway
          detection, threaded ping sweep, ARP cross-reference (catches
          devices with ICMP disabled), seed MAC vendor lookup, offline
          hostname resolution, common-port probing with role guessing,
          Wi-Fi network scanning, and JSON export.

Standard-library only. No pip installs, on purpose -- see CLAUDE.md for why.

Run it directly:  python3 network_discovery_v0.12.0.py
Skip the slow steps while testing:  python3 network_discovery_v0.12.0.py --no-ports --no-wifi
Stay fully offline, no exceptions: python3 network_discovery_v0.12.0.py --no-internet
Dump machine-readable output:       python3 network_discovery_v0.12.0.py --json out.json

Note on Wi-Fi scanning permissions: on Linux, actually triggering a scan
(as opposed to reading a cached list) usually needs root. If you see a
"not permitted" style error in the output, try running with sudo.

Note on firewall rule reading: on Linux and macOS, reading the full
firewall ruleset (iptables/nft, pfctl) needs root -- run with sudo if
you see a permission error under the firewall section. Skip it entirely
with --no-firewall.
"""

import argparse
import ipaddress
import json
import os
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor


def _import_a6():
    """
    Dynamically loads whichever a6_encrypted_cache_v*.py sits next to this
    file, picking the highest (major, minor, patch) version present --
    same reasoning A2 already uses to avoid hardcoding A1's version: A6
    can keep bumping its own filename with zero changes needed here.
    Returns None if no A6 file is found (--cache then reports that
    clearly instead of crashing the scan).
    """
    import glob
    import importlib.util
    import re as _re

    here = os.path.dirname(os.path.abspath(__file__))
    candidates = glob.glob(os.path.join(here, "a6_encrypted_cache_v*.py"))
    if not candidates:
        return None

    def _version_key(path):
        m = _re.search(r"_v(\d+)\.(\d+)\.(\d+)\.py$", path)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    path = max(candidates, key=_version_key)
    spec = importlib.util.spec_from_file_location("a6_encrypted_cache", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Ports we probe on every live host, and what finding an open one suggests
# about the device's role. This is a coarse guess for A2 to refine later,
# not a real fingerprint.
COMMON_PORTS = {
    22: "ssh host",
    23: "telnet (legacy router/switch admin)",
    53: "DNS server",
    80: "web-admin device",
    443: "web-admin device (https)",
    8080: "web-admin device (alt port)",
}

# Seed OUI table (MAC prefix -> vendor). Deliberately small -- CLAUDE.md
# flags this as a known gap that needs a full offline OUI database later.
# Prefixes are the first 3 octets of the MAC, uppercase, colon-separated.
OUI_TABLE = {
    "C8:3A:35": "Tenda",
    "50:2B:73": "Tenda",
    "A8:57:4E": "TP-Link",
    "50:C7:BF": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "B0:47:BF": "TP-Link",
    "6C:3B:6B": "TP-Link",
    "48:8F:5A": "MikroTik",
    "4C:5E:0C": "MikroTik",
    "D4:CA:6D": "MikroTik",
    "00:0C:29": "VMware (virtual)",
    "00:1A:2B": "Cisco",
    "00:1B:D4": "Cisco",
    "58:AC:78": "Cisco",
    "F8:0F:6F": "Cisco",
    "DC:A6:32": "Raspberry Pi Foundation",
    "B8:27:EB": "Raspberry Pi Foundation",
}

# The three 2.4GHz channels that don't overlap each other at all (each
# channel is 20MHz wide but channels are spaced 5MHz apart, so anything
# closer than 5 channels away bleeds into its neighbour). Every router and
# regulatory region supports these three, which is why professional Wi-Fi
# installers only ever recommend picking among them.
NONOVERLAPPING_24GHZ = [1, 6, 11]

# 5GHz channels that don't require DFS (radar detection) -- safe to
# recommend without worrying about a router refusing or delaying on them.
COMMON_5GHZ = [36, 40, 44, 48, 149, 153, 157, 161]

# Used only by check_internet_reachability() -- Cloudflare and Google's
# anycast IPs, picked purely for extremely high uptime/ubiquity as
# reachability-check targets (this is standard practice, e.g. router
# firmware "internet check" features use the same pattern). We do a bare
# TCP connect to port 443 and nothing else -- no data sent beyond the
# handshake, no DNS lookups performed against them.
INTERNET_CHECK_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 443)]

SYSTEM = platform.system()  # "Windows", "Linux", or "Darwin" (macOS)


def get_local_ip_and_subnet():
    """
    Figures out this machine's LAN IP and (best-effort) its /24 subnet.

    The socket.connect() call below to 8.8.8.8 does NOT send any packets --
    for UDP sockets, connect() just asks the OS "which local interface and
    IP would you use to reach this address?" and answers from the routing
    table. So this works fine with no internet connection; it's a local
    lookup, not a network call.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except OSError:
        local_ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()

    netmask = _get_netmask_for_ip(local_ip)
    network = ipaddress.ip_network(f"{local_ip}/{netmask}", strict=False)
    return local_ip, str(network)


def _get_netmask_for_ip(ip):
    """
    Tries to find the real subnet mask/prefix for our IP by parsing OS
    tools. Falls back to assuming /24 (255.255.255.0) if parsing fails --
    that's the common case on small consumer/SMB networks anyway.
    """
    try:
        if SYSTEM == "Windows":
            out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
            blocks = out.split("\r\n\r\n")
            for block in blocks:
                if ip in block:
                    m = re.search(r"Subnet Mask[.\s]*:\s*([\d.]+)", block)
                    if m:
                        return str(ipaddress.IPv4Network(f"0.0.0.0/{m.group(1)}").prefixlen)
        elif SYSTEM == "Linux":
            out = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show"], text=True)
            for line in out.splitlines():
                if ip in line:
                    m = re.search(r"inet \S+/(\d+)", line)
                    if m:
                        return m.group(1)
        elif SYSTEM == "Darwin":
            out = subprocess.check_output(["ifconfig"], text=True)
            blocks = out.split("\n\n")
            for block in blocks:
                if ip in block:
                    m = re.search(r"netmask (0x[0-9a-fA-F]+)", block)
                    if m:
                        mask_int = int(m.group(1), 16)
                        return str(bin(mask_int).count("1"))
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return "24"


def _get_interface_for_ip(ip):
    """Finds which network interface has this IP assigned. Used by
    get_ip_assignment_mode() to know which connection/interface to ask
    about. Returns None if not found (e.g. on Windows, which looks up
    DHCP status by IP directly instead and doesn't need this)."""
    try:
        if SYSTEM == "Linux":
            out = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show"], text=True)
            for line in out.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        elif SYSTEM == "Darwin":
            out = subprocess.check_output(["ifconfig"], text=True)
            for block in out.split("\n\n"):
                if ip in block:
                    m = re.match(r"^(\w+):", block)
                    if m:
                        return m.group(1)
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return None


def get_default_gateway():
    """Returns the default gateway IP as a string, or None if not found."""
    try:
        if SYSTEM == "Windows":
            out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
            m = re.search(r"Default Gateway[.\s]*:\s*([\d.]+)", out)
            return m.group(1) if m else None
        elif SYSTEM == "Linux":
            out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
            m = re.search(r"default via ([\d.]+)", out)
            return m.group(1) if m else None
        elif SYSTEM == "Darwin":
            out = subprocess.check_output(["route", "-n", "get", "default"], text=True)
            m = re.search(r"gateway:\s*([\d.]+)", out)
            return m.group(1) if m else None
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return None


def get_dns_servers():
    """
    Finds the DNS server(s) this machine is configured to use. Fully
    offline -- reads local config/OS state, never queries a DNS server
    itself.

    Returns (servers, errors). Every failure -- including the command
    succeeding but nothing matching the format we expect -- is reported
    instead of silently coming back as an empty list.
    """
    servers = []
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("ipconfig not found (unexpected on Windows)")
                return servers, errors
            if result.returncode != 0:
                errors.append(f"ipconfig /all failed: {(result.stderr or result.stdout).strip()}")
                return servers, errors

            in_dns_block = False
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("DNS Servers"):
                    m = re.search(r":\s*([\d.]+)\s*$", stripped)
                    if m:
                        servers.append(m.group(1))
                    in_dns_block = True
                    continue
                if in_dns_block and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", stripped):
                    servers.append(stripped)
                    continue
                in_dns_block = False

            if not servers:
                errors.append("ipconfig /all ran but no \"DNS Servers\" line was found for any adapter")

        else:
            # Linux and macOS both maintain /etc/resolv.conf.
            try:
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                servers.append(parts[1])
            except FileNotFoundError:
                errors.append("/etc/resolv.conf not found")

            if not servers and SYSTEM == "Darwin":
                try:
                    result = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, errors="ignore", timeout=10)
                except FileNotFoundError:
                    errors.append("scutil not found")
                    result = None
                if result is not None:
                    if result.returncode != 0:
                        errors.append(f"scutil --dns failed: {(result.stderr or result.stdout).strip()}")
                    else:
                        for line in result.stdout.splitlines():
                            m = re.search(r"nameserver\[\d+\]\s*:\s*([\d.]+)", line)
                            if m:
                                servers.append(m.group(1))
                        if not servers:
                            errors.append("scutil --dns ran but no nameserver entries were found")
    except Exception as e:
        errors.append(f"unexpected error finding DNS servers: {e}")

    seen = set()
    unique = []
    for s in servers:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique, errors


def calculate_pool_usage(network_str, device_count):
    """
    Rough IP pool usage for the subnet we scanned: how many addresses are
    in use out of how many are usable.

    Known gap: this is usage across the *whole subnet*, not the router's
    actual configured DHCP range -- a router might only hand out
    .100-.200 while the subnet is a full /24. We have no way to know the
    real DHCP range without asking the router directly (that's an A3-era
    problem, once we have router credentials/access).
    """
    network = ipaddress.ip_network(network_str, strict=False)
    total_usable = max(network.num_addresses - 2, 1)
    used = min(device_count, total_usable)
    return {
        "subnet": str(network),
        "total_usable": total_usable,
        "used": used,
        "free": total_usable - used,
        "percent_used": round(used / total_usable * 100, 1),
    }


def _macos_interface_types():
    """Maps macOS interface names (en0, en1, ...) to wifi/ethernet using
    the hardware-port list, since macOS names alone don't tell you which
    is which (en0 is Wi-Fi on some Macs, Ethernet on others)."""
    types = {}
    try:
        out = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
        for block in out.split("\n\n"):
            port_m = re.search(r"Hardware Port: (.+)", block)
            dev_m = re.search(r"Device: (\w+)", block)
            if port_m and dev_m:
                if "Wi-Fi" in port_m.group(1) or "AirPort" in port_m.group(1):
                    types[dev_m.group(1)] = "wifi"
                elif "Ethernet" in port_m.group(1):
                    types[dev_m.group(1)] = "ethernet"
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return types


def _guess_interface_type(name):
    """Best-effort ethernet/wifi guess from interface naming conventions.
    Known gap: unreliable on macOS by name alone -- get_interface_status()
    uses _macos_interface_types() instead there."""
    lname = name.lower()
    if "wi-fi" in lname or "wifi" in lname or "wlan" in lname or lname.startswith("wl"):
        return "wifi"
    if "ethernet" in lname or lname.startswith("eth") or lname.startswith("en"):
        return "ethernet"
    return "other"


def _windows_mtu_by_interface():
    """Maps interface name -> MTU on Windows via a second, separate netsh
    command from the one get_interface_status() uses for up/down state."""
    mtu = {}
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "subinterfaces"],
            capture_output=True, text=True, errors="ignore", timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0].isdigit():
                    mtu[" ".join(parts[4:])] = int(parts[0])
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return mtu


def get_interface_status():
    """
    Lists network interfaces with two separate signals per interface,
    not one collapsed "up" bool, plus MTU:
      - admin_enabled: was the adapter itself turned on/off (Windows
        adapter settings "Enable"/"Disable", Linux/macOS admin UP flag)
      - connected: is it actually carrying a link right now (Windows
        "Connected"/"Disconnected", Linux LOWER_UP flag, macOS
        "status: active/inactive")
    An adapter can be enabled but not connected (cable unplugged, no
    network in range) -- that's a different situation from the adapter
    being disabled outright, and worth telling apart.

    Returns (interfaces, errors) -- same pattern as scan_wifi_networks().
    An earlier version of this function had the exact silent-failure bug
    that v0.2.0 fixed for Wi-Fi scanning, just not fixed here yet: caught
    on Ammar's real Windows machine, where it came back completely empty
    with no explanation at all.
    """
    interfaces = []
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("netsh not found (unexpected on Windows)")
                return interfaces, errors
            if result.returncode != 0:
                errors.append(f"netsh interface show interface failed: {(result.stderr or result.stdout).strip()}")
                return interfaces, errors

            mtu_by_name = _windows_mtu_by_interface()
            for line in result.stdout.splitlines():
                parts = line.split(None, 3)
                if len(parts) == 4 and parts[0] in ("Enabled", "Disabled"):
                    admin_state, conn_state, _if_type, name = parts
                    name = name.strip()
                    interfaces.append({
                        "name": name,
                        "type": _guess_interface_type(name),
                        "admin_enabled": admin_state == "Enabled",
                        "connected": conn_state == "Connected",
                        "mtu": mtu_by_name.get(name),
                    })
            if not interfaces:
                snippet = "\n".join(result.stdout.splitlines()[:6])
                errors.append(
                    "netsh ran but no interface rows were recognized -- output may not "
                    f"match the expected format. First lines:\n{snippet}"
                )

        elif SYSTEM == "Linux":
            try:
                result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("`ip` command not found")
                return interfaces, errors
            if result.returncode != 0:
                errors.append(f"ip link show failed: {(result.stderr or result.stdout).strip()}")
                return interfaces, errors

            for line in result.stdout.splitlines():
                m = re.match(r"\d+:\s+([^:@]+)[:@].*?<([^>]*)>", line)
                if not m:
                    continue
                name, flags = m.group(1), m.group(2).split(",")
                if name == "lo":
                    continue
                mtu_m = re.search(r"\bmtu\s+(\d+)", line)
                interfaces.append({
                    "name": name,
                    "type": _guess_interface_type(name),
                    "admin_enabled": "UP" in flags,
                    "connected": "LOWER_UP" in flags,
                    "mtu": int(mtu_m.group(1)) if mtu_m else None,
                })
            if not interfaces:
                errors.append("ip link show ran but found no non-loopback interfaces")

        elif SYSTEM == "Darwin":
            mac_types = _macos_interface_types()
            try:
                result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("ifconfig not found")
                return interfaces, errors
            if result.returncode != 0:
                errors.append(f"ifconfig failed: {(result.stderr or result.stdout).strip()}")
                return interfaces, errors

            for block in result.stdout.split("\n\n"):
                m = re.match(r"^(\w+):\s*flags=\d+<([^>]*)>", block)
                if not m:
                    continue
                name, flags = m.group(1), m.group(2).split(",")
                if name == "lo0":
                    continue
                status_m = re.search(r"status:\s*(\w+)", block)
                mtu_m = re.search(r"\bmtu\s+(\d+)", block)
                interfaces.append({
                    "name": name,
                    "type": mac_types.get(name, _guess_interface_type(name)),
                    "admin_enabled": "UP" in flags,
                    "connected": (status_m.group(1) == "active") if status_m else None,
                    "mtu": int(mtu_m.group(1)) if mtu_m else None,
                })
            if not interfaces:
                errors.append("ifconfig ran but found no non-loopback interfaces")
    except Exception as e:
        errors.append(f"unexpected error checking interfaces: {e}")

    return interfaces, errors


def get_wifi_radio_state():
    """
    Reports the Wi-Fi radio's hardware/software on-off state --
    "hardware" is a physical switch/killswitch, "software" is a radio
    kill done in software, which is the actual mechanism both Airplane
    Mode and Fn-key Wi-Fi toggles use.

    This deliberately does NOT claim to read Windows' system-wide
    "Airplane Mode" setting directly. The documented way to do that needs
    WinRT interop through PowerShell, which is fragile to write blind
    without a Windows machine to test against; the alternative is an
    undocumented registry key whose exact on/off value mapping isn't
    something that could be verified without hardware either, and
    shipping a confidently-wrong on/off reading is worse than not having
    the feature. Hardware/software radio state is the practical
    diagnostic that actually matters here, and it's readable through
    netsh/rfkill, tools this file already trusts.

    Not applicable on macOS -- there's no OS-level Airplane Mode there,
    Wi-Fi power is a per-adapter toggle only (see scan_wifi_networks()).

    Known gap: the Windows netsh output parsing hasn't been confirmed
    against real hardware. If it comes back with a parse error, that's
    expected until tested -- the error includes a snippet of the raw
    output so the parsing can be corrected in one pass.

    Returns ({"hardware": "on"/"off"/None, "software": "on"/"off"/None}, errors).
    """
    state = {"hardware": None, "software": None}
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("netsh not found (unexpected on Windows)")
                return state, errors
            if result.returncode != 0:
                errors.append(f"netsh wlan show interfaces failed: {(result.stderr or result.stdout).strip()}")
                return state, errors

            hw_m = re.search(r"Hardware\s+(On|Off)", result.stdout)
            sw_m = re.search(r"Software\s+(On|Off)", result.stdout)
            if hw_m:
                state["hardware"] = hw_m.group(1).lower()
            if sw_m:
                state["software"] = sw_m.group(1).lower()
            if not hw_m and not sw_m:
                snippet = "\n".join(result.stdout.splitlines()[:12])
                errors.append(
                    "netsh wlan show interfaces ran but no \"Radio status\" was found -- "
                    f"output format may not match what this code expects. First lines:\n{snippet}"
                )

        elif SYSTEM == "Linux":
            try:
                result = subprocess.run(["rfkill", "list"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("rfkill not installed (install util-linux's rfkill, or try `nmcli radio wifi`)")
                return state, errors
            if result.returncode != 0:
                errors.append(f"rfkill list failed: {(result.stderr or result.stdout).strip()}")
                return state, errors

            in_wifi = False
            for line in result.stdout.splitlines():
                if re.match(r"^\d+:\s", line):
                    in_wifi = any(w in line.lower() for w in ("wlan", "wireless", "wifi"))
                elif in_wifi and "Soft blocked" in line:
                    state["software"] = "off" if "yes" in line.lower() else "on"
                elif in_wifi and "Hard blocked" in line:
                    state["hardware"] = "off" if "yes" in line.lower() else "on"
            if state["hardware"] is None and state["software"] is None:
                errors.append("rfkill list ran but found no Wi-Fi radio entry")
        # SYSTEM == "Darwin": intentionally left as (None, None) with no
        # errors -- not a failure, just not a thing macOS has.
    except Exception as e:
        errors.append(f"unexpected error checking Wi-Fi radio state: {e}")

    return state, errors


def get_ip_assignment_mode(local_ip):
    """
    Best-effort check for whether this machine's IP came from DHCP or was
    set statically.

    Known gap: Linux detection depends on NetworkManager (nmcli) managing
    the interface -- returns "unknown" rather than guessing wrong if
    nmcli isn't present or the interface isn't NetworkManager-managed
    (common on servers using netplan/systemd-networkd directly).

    Returns (mode, errors) -- mode is "dhcp" / "static" / "unknown".
    """
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("ipconfig not found (unexpected on Windows)")
                return "unknown", errors
            if result.returncode != 0:
                errors.append(f"ipconfig /all failed: {(result.stderr or result.stdout).strip()}")
                return "unknown", errors

            for block in result.stdout.split("\r\n\r\n"):
                if local_ip in block:
                    m = re.search(r"DHCP Enabled[.\s]*:\s*(Yes|No)", block)
                    if m:
                        return ("dhcp" if m.group(1) == "Yes" else "static"), errors
            errors.append(f"ipconfig /all ran but no adapter block contained {local_ip}")

        elif SYSTEM == "Linux":
            iface = _get_interface_for_ip(local_ip)
            if not iface:
                errors.append(f"could not find a network interface for {local_ip}")
                return "unknown", errors
            try:
                active = subprocess.run(
                    ["nmcli", "-t", "-f", "NAME,DEVICE", "con", "show", "--active"],
                    capture_output=True, text=True, errors="ignore", timeout=10,
                )
            except FileNotFoundError:
                errors.append("nmcli not installed")
                return "unknown", errors
            if active.returncode != 0:
                errors.append(f"nmcli con show failed: {(active.stderr or active.stdout).strip()}")
                return "unknown", errors

            found_conn = False
            for line in active.stdout.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[1] == iface:
                    found_conn = True
                    method_out = subprocess.run(
                        ["nmcli", "-t", "-f", "ipv4.method", "con", "show", parts[0]],
                        capture_output=True, text=True, errors="ignore", timeout=10,
                    )
                    method = method_out.stdout.strip().split(":")[-1]
                    if method == "auto":
                        return "dhcp", errors
                    if method == "manual":
                        return "static", errors
                    errors.append(f"nmcli reported ipv4.method={method!r} for {iface}, not auto/manual")
                    break
            if not found_conn:
                errors.append(f"no active nmcli connection found for interface {iface}")

        elif SYSTEM == "Darwin":
            iface = _get_interface_for_ip(local_ip)
            if not iface:
                errors.append(f"could not find a network interface for {local_ip}")
                return "unknown", errors
            out = subprocess.run(
                ["ipconfig", "getpacket", iface],
                capture_output=True, text=True, errors="ignore", timeout=5,
            )
            if out.returncode == 0 and out.stdout.strip():
                return "dhcp", errors
            return "static", errors
    except Exception as e:
        errors.append(f"unexpected error checking dhcp/static: {e}")

    return "unknown", errors


def _ping_once(ip, timeout_ms=1000):
    """Sends a single ICMP echo using the OS ping command (no raw sockets,
    no admin/root privileges needed that way)."""
    if SYSTEM == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_ms / 1000 + 2)
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def ping_sweep(network_str, max_workers=64):
    """
    Threaded ping sweep across every host in the subnet. Returns the set of
    IPs that answered ICMP. This alone misses devices with ping/ICMP
    disabled in their firewall -- that's why we cross-reference with the
    ARP table afterwards.
    """
    network = ipaddress.ip_network(network_str, strict=False)
    hosts = list(network.hosts())
    alive = set()

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ping_once, str(ip)): str(ip) for ip in hosts}
        for future in futures:
            ip = futures[future]
            if future.result():
                alive.add(ip)
    return alive


def check_gateway_latency(gateway_ip, count=4, timeout_ms=1000):
    """
    Pings the gateway a handful of times -- not just once -- for real
    signal on connection quality: packet loss and average round-trip
    time, not just alive/dead. Deliberately separate from the one-shot
    _ping_once() the subnet sweep uses; running several pings against
    every host in the subnet would be far too slow, so this only ever
    targets the single gateway IP.
    """
    if not gateway_ip:
        return {"target": None, "sent": 0, "received": 0, "loss_percent": None, "avg_ms": None}

    rtts = []
    received = 0
    for _ in range(count):
        if SYSTEM == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), gateway_ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), gateway_ip]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 2)
        except (subprocess.SubprocessError, OSError):
            continue
        if result.returncode == 0:
            received += 1
            m = re.search(r"time[=<]\s*([\d.]+)\s*ms", result.stdout, re.IGNORECASE)
            if m:
                rtts.append(float(m.group(1)))

    return {
        "target": gateway_ip,
        "sent": count,
        "received": received,
        "loss_percent": round((count - received) / count * 100, 1) if count else None,
        "avg_ms": round(sum(rtts) / len(rtts), 1) if rtts else None,
    }


def check_internet_reachability(targets=INTERNET_CHECK_TARGETS, timeout=2.0):
    """
    A1's one deliberate exception to "only A7 touches the internet" (see
    CLAUDE.md's Architecture section) -- a lightweight reachability TEST,
    not a dependency. Nothing else in this file needs this to succeed;
    everything else works fully offline. This exists because the
    product's whole vision is diagnosing network issues *including* when
    the internet connection itself is the problem, which needs an actual
    check of whether the WAN path is up.

    Uses a plain TCP connect (not ICMP) to a couple of well-known IPs on
    port 443 -- no admin/root needed, and it reflects real usage (a
    browser doing HTTPS) better than a ping would. Skippable with
    --no-internet.
    """
    checks = []
    reachable = False
    for ip, port in targets:
        start = time.monotonic()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            elapsed_ms = round((time.monotonic() - start) * 1000, 1)
            checks.append({"target": f"{ip}:{port}", "reachable": True, "latency_ms": elapsed_ms})
            reachable = True
        except OSError:
            checks.append({"target": f"{ip}:{port}", "reachable": False, "latency_ms": None})
        finally:
            s.close()
    return {"reachable": reachable, "checks": checks}


# IANA-reserved for documentation/testing (RFC 2606) -- guaranteed to
# exist and never used for anything real, so it's about as stable a
# target as a DNS resolution test can have.
_DNS_TEST_HOSTNAME = "example.com"


def _encode_dns_name(hostname):
    """Encodes a hostname into DNS wire format: length-prefixed labels
    ending in a zero byte, e.g. "example.com" -> b'\\x07example\\x03com\\x00'."""
    parts = hostname.strip(".").split(".")
    return b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"


def _build_dns_query(hostname, query_id):
    """Builds a minimal DNS query packet (header + one question, type A)
    by hand -- there's no stdlib DNS client, and we specifically need to
    query one exact server rather than however the OS resolver decides
    to pick among configured servers."""
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(hostname) + struct.pack(">HH", 1, 1)  # type A, class IN
    return header + question


def _parse_dns_response(data, expected_id):
    """Reads just the DNS response header -- enough to know whether the
    server answered our exact query successfully, without needing a full
    resource-record parser."""
    if len(data) < 12:
        return None
    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    if resp_id != expected_id:
        return None
    return {
        "is_response": bool(flags & 0x8000),
        "rcode": flags & 0x000F,
        "answer_count": ancount,
    }


def check_dns_resolution(dns_servers=None, timeout=2.0):
    """
    Tests whether each *configured* DNS server actually resolves names,
    instead of just reading the config and assuming it works. This is
    the "internet is reachable but DNS is broken" case -- ISP DNS server
    down, DNS hijacked/misconfigured, a captive portal -- which looks
    identical to "internet is down" to a non-technical user, but has a
    completely different fix.

    A1's second deliberate exception to "only A7 touches the internet"
    (see check_internet_reachability() and CLAUDE.md's Architecture
    section): most configured DNS servers live off-LAN, so testing one
    means an outbound query. Same as the reachability check, this is a
    diagnostic TEST, not a dependency -- gated under the same
    --no-internet flag since both are the same category of operation.

    Sends a raw DNS query directly to each server (not through the OS
    resolver, which can't be pointed at one specific server) for
    example.com. Returns {"servers_tested": [...], "any_working": bool}.
    """
    if dns_servers is None:
        dns_servers, _ = get_dns_servers()

    results = []
    for server in dns_servers:
        query_id = random.randint(0, 65535)
        query = _build_dns_query(_DNS_TEST_HOSTNAME, query_id)
        start = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (server, 53))
            data, _addr = sock.recvfrom(512)
            elapsed_ms = round((time.monotonic() - start) * 1000, 1)
            parsed = _parse_dns_response(data, query_id)
            if parsed and parsed["is_response"] and parsed["rcode"] == 0 and parsed["answer_count"] > 0:
                results.append({"server": server, "working": True, "latency_ms": elapsed_ms, "error": None})
            elif parsed:
                results.append({
                    "server": server, "working": False, "latency_ms": elapsed_ms,
                    "error": f"responded but rcode={parsed['rcode']} answers={parsed['answer_count']}",
                })
            else:
                results.append({"server": server, "working": False, "latency_ms": None, "error": "malformed or mismatched response"})
        except socket.timeout:
            results.append({"server": server, "working": False, "latency_ms": None, "error": "timed out"})
        except OSError as e:
            results.append({"server": server, "working": False, "latency_ms": None, "error": str(e)})
        finally:
            sock.close()

    return {"servers_tested": results, "any_working": any(r["working"] for r in results)}


# Firewall rule scanning -- see check_firewall_rules() below. Deliberately
# a small, named table, not "every port": each one maps to a symptom
# A1/A2 can already detect and correlate against (see A2's
# check_firewall_blocking()) -- DNS -> DNS not resolving, HTTP/HTTPS ->
# internet unreachable (check_internet_reachability() itself tests port
# 443), DHCP -> no gateway found at all. Widening this to every possible
# port would mean flagging a customer's legitimate custom rule (blocking
# some unrelated app's port) as if it explains a connectivity problem it
# has nothing to do with.
_CONNECTIVITY_PORTS = {
    53: ("DNS", {"tcp", "udp"}),
    80: ("HTTP", {"tcp"}),
    443: ("HTTPS", {"tcp", "udp"}),  # udp covers HTTP/3 (QUIC)
    67: ("DHCP (server)", {"udp"}),
    68: ("DHCP (client)", {"udp"}),
}


def _port_matches(port_field, port):
    """
    Best-effort check for whether a rule's port field includes the given
    port number. Handles the formats netsh/iptables/pfctl all use in some
    form: a single port ("53"), a comma list ("53,80"), or a range
    ("50-60"). Returns False for anything unparseable rather than
    guessing.
    """
    if not port_field:
        return False
    for part in str(port_field).split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                if int(lo) <= port <= int(hi):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == port:
                    return True
            except ValueError:
                continue
    return False


def _matched_connectivity_service(port_field, protocol):
    """
    Checks a rule's port field against every port in _CONNECTIVITY_PORTS
    for the given protocol, returning (port, service_name) for the first
    match, or (None, None). A rule's port field can be a single port, a
    comma list, or a range -- _port_matches() already handles all three.
    """
    for port, (service, protocols) in _CONNECTIVITY_PORTS.items():
        if protocol in protocols and _port_matches(port_field, port):
            return port, service
    return None, None


def _firewall_windows(errors):
    """
    Parses `netsh advfirewall firewall show rule name=all` into per-rule
    blocks, then keeps only the enabled Block rules whose protocol/port
    match one of _CONNECTIVITY_PORTS, ICMP, or a blanket "blocks all
    remote ports" rule (Protocol=Any or RemotePort=Any, outbound --
    service "ALL"). A blanket rule doesn't map to one connectivity
    service; it's evidence against all of them at once, so it's kept in
    a separate category rather than forced into the five-service table.
    Reading rules this way doesn't need elevation on Windows, unlike the
    Linux/macOS paths.
    """
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, errors="ignore", timeout=20,
        )
    except FileNotFoundError:
        errors.append("netsh not found (unexpected on Windows)")
        return []
    except subprocess.TimeoutExpired:
        errors.append("netsh advfirewall show rule timed out")
        return []
    if result.returncode != 0:
        errors.append(f"netsh advfirewall firewall show rule failed: {(result.stderr or result.stdout).strip()}")
        return []

    rules = []
    current = {}
    for line in result.stdout.splitlines():
        line = line.rstrip()
        if line.startswith("Rule Name:"):
            if current:
                rules.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif ":" in line and current:
            key, _, val = line.partition(":")
            current[key.strip()] = val.strip()
    if current:
        rules.append(current)

    if not rules:
        errors.append("netsh advfirewall ran but no rules were parsed -- output may not match the expected format")
        return []

    suspects = []
    for r in rules:
        if r.get("Enabled") != "Yes" or r.get("Action") != "Block":
            continue
        protocol = (r.get("Protocol") or "").lower()
        direction = (r.get("Direction") or "").lower()
        is_icmp = protocol.startswith("icmpv4") or protocol.startswith("icmpv6") or protocol == "icmp"
        is_blanket = direction == "out" and (
            protocol == "any" or (r.get("RemotePort") or "").strip().lower() == "any"
        )
        port, service = (None, None)
        if is_blanket:
            service = "ALL"
        elif protocol in ("tcp", "udp"):
            port, service = _matched_connectivity_service(r.get("LocalPort"), protocol)
        if service or is_icmp:
            suspects.append({
                "name": r.get("name", "unnamed rule"),
                "direction": direction or None,
                "protocol": "icmp" if is_icmp else protocol,
                "port": port,
                "service": "ICMP" if is_icmp else service,
                "action": "block",
            })
    return suspects


def _windows_firewall_profile_policy(errors):
    """
    Reads whether the currently active Windows Firewall profile blocks
    outbound connections by default -- a policy-level setting, not an
    individual rule, so it's invisible to _firewall_windows()'s per-rule
    parsing no matter how that's extended. `netsh advfirewall show
    currentprofile` reports it directly. Returns True/False, or None if
    it couldn't be read (with the reason in errors).
    """
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "currentprofile"],
            capture_output=True, text=True, errors="ignore", timeout=10,
        )
    except FileNotFoundError:
        errors.append("netsh not found (unexpected on Windows)")
        return None
    except subprocess.TimeoutExpired:
        errors.append("netsh advfirewall show currentprofile timed out")
        return None
    if result.returncode != 0:
        errors.append(f"netsh advfirewall show currentprofile failed: {(result.stderr or result.stdout).strip()}")
        return None

    m = re.search(r"Outbound connections\s*:\s*(\w+)", result.stdout, re.IGNORECASE)
    if not m:
        errors.append(
            "netsh advfirewall show currentprofile ran but no \"Outbound connections\" "
            "setting was found -- output may not match the expected format"
        )
        return None
    return m.group(1).strip().lower() == "block"


# iptables normally prints protocol names (udp/tcp/icmp/all), but on at
# least one real system tested against (a minimal container, despite a
# populated /etc/protocols) it printed raw protocol numbers instead --
# caught by testing against a real ruleset, not assumed. Mapped here so
# parsing doesn't silently miss rules just because of that difference.
# "0" is the kernel's IPPROTO_IP sentinel, which is what a rule with no
# -p at all shows as here -- caught the same way, by testing a real
# unrestricted rule and seeing "0" instead of the expected "all".
_IPTABLES_PROTO_NUMBERS = {"0": "all", "1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}


def _firewall_linux_iptables(errors):
    """
    Parses `iptables -L -n` for DROP/REJECT rules matching a port in
    _CONNECTIVITY_PORTS, ICMP, or a blanket rule (no -p given, shows as
    protocol "all") -- service "ALL", same reasoning as the Windows
    blanket case: it isn't one connectivity service, it's evidence
    against all of them. Also recognizes a chain's own default policy
    (`Chain OUTPUT (policy DROP)`) as its own "ALL" suspect -- a
    genuinely different mechanism from an individual rule, previously
    invisible because the chain-header regex only ever captured the
    chain name, never the policy verdict next to it.

    Returns None (not []) on any failure to read the ruleset at all, so
    the caller can fall back to nft -- an empty list means "read the
    ruleset successfully, found nothing matching," a real and useful
    result that shouldn't trigger a fallback.
    """
    try:
        result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("iptables not installed")
        return None
    except subprocess.TimeoutExpired:
        errors.append("iptables -L timed out")
        return None
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"iptables -L failed: {msg}")
        if "permission denied" in msg.lower() or "not running" in msg.lower():
            errors.append("Reading iptables rules usually needs root -- try running with sudo.")
        return None

    suspects = []
    chain = None
    for line in result.stdout.splitlines():
        chain_m = re.match(r"^Chain (\S+)(?:\s*\(policy (\w+)\))?", line)
        if chain_m:
            chain = chain_m.group(1)
            policy = chain_m.group(2)
            if policy in ("DROP", "REJECT") and chain in ("INPUT", "OUTPUT"):
                suspects.append({
                    "name": f"{chain} chain default policy: {policy}",
                    "direction": {"INPUT": "in", "OUTPUT": "out"}.get(chain),
                    "protocol": "all",
                    "port": None,
                    "service": "ALL",
                    "action": policy.lower(),
                })
            continue
        parts = line.split()
        if len(parts) < 2 or parts[0] not in ("DROP", "REJECT"):
            continue
        target, raw_proto = parts[0], parts[1]
        proto = _IPTABLES_PROTO_NUMBERS.get(raw_proto, raw_proto)
        is_icmp = proto in ("icmp", "icmpv6")
        is_blanket = proto == "all"
        port, service = (None, None)
        if is_blanket:
            service = "ALL"
        elif proto in ("tcp", "udp"):
            port_m = re.search(r"dpt:(\d+)", line)
            if port_m:
                candidate = int(port_m.group(1))
                entry = _CONNECTIVITY_PORTS.get(candidate)
                if entry and proto in entry[1]:
                    port, service = candidate, entry[0]
        if service or is_icmp:
            suspects.append({
                "name": f"{chain or '?'} chain: {target} {proto}",
                "direction": {"INPUT": "in", "OUTPUT": "out", "FORWARD": "forward"}.get(chain, chain),
                "protocol": "icmp" if is_icmp else proto,
                "port": port,
                "service": "ICMP" if is_icmp else service,
                "action": target.lower(),
            })
    return suspects


def _firewall_linux_nft(errors):
    """
    Fallback for nftables-only systems (no iptables shim installed).
    Coarse line-based parsing, not a full nft grammar parser -- looks for
    drop/reject lines that also mention ICMP or a _CONNECTIVITY_PORTS
    match, same "good enough, report clearly when it isn't" approach as
    the rest of this file's OS-tool parsing.

    Also recognizes two blanket-block shapes as service "ALL": a chain's
    own `policy drop;`/`policy reject;` line (nft's default-policy
    syntax), and a drop/reject statement that names neither a port nor
    ICMP at all -- most likely an unrestricted rule. This is a looser
    heuristic than the other nft matches, flagged as such: nft can drop
    a single non-tcp/udp/icmp protocol this same way, which would look
    identical here. Kept anyway because missing an actual blanket rule
    is worse than an occasional over-broad flag on this fallback path.
    """
    try:
        result = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("nft not installed")
        return None
    except subprocess.TimeoutExpired:
        errors.append("nft list ruleset timed out")
        return None
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"nft list ruleset failed: {msg}")
        if "permission denied" in msg.lower():
            errors.append("Reading nftables rules usually needs root -- try running with sudo.")
        return None

    suspects = []
    for line in result.stdout.splitlines():
        stripped = line.strip()

        policy_m = re.match(r"^policy\s+(drop|reject)\s*;?", stripped, re.IGNORECASE)
        if policy_m:
            suspects.append({
                "name": stripped, "direction": None, "protocol": "all",
                "port": None, "service": "ALL", "action": policy_m.group(1).lower(),
            })
            continue

        if not re.search(r"\b(drop|reject)\b", stripped, re.IGNORECASE):
            continue
        is_icmp = re.search(r"\bicmpx?(v6)?\b", stripped, re.IGNORECASE) is not None
        proto = "udp" if "udp" in stripped.lower() else "tcp" if "tcp" in stripped.lower() else None
        port, service = (None, None)
        if proto:
            port_m = re.search(r"dport\s+(\d+)", stripped)
            if port_m:
                candidate = int(port_m.group(1))
                entry = _CONNECTIVITY_PORTS.get(candidate)
                if entry and proto in entry[1]:
                    port, service = candidate, entry[0]
        is_blanket = not is_icmp and not service and proto is None
        if is_blanket:
            service = "ALL"
        if service or is_icmp:
            suspects.append({
                "name": stripped,
                "direction": None,
                "protocol": "icmp" if is_icmp else (proto or "all"),
                "port": port,
                "service": "ICMP" if is_icmp else service,
                "action": "drop" if re.search(r"\bdrop\b", stripped, re.IGNORECASE) else "reject",
            })
    return suspects


def _firewall_macos(errors):
    """
    Parses `pfctl -sr` for block rules matching a port in
    _CONNECTIVITY_PORTS, ICMP, or a blanket rule -- a `block` line naming
    neither `udp` nor `tcp`. That's correct pf semantics, not a guess:
    pf rules apply to all protocols by default when `proto` is omitted,
    so the absence of either keyword genuinely means "blocks everything,"
    same reasoning as iptables' protocol "all" rows. Needs root -- pfctl's
    own error message says so plainly, so that's passed through rather
    than guessed at.
    """
    try:
        result = subprocess.run(["pfctl", "-sr"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("pfctl not found (unexpected on macOS)")
        return []
    except subprocess.TimeoutExpired:
        errors.append("pfctl -sr timed out")
        return []
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"pfctl -sr failed: {msg}")
        if "must be root" in msg.lower() or "permission" in msg.lower():
            errors.append("Reading pf rules needs root -- try running with sudo.")
        return []

    suspects = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not re.match(r"^block\b", stripped, re.IGNORECASE):
            continue
        lower = stripped.lower()
        is_icmp = "icmp" in lower
        proto = "udp" if "udp" in lower else "tcp" if "tcp" in lower else None
        port, service = (None, None)
        if proto:
            port_m = re.search(r"port\s*=?\s*(\d+)", lower)
            if port_m:
                candidate = int(port_m.group(1))
                entry = _CONNECTIVITY_PORTS.get(candidate)
                if entry and proto in entry[1]:
                    port, service = candidate, entry[0]
        is_blanket = not is_icmp and not service and proto is None
        if is_blanket:
            service = "ALL"
        if service or is_icmp:
            direction = "in" if re.search(r"\bin\b", lower) else "out" if re.search(r"\bout\b", lower) else None
            suspects.append({
                "name": stripped,
                "direction": direction,
                "protocol": "icmp" if is_icmp else (proto or "all"),
                "port": port,
                "service": "ICMP" if is_icmp else service,
                "action": "block",
            })
    return suspects


def check_firewall_rules():
    """
    Reads the actual local firewall ruleset for any rule that blocks one
    of _CONNECTIVITY_PORTS (DNS, HTTP, HTTPS, DHCP), ICMP, or blocks
    everything (service "ALL" -- see _firewall_windows()/
    _firewall_linux_iptables()/etc. for what that covers per platform,
    including Windows' profile-level default outbound policy, which is
    a separate check since it isn't a rule at all). Pure data gathering,
    same as every other function in this file -- this reports what
    rules exist, it doesn't decide whether one of them explains a
    connectivity problem. A2's check_firewall_blocking() is what
    correlates a matching rule against an actual failure and calls it a
    likely cause.

    Only returns that small, curated subset of rules, not a full ruleset
    dump -- nothing downstream needs the rest, and a wider net would mean
    flagging a customer's legitimate custom rule as if it were the cause
    of a problem it has nothing to do with. "ALL" is the one deliberate
    exception to "curated by specific service" -- a blanket rule isn't
    a legitimate custom rule for something unrelated, it's evidence
    against every connectivity symptom at once.

    Known limitation: reading the full ruleset needs root on Linux
    (iptables/nft) and macOS (pfctl). Without it, the errors list
    explains why instead of silently returning "no blocking rules found"
    -- an empty result has to be distinguishable from "couldn't check,"
    same reasoning behind every other error-surfacing fix in this file.
    Windows' netsh advfirewall doesn't need elevation to read rules.

    Returns (suspect_rules, errors).
    """
    errors = []
    suspects = []
    try:
        if SYSTEM == "Windows":
            suspects = _firewall_windows(errors)
            outbound_blocked = _windows_firewall_profile_policy(errors)
            if outbound_blocked:
                suspects.append({
                    "name": "Windows Firewall profile default (Outbound connections: Block)",
                    "direction": "out", "protocol": "all", "port": None,
                    "service": "ALL", "action": "block",
                })
        elif SYSTEM == "Linux":
            result = _firewall_linux_iptables(errors)
            if result is None:
                result = _firewall_linux_nft(errors)
            if result is None:
                errors.append("could not read firewall rules via iptables or nft")
                suspects = []
            else:
                suspects = result
        elif SYSTEM == "Darwin":
            suspects = _firewall_macos(errors)
        else:
            errors.append(f"unrecognized platform: {SYSTEM}")
    except Exception as e:
        errors.append(f"unexpected error checking firewall rules: {e}")
    return suspects, errors


# UPnP IGD (Internet Gateway Device) -- see query_upnp_gateway() below for
# what this is and why it needs no router credentials.
_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_UPNP_DEVICE_NS = "urn:schemas-upnp-org:device-1-0"


def _ssdp_discover(timeout=3.0):
    """
    Sends a UPnP SSDP M-SEARCH multicast request and collects LOCATION
    URLs from any Internet Gateway Device that answers. This is the
    standard way UPnP devices are found on a LAN -- no credentials, no
    prior knowledge of the router's IP needed, just a multicast question
    on the local network.
    """
    request = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}",
        'MAN: "ssdp:discover"',
        "MX: 2",
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "", "",
    ]).encode()

    locations = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)
    deadline = time.monotonic() + timeout
    try:
        sock.sendto(request, (_SSDP_ADDR, _SSDP_PORT))
        while time.monotonic() < deadline:
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode(errors="ignore")
            m = re.search(r"^LOCATION:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)
            if m and m.group(1) not in locations:
                locations.append(m.group(1))
    except OSError:
        pass
    finally:
        sock.close()
    return locations


def _fetch_igd_xml(location_url, timeout=3.0):
    """Downloads and parses a UPnP device's description XML (a plain,
    unauthenticated HTTP GET) into an ElementTree. Returns None on any
    failure -- fetching, timing out, or malformed XML."""
    try:
        with urllib.request.urlopen(location_url, timeout=timeout) as resp:
            xml_bytes = resp.read()
        return ET.fromstring(xml_bytes)
    except (urllib.error.URLError, OSError, ValueError, ET.ParseError):
        return None


def _find_igd_service(root, base_url, wanted_substrings):
    """
    Searches a parsed IGD description tree for the first service whose
    serviceType contains any of `wanted_substrings` (e.g.
    "WANIPConnection"), at any nesting depth -- IGD services are
    typically nested a few devices deep (root -> WANDevice ->
    WANConnectionDevice -> the actual service), and ElementTree's
    .iter() searches all descendants regardless of depth. Returns
    (control_url, service_type), or (None, None) if nothing matched.
    """
    def tag(name):
        return f"{{{_UPNP_DEVICE_NS}}}{name}"

    for service in root.iter(tag("service")):
        service_type = service.findtext(tag("serviceType")) or ""
        if any(w in service_type for w in wanted_substrings):
            control = service.findtext(tag("controlURL"))
            if control:
                if not control.startswith("http"):
                    control = base_url + (control if control.startswith("/") else "/" + control)
                return control, service_type
    return None, None


def _soap_call(control_url, service_type, action, timeout=3.0):
    """
    Sends a UPnP SOAP action call (a plain HTTP POST with an XML body --
    no auth) and returns every leaf element's text from the response,
    keyed by tag name (e.g. {"NewExternalIPAddress": "41.x.x.x"}).
    Returns None on any failure.
    """
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:{action} xmlns:u="{service_type}"></u:{action}>'
        "</s:Body></s:Envelope>"
    ).encode()

    req = urllib.request.Request(
        control_url,
        data=body,
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service_type}#{action}"',
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_bytes = resp.read()
    except (urllib.error.URLError, OSError, ValueError):
        return None

    try:
        root = ET.fromstring(resp_bytes)
    except ET.ParseError:
        return None

    result = {}
    for elem in root.iter():
        tag_name = elem.tag.split("}")[-1]
        if elem.text and elem.text.strip() and not list(elem):
            result[tag_name] = elem.text.strip()
    return result


# Cheap consumer routers' UPnP stacks are frequently buggy -- these are
# the specific, recognizable ways that shows up in practice (see
# _upnp_sanity_notes()), not an exhaustive validity check.
_UPNP_MAX_UINT32 = 2**32 - 1
_UPNP_IMPLAUSIBLE_UPTIME_SECONDS = 5 * 365 * 24 * 3600  # ~5 years


def _upnp_sanity_notes(info):
    """
    UPnP IGD implementations on cheap consumer routers are frequently
    buggy. A response can be well-formed and still be nonsense -- this
    checks for the specific ways that showed up on Ammar's real Tenda
    router (a "external" IP that's actually private, an uptime of
    decades, a traffic counter sitting at exactly 2^32-1) and returns
    plain-language notes about them, instead of silently printing
    whatever the firmware said as if it were trustworthy.
    """
    notes = []

    ext_ip = info.get("external_ip")
    if ext_ip:
        try:
            if ipaddress.ip_address(ext_ip).is_private:
                notes.append(
                    f"external_ip ({ext_ip}) is itself a private address -- a real WAN IP "
                    "can't be private. This router is behind another router/NAT (double-NAT), "
                    "common with some FTTH ONT/modem setups. Port forwarding may need to "
                    "happen on the upstream device instead."
                )
        except ValueError:
            pass

    uptime = info.get("uptime_seconds")
    if uptime is not None:
        try:
            uptime_int = int(uptime)
            if uptime_int > _UPNP_IMPLAUSIBLE_UPTIME_SECONDS:
                years = round(uptime_int / (365 * 24 * 3600), 1)
                notes.append(
                    f"uptime_seconds ({uptime_int}, about {years} years) is implausible for a "
                    "home router -- almost certainly a bug in this router's UPnP firmware, not "
                    "a real reading."
                )
        except (TypeError, ValueError):
            pass

    for key in ("total_bytes_sent", "total_bytes_received"):
        val = info.get(key)
        if val is not None:
            try:
                if int(val) == _UPNP_MAX_UINT32:
                    notes.append(
                        f"{key} is exactly 2^32-1 -- the signature of either an overflowed/"
                        "wrapped 32-bit counter or a \"not really supported\" sentinel value. "
                        "Not a reliable measurement."
                    )
            except (TypeError, ValueError):
                pass

    return notes


def query_upnp_gateway(timeout=3.0):
    """
    Talks to the router via UPnP IGD (Internet Gateway Device) -- a real,
    standardized protocol most consumer routers (Tenda/TP-Link included)
    support, and one that's normally unauthenticated on the LAN by
    design (it exists so any app can request port-forwarding without a
    login prompt). No router credentials needed, unlike the web admin
    panel.

    This only ever covers what the standard exposes: WAN/external IP,
    connection status, uptime, and (best-effort) traffic byte counters.
    It does NOT get the DHCP client list or the router's actual
    configured DHCP range -- that data only lives behind the router's
    own web admin login, which UPnP doesn't expose. See CLAUDE.md's
    "Flagged / open decisions" for that piece.

    Known gap: the WANCommonInterfaceConfig traffic-counter lookup is
    unverified against real hardware -- not every router implements it,
    and a missing/failed result there is treated as "not available,"
    not an error, since it's a bonus on top of the core WAN info.

    A successful response isn't necessarily a *trustworthy* one -- see
    _upnp_sanity_notes(), which info["notes"] holds the output of.

    Returns (info, errors). info is {} if no IGD was found at all.
    """
    errors = []
    info = {}

    locations = _ssdp_discover(timeout=timeout)
    if not locations:
        errors.append(
            "No UPnP Internet Gateway Device responded to SSDP discovery "
            "(some routers have UPnP turned off by default)"
        )
        return info, errors

    root = None
    base_url = None
    for location in locations:
        candidate_root = _fetch_igd_xml(location, timeout=timeout)
        if candidate_root is not None:
            parsed = urllib.parse.urlparse(location)
            root = candidate_root
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            break
    if root is None:
        errors.append(f"Found {len(locations)} UPnP device(s) but couldn't fetch/parse their description XML")
        return info, errors

    control_url, service_type = _find_igd_service(root, base_url, ("WANIPConnection", "WANPPPConnection"))
    if not control_url:
        errors.append("No WANIPConnection/WANPPPConnection service found in the UPnP device description")
        return info, errors
    info["control_url"] = control_url
    info["service_type"] = service_type

    ext_ip = _soap_call(control_url, service_type, "GetExternalIPAddress", timeout=timeout)
    if ext_ip and "NewExternalIPAddress" in ext_ip:
        info["external_ip"] = ext_ip["NewExternalIPAddress"]
    else:
        errors.append("GetExternalIPAddress did not return a usable response")

    status = _soap_call(control_url, service_type, "GetStatusInfo", timeout=timeout)
    if status:
        info["connection_status"] = status.get("NewConnectionStatus")
        info["uptime_seconds"] = status.get("NewUptime")
        info["last_connection_error"] = status.get("NewLastConnectionError")
    else:
        errors.append("GetStatusInfo did not return a usable response")

    # Traffic counters live on a different service (WANCommonInterfaceConfig,
    # a sibling of WANIPConnection) that not every router implements --
    # best-effort, missing is normal, not an error.
    traffic_control_url, traffic_service_type = _find_igd_service(root, base_url, ("WANCommonInterfaceConfig",))
    if traffic_control_url:
        sent = _soap_call(traffic_control_url, traffic_service_type, "GetTotalBytesSent", timeout=timeout)
        received = _soap_call(traffic_control_url, traffic_service_type, "GetTotalBytesReceived", timeout=timeout)
        if sent and "NewTotalBytesSent" in sent:
            info["total_bytes_sent"] = sent["NewTotalBytesSent"]
        if received and "NewTotalBytesReceived" in received:
            info["total_bytes_received"] = received["NewTotalBytesReceived"]

    info["notes"] = _upnp_sanity_notes(info)
    return info, errors


def get_arp_table():
    """
    Reads the OS ARP table (IP -> MAC), which reflects Layer 2 activity.
    This catches devices that block ICMP ping, because ARP resolution
    happens below the firewall -- a device has to answer ARP requests to
    receive any IP traffic at all, ping or otherwise.
    """
    entries = {}
    try:
        if SYSTEM == "Linux":
            # /proc/net/arp is more reliably parseable than `arp -a` output.
            with open("/proc/net/arp") as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    ip, mac = parts[0], parts[3]
                    if mac != "00:00:00:00:00:00":
                        entries[ip] = mac.upper()
        else:
            out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
            for line in out.splitlines():
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}).*?((?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2})", line)
                if m:
                    ip, mac = m.group(1), m.group(2).replace("-", ":").upper()
                    entries[ip] = mac
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return entries


def lookup_vendor(mac):
    """Looks up a MAC's vendor in the seed OUI table. Known gap: small
    table, needs a full offline OUI database later (see CLAUDE.md)."""
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8]
    return OUI_TABLE.get(prefix, "Unknown")


def resolve_hostname(ip):
    """Offline hostname resolution via the OS resolver (hosts file, mDNS/
    NetBIOS caches, etc). No call out to the internet."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def probe_ports(ip, ports=COMMON_PORTS, timeout=0.5):
    """Tries a quick TCP connect to each common port. Returns the set of
    ports that accepted a connection."""
    open_ports = set()
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.add(port)
        except OSError:
            pass
        finally:
            s.close()
    return open_ports


def guess_role(ip, gateway_ip, open_ports):
    """Coarse role guess from open ports + whether this is the gateway.
    A2 (Rule Engine) will refine this later with real diagnostic logic."""
    if ip == gateway_ip:
        return "router/gateway"
    if 22 in open_ports:
        return "ssh host"
    if any(p in open_ports for p in (80, 443, 8080)):
        return "web-admin device"
    return "end-user device"


def _to_int(value):
    """Best-effort int conversion; returns None instead of raising."""
    if value is None:
        return None
    try:
        return int(float(str(value).strip().rstrip("%")))
    except (TypeError, ValueError):
        return None


def _freq_to_channel(freq_mhz):
    """Converts a Wi-Fi frequency in MHz (what `iw` reports) to a channel
    number. Covers 2.4GHz, 5GHz, and 6GHz (Wi-Fi 6E)."""
    try:
        freq = int(float(freq_mhz))
    except (TypeError, ValueError):
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if 5000 <= freq <= 5895:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return None


def _scan_wifi_windows(errors):
    networks = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, errors="ignore", timeout=20,
        )
    except FileNotFoundError:
        errors.append("netsh not found (unexpected on Windows)")
        return networks
    except subprocess.TimeoutExpired:
        errors.append("netsh timed out")
        return networks

    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"netsh failed: {msg}")
        if "powered down" in msg.lower():
            errors.append(
                "The Wi-Fi adapter is turned off -- check the physical Wi-Fi switch/"
                "function key, Airplane mode, or enable the adapter in Windows network "
                "adapter settings. (See the interface status list above -- Wi-Fi should "
                "show as DOWN there too.)"
            )
        return networks

    current = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("SSID") and " BSSID" not in line:
            if current:
                networks.append(current)
            current = {"ssid": line.split(":", 1)[1].strip(), "channel": None, "signal": None}
        elif line.startswith("Signal"):
            current["signal"] = _to_int(line.split(":", 1)[1])
        elif line.startswith("Authentication"):
            current["security"] = line.split(":", 1)[1].strip()
        elif line.startswith("Channel"):
            current["channel"] = _to_int(line.split(":", 1)[1])
    if current:
        networks.append(current)

    if not networks and not result.stdout.strip():
        errors.append("netsh returned no output -- is Wi-Fi turned on?")
    return networks


def _scan_wifi_nmcli(errors):
    networks = []
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, errors="ignore", timeout=20,
        )
    except FileNotFoundError:
        errors.append("nmcli not installed")
        return None
    except subprocess.TimeoutExpired:
        errors.append("nmcli timed out")
        return None

    if result.returncode != 0:
        errors.append(f"nmcli failed: {(result.stderr or result.stdout).strip()}")
        return None

    for line in result.stdout.splitlines():
        # nmcli terse output backslash-escapes literal colons inside a
        # field, so split on unescaped colons only.
        parts = re.split(r"(?<!\\):", line)
        parts = [p.replace("\\:", ":") for p in parts]
        if len(parts) >= 4 and parts[0]:
            networks.append({
                "ssid": parts[0],
                "signal": _to_int(parts[1]),
                "channel": _to_int(parts[2]),
                "security": parts[3] or "Open",
            })
    return networks


def _scan_wifi_iw(errors):
    try:
        dev_out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("iw not installed")
        return None
    except subprocess.TimeoutExpired:
        errors.append("iw dev timed out")
        return None
    if dev_out.returncode != 0:
        errors.append(f"iw dev failed: {(dev_out.stderr or dev_out.stdout).strip()}")
        return None

    iface_m = re.search(r"Interface (\S+)", dev_out.stdout)
    if not iface_m:
        errors.append("iw dev found no wireless interface")
        return None
    iface = iface_m.group(1)

    try:
        scan_out = subprocess.run(["iw", "dev", iface, "scan"], capture_output=True, text=True, timeout=25)
    except subprocess.TimeoutExpired:
        errors.append(f"iw dev {iface} scan timed out")
        return None

    if scan_out.returncode != 0:
        msg = (scan_out.stderr or scan_out.stdout).strip()
        errors.append(f"iw dev {iface} scan failed: {msg}")
        if "not permitted" in msg.lower() or "denied" in msg.lower():
            errors.append("Wi-Fi scanning on Linux usually needs root -- try running with sudo.")
        return None

    networks = []
    current = None
    for line in scan_out.stdout.splitlines():
        stripped = line.strip()
        if line.startswith("BSS "):
            if current:
                networks.append(current)
            current = {"ssid": None, "channel": None, "signal": None, "security": "Open"}
        elif current is None:
            continue
        elif stripped.startswith("freq:"):
            current["channel"] = _freq_to_channel(stripped.split(":", 1)[1].strip())
        elif stripped.startswith("signal:"):
            current["signal"] = _to_int(stripped.split(":", 1)[1].replace("dBm", ""))
        elif stripped.startswith("SSID:"):
            current["ssid"] = stripped.split(":", 1)[1].strip() or "(hidden)"
        elif stripped.startswith("RSN:") or stripped.startswith("WPA:"):
            current["security"] = "WPA/WPA2"
    if current:
        networks.append(current)

    if not networks and not scan_out.stdout.strip():
        errors.append(f"iw dev {iface} scan returned no output")
    return networks


def _scan_wifi_iwlist(errors):
    try:
        result = subprocess.run(["iwlist", "scan"], capture_output=True, text=True, errors="ignore", timeout=25)
    except FileNotFoundError:
        errors.append("iwlist not installed (install wireless-tools, or use NetworkManager for nmcli)")
        return None
    except subprocess.TimeoutExpired:
        errors.append("iwlist scan timed out")
        return None

    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"iwlist scan failed: {msg}")
        if "not permitted" in msg.lower():
            errors.append("Wi-Fi scanning on Linux usually needs root -- try running with sudo.")
        return None

    networks = []
    current = None
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Cell"):
            if current:
                networks.append(current)
            current = {"ssid": None, "channel": None, "signal": None, "security": "Open"}
        elif current is None:
            continue
        elif line.startswith("ESSID"):
            current["ssid"] = line.split(":", 1)[1].strip('"') or "(hidden)"
        elif "Signal level" in line:
            m = re.search(r"Signal level[=:](-?\d+)", line)
            if m:
                current["signal"] = int(m.group(1))
        elif line.startswith("Channel:"):
            current["channel"] = _to_int(line.split(":", 1)[1])
        elif "Encryption key:on" in line:
            current["security"] = "WEP/WPA"
    if current:
        networks.append(current)
    return networks


def _scan_wifi_macos(errors):
    networks = []
    try:
        iface_out = subprocess.run(["networksetup", "-listallhardwareports"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        errors.append(f"networksetup -listallhardwareports failed: {e}")
        return networks

    iface_m = re.search(r"Hardware Port: Wi-Fi\nDevice: (\w+)", iface_out.stdout)
    iface = iface_m.group(1) if iface_m else "en0"

    try:
        result = subprocess.run(["networksetup", "-getairportnetwork", iface], capture_output=True, text=True, errors="ignore", timeout=10)
    except subprocess.TimeoutExpired:
        errors.append("networksetup -getairportnetwork timed out")
        return networks

    if result.returncode != 0:
        errors.append(f"networksetup failed: {(result.stderr or result.stdout).strip()}")
        return networks

    m = re.search(r"Current Wi-Fi Network:\s*(.+)", result.stdout)
    if m:
        networks.append({
            "ssid": m.group(1).strip(),
            "channel": None,
            "signal": None,
            "note": "current network only -- Apple removed the nearby-scan tool "
                    "(airport) from recent macOS versions, this is a platform limit",
        })
    else:
        errors.append("Not currently connected to Wi-Fi (macOS can only report the connected network)")
    return networks


def scan_wifi_networks():
    """
    Scans for nearby Wi-Fi networks using OS-native tools (no libraries).
    On macOS this can only report the currently connected network -- see
    _scan_wifi_macos().

    Returns (networks, errors). Every failure is reported in `errors`
    instead of being silently swallowed -- an earlier version of this
    function caught every exception and did nothing with it, so a failed
    scan looked identical to "no networks found."
    """
    errors = []
    networks = []
    try:
        if SYSTEM == "Windows":
            networks = _scan_wifi_windows(errors)
        elif SYSTEM == "Linux":
            # Try nmcli first (no root needed if NetworkManager owns the
            # interface), then iw, then the older iwlist -- in roughly
            # newest-and-most-likely-to-work to oldest order.
            networks = _scan_wifi_nmcli(errors)
            if not networks:
                networks = _scan_wifi_iw(errors)
            if not networks:
                networks = _scan_wifi_iwlist(errors)
            networks = networks or []
        elif SYSTEM == "Darwin":
            networks = _scan_wifi_macos(errors)
        else:
            errors.append(f"unrecognized platform: {SYSTEM}")
    except Exception as e:  # belt-and-braces -- every path above handles
        # its own errors, so reaching here means something unexpected.
        errors.append(f"unexpected error during Wi-Fi scan: {e}")

    return networks, errors


def _signal_weight(signal):
    """
    Turns a signal reading into a rough 0..1 "how disruptive is this to a
    neighbouring channel" weight. Signal comes in two scales depending on
    which tool found it: dBm (negative, e.g. -42, from iw/iwlist) or a
    0-100 percentage (nmcli, netsh). Unknown/missing readings get a
    neutral 0.5 so one bad reading doesn't zero out a whole channel.
    """
    if signal is None:
        return 0.5
    if signal < 0:
        return max(0.0, min(1.0, (signal + 90) / 60))
    return max(0.0, min(1.0, signal / 100))


def suggest_best_channel(networks):
    """
    Looks at every Wi-Fi network we saw and recommends the least congested
    channel, separately for 2.4GHz and 5GHz. Only networks with a
    parseable numeric channel count towards this -- one with no channel
    info just gets skipped.

    2.4GHz channels overlap their neighbours (each channel is 20MHz wide
    but they're spaced 5MHz apart), so a network on channel 3 partially
    congests channels 1 and 6 too. We only ever recommend among 1/6/11 --
    the three channels that don't overlap anything -- same as any
    professional Wi-Fi installer would.

    5GHz channels don't overlap each other the same way, so it's just
    "which channel has the fewest/weakest networks on it already."
    """
    band24 = [n for n in networks if n.get("channel") is not None and 1 <= n["channel"] <= 14]
    band5 = [n for n in networks if n.get("channel") is not None and n["channel"] >= 36]

    recommendation = {}

    if band24:
        scores = {}
        for ch in NONOVERLAPPING_24GHZ:
            score = 0.0
            for n in band24:
                distance = abs(n["channel"] - ch)
                if distance == 0:
                    weight = 1.0
                elif distance <= 4:
                    weight = (5 - distance) / 5
                else:
                    weight = 0.0
                score += weight * _signal_weight(n.get("signal"))
            scores[ch] = round(score, 2)
        best = min(scores, key=scores.get)
        recommendation["2.4ghz"] = {"recommended_channel": best, "congestion_by_channel": scores}

    if band5:
        scores = {ch: 0.0 for ch in COMMON_5GHZ}
        for n in band5:
            ch = n["channel"]
            scores[ch] = round(scores.get(ch, 0.0) + _signal_weight(n.get("signal")), 2)
        best = min(scores, key=scores.get)
        recommendation["5ghz"] = {"recommended_channel": best, "congestion_by_channel": scores}

    return recommendation


def run_discovery(skip_ports=False, skip_wifi=False, skip_internet=False, skip_upnp=False, skip_firewall=False):
    print("Detecting local network...")
    local_ip, network_str = get_local_ip_and_subnet()
    gateway_ip = get_default_gateway()
    dns_servers, dns_errors = get_dns_servers()
    ip_mode, ip_mode_errors = get_ip_assignment_mode(local_ip)
    print(f"  Local IP: {local_ip} ({ip_mode})")
    print(f"  Subnet:   {network_str}")
    print(f"  Gateway:  {gateway_ip or 'not found'}")
    print(f"  DNS:      {', '.join(dns_servers) if dns_servers else 'not found'}")
    for err in dns_errors + ip_mode_errors:
        print(f"  ! {err}")

    gateway_latency = check_gateway_latency(gateway_ip)
    if gateway_latency["target"]:
        print(f"  Gateway latency: {gateway_latency['received']}/{gateway_latency['sent']} replies, "
              f"{gateway_latency['loss_percent']}% loss, avg {gateway_latency['avg_ms']}ms")

    print("\nChecking network interfaces...")
    interfaces, iface_errors = get_interface_status()
    for err in iface_errors:
        print(f"  ! {err}")
    for iface in interfaces:
        admin = "enabled" if iface["admin_enabled"] else "DISABLED"
        if iface["connected"] is None:
            conn = "connected: unknown"
        else:
            conn = "connected" if iface["connected"] else "not connected"
        mtu = f"mtu={iface['mtu']}" if iface["mtu"] else "mtu=?"
        print(f"  {iface['name']:<12} type={iface['type']:<9} {admin:<10} {conn:<16} {mtu}")

    wifi_radio, wifi_radio_errors = get_wifi_radio_state()
    if wifi_radio["hardware"] or wifi_radio["software"]:
        print(f"  Wi-Fi radio: hardware={wifi_radio['hardware'] or '?'} software={wifi_radio['software'] or '?'}")
        if wifi_radio["software"] == "off":
            print("    Wi-Fi is software-disabled -- this is what Airplane Mode or an Fn-key Wi-Fi toggle turns off.")
        if wifi_radio["hardware"] == "off":
            print("    Wi-Fi is hardware-disabled -- check for a physical Wi-Fi switch.")
    for err in wifi_radio_errors:
        print(f"  ! {err}")

    print("\nPinging subnet (this can take a bit)...")
    alive = ping_sweep(network_str)

    print("Reading ARP table...")
    arp_table = get_arp_table()

    # A device counts as "found" if it answered ping OR shows up in ARP --
    # this is the fix for devices with ICMP disabled (see CLAUDE.md).
    all_ips = alive | set(arp_table.keys())
    all_ips = {ip for ip in all_ips if ipaddress.ip_address(ip) in ipaddress.ip_network(network_str, strict=False)}

    print(f"Found {len(all_ips)} device(s). Gathering details...\n")

    devices = []
    for ip in sorted(all_ips, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = arp_table.get(ip)
        vendor = lookup_vendor(mac)
        hostname = resolve_hostname(ip)
        open_ports = probe_ports(ip) if not skip_ports else set()
        role = guess_role(ip, gateway_ip, open_ports)

        device = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "responded_to_ping": ip in alive,
            "open_ports": sorted(open_ports),
            "role_guess": role,
        }
        devices.append(device)

        print(f"  {ip:<15} mac={mac or 'unknown':<17} vendor={vendor:<20} "
              f"hostname={hostname or '-':<20} role={role}")

    pool_usage = calculate_pool_usage(network_str, len(all_ips))
    print(f"\nIP pool usage: {pool_usage['used']}/{pool_usage['total_usable']} "
          f"({pool_usage['percent_used']}%) -- across the scanned subnet, "
          f"not necessarily the router's actual DHCP range")

    wifi_networks, wifi_errors = [], []
    channel_recommendation = {}
    if not skip_wifi:
        print("\nScanning Wi-Fi networks...")
        wifi_networks, wifi_errors = scan_wifi_networks()

        for err in wifi_errors:
            print(f"  ! {err}")

        if wifi_networks:
            for net in wifi_networks:
                print(f"  {net}")
            channel_recommendation = suggest_best_channel(wifi_networks)
            if channel_recommendation:
                print("\nChannel recommendation:")
                for band, info in channel_recommendation.items():
                    print(f"  {band}: use channel {info['recommended_channel']} "
                          f"(congestion by channel: {info['congestion_by_channel']})")
        elif not wifi_errors:
            print("  No Wi-Fi networks found.")

    internet = {"reachable": None, "checks": []}
    if not skip_internet:
        print("\nChecking internet reachability...")
        internet = check_internet_reachability()
        if internet["reachable"]:
            ok = next(c for c in internet["checks"] if c["reachable"])
            print(f"  Reachable ({ok['target']} in {ok['latency_ms']}ms)")
        else:
            tried = ", ".join(c["target"] for c in internet["checks"])
            print(f"  NOT reachable (tried {tried})")

    dns_resolution = {"servers_tested": [], "any_working": None}
    if not skip_internet:
        print("\nChecking DNS resolution (not just configured -- actually tested)...")
        if dns_servers:
            dns_resolution = check_dns_resolution(dns_servers)
            for result in dns_resolution["servers_tested"]:
                if result["working"]:
                    print(f"  {result['server']:<15} working ({result['latency_ms']}ms)")
                else:
                    print(f"  {result['server']:<15} NOT working ({result['error']})")
            if internet["reachable"] and not dns_resolution["any_working"]:
                print("  Internet is reachable but no configured DNS server is resolving names -- "
                      "this looks like a DNS problem, not a general connectivity problem.")
        else:
            print("  No DNS servers were found to test (see the ! line under DNS above).")

    firewall_rules, firewall_errors = [], []
    if not skip_firewall:
        print("\nChecking local firewall rules for DNS/HTTP/HTTPS/DHCP/ICMP blocks...")
        firewall_rules, firewall_errors = check_firewall_rules()
        for err in firewall_errors:
            print(f"  ! {err}")
        if firewall_rules:
            for r in firewall_rules:
                if r["service"] == "ALL":
                    print(f"  ! {r['name']} blocks ALL outbound traffic")
                else:
                    print(f"  ! {r['name']} blocks {r['service']}" + (f" (port {r['port']})" if r["port"] else ""))
        elif not firewall_errors:
            print("  No rules blocking DNS/HTTP/HTTPS/DHCP/ICMP found.")

    upnp_gateway, upnp_errors = {}, []
    if not skip_upnp:
        print("\nChecking router via UPnP (no credentials needed)...")
        upnp_gateway, upnp_errors = query_upnp_gateway()
        for err in upnp_errors:
            print(f"  ! {err}")
        if upnp_gateway.get("external_ip"):
            print(f"  External IP: {upnp_gateway['external_ip']}")
        if upnp_gateway.get("connection_status"):
            print(f"  Connection:  {upnp_gateway['connection_status']}"
                  + (f" (uptime {upnp_gateway['uptime_seconds']}s)" if upnp_gateway.get("uptime_seconds") else ""))
        if upnp_gateway.get("total_bytes_sent") or upnp_gateway.get("total_bytes_received"):
            print(f"  Traffic:     sent={upnp_gateway.get('total_bytes_sent', '?')} "
                  f"received={upnp_gateway.get('total_bytes_received', '?')}")
        for note in upnp_gateway.get("notes", []):
            print(f"  ! {note}")

    return {
        "local_ip": local_ip,
        "ip_assignment_mode": ip_mode,
        "ip_assignment_errors": ip_mode_errors,
        "subnet": network_str,
        "gateway": gateway_ip,
        "gateway_latency": gateway_latency,
        "dns_servers": dns_servers,
        "dns_scan_errors": dns_errors,
        "interfaces": interfaces,
        "interface_scan_errors": iface_errors,
        "wifi_radio_state": wifi_radio,
        "wifi_radio_errors": wifi_radio_errors,
        "pool_usage": pool_usage,
        "devices": devices,
        "wifi_networks": wifi_networks,
        "wifi_scan_errors": wifi_errors,
        "channel_recommendation": channel_recommendation,
        "internet": internet,
        "dns_resolution": dns_resolution,
        "firewall_rules": firewall_rules,
        "firewall_scan_errors": firewall_errors,
        "upnp_gateway": upnp_gateway,
        "upnp_errors": upnp_errors,
    }


def main():
    parser = argparse.ArgumentParser(description="Offline network discovery (Module A1)")
    parser.add_argument("--json", nargs="?", const="-", default=None,
                         help="Export results as JSON. Give a path to write to a file, "
                              "or omit the path to print JSON to stdout.")
    parser.add_argument("--no-ports", action="store_true", help="Skip port probing (faster)")
    parser.add_argument("--no-wifi", action="store_true", help="Skip Wi-Fi network scanning (faster)")
    parser.add_argument("--no-internet", action="store_true",
                         help="Skip the internet reachability check (A1's one exception to staying fully offline)")
    parser.add_argument("--no-upnp", action="store_true",
                         help="Skip the UPnP router query (still LAN-only, but a separate protocol/socket path)")
    parser.add_argument("--no-firewall", action="store_true",
                         help="Skip the local firewall rule scan (reading the full ruleset needs root on Linux/macOS)")
    parser.add_argument("--cache", action="store_true",
                         help="Also write this scan straight into A6 (Encrypted Local Cache) via write_scan(). "
                              "Needs a6_encrypted_cache_v*.py next to this file and the 'cryptography' package.")
    parser.add_argument("--cache-db", default=None,
                         help="A6 database path (default: A6's own default, network_cache.db)")
    parser.add_argument("--cache-key", default=None,
                         help="A6 key file path (default: A6's own default, network_cache.key)")
    args = parser.parse_args()

    results = run_discovery(
        skip_ports=args.no_ports, skip_wifi=args.no_wifi,
        skip_internet=args.no_internet, skip_upnp=args.no_upnp,
        skip_firewall=args.no_firewall,
    )

    if args.json:
        payload = json.dumps(results, indent=2)
        if args.json == "-":
            print("\n" + payload)
        else:
            with open(args.json, "w") as f:
                f.write(payload)
            print(f"\nWrote JSON results to {args.json}")

    if args.cache:
        a6 = _import_a6()
        if a6 is None:
            print("\n! --cache: no a6_encrypted_cache_v*.py found next to this file -- scan not cached.",
                  file=sys.stderr)
        else:
            try:
                kwargs = {}
                if args.cache_db:
                    kwargs["db_path"] = args.cache_db
                if args.cache_key:
                    kwargs["key_path"] = args.cache_key
                with a6.A6Cache(**kwargs) as cache:
                    scan_id = cache.write_scan(results, source_version=os.path.basename(__file__))
                print(f"\nCached scan as A6 scan id {scan_id} "
                      f"({args.cache_db or a6.DEFAULT_DB_PATH})")
            except ImportError as e:
                print(f"\n! --cache: {e} -- scan not cached (A1 itself still ran fine).", file=sys.stderr)
            except Exception as e:
                print(f"\n! --cache: failed to write to A6: {e} -- scan not cached.", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
