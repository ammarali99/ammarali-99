#!/usr/bin/env python3
"""
network_discovery.py -- Module A1 (Discovery) of the offline network
diagnostic app.

VERSION: 0.2.0
CHANGELOG:
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

Run it directly:  python3 network_discovery_v0.2.0.py
Skip the slow steps while testing:  python3 network_discovery_v0.2.0.py --no-ports --no-wifi
Dump machine-readable output:       python3 network_discovery_v0.2.0.py --json out.json

Note on Wi-Fi scanning permissions: on Linux, actually triggering a scan
(as opposed to reading a cached list) usually needs root. If you see a
"not permitted" style error in the output, try running with sudo.
"""

import argparse
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

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
        errors.append(f"netsh failed: {(result.stderr or result.stdout).strip()}")
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


def run_discovery(skip_ports=False, skip_wifi=False):
    print("Detecting local network...")
    local_ip, network_str = get_local_ip_and_subnet()
    gateway_ip = get_default_gateway()
    print(f"  Local IP: {local_ip}")
    print(f"  Subnet:   {network_str}")
    print(f"  Gateway:  {gateway_ip or 'not found'}")

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

    return {
        "local_ip": local_ip,
        "subnet": network_str,
        "gateway": gateway_ip,
        "devices": devices,
        "wifi_networks": wifi_networks,
        "wifi_scan_errors": wifi_errors,
        "channel_recommendation": channel_recommendation,
    }


def main():
    parser = argparse.ArgumentParser(description="Offline network discovery (Module A1)")
    parser.add_argument("--json", nargs="?", const="-", default=None,
                         help="Export results as JSON. Give a path to write to a file, "
                              "or omit the path to print JSON to stdout.")
    parser.add_argument("--no-ports", action="store_true", help="Skip port probing (faster)")
    parser.add_argument("--no-wifi", action="store_true", help="Skip Wi-Fi network scanning (faster)")
    args = parser.parse_args()

    results = run_discovery(skip_ports=args.no_ports, skip_wifi=args.no_wifi)

    if args.json:
        payload = json.dumps(results, indent=2)
        if args.json == "-":
            print("\n" + payload)
        else:
            with open(args.json, "w") as f:
                f.write(payload)
            print(f"\nWrote JSON results to {args.json}")


if __name__ == "__main__":
    sys.exit(main())
