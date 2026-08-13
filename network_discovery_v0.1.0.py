#!/usr/bin/env python3
"""
network_discovery.py -- Module A1 (Discovery) of the offline network
diagnostic app.

VERSION: 0.1.0
CHANGELOG:
  0.1.0 - First version in this repo. Implements everything listed under
          "Current state" in CLAUDE.md: local IP/subnet + gateway
          detection, threaded ping sweep, ARP cross-reference (catches
          devices with ICMP disabled), seed MAC vendor lookup, offline
          hostname resolution, common-port probing with role guessing,
          Wi-Fi network scanning, and JSON export.

Standard-library only. No pip installs, on purpose -- see CLAUDE.md for why.

Run it directly:  python3 network_discovery_v0.1.0.py
Skip the slow steps while testing:  python3 network_discovery_v0.1.0.py --no-ports --no-wifi
Dump machine-readable output:       python3 network_discovery_v0.1.0.py --json out.json
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


def scan_wifi_networks():
    """
    Scans for nearby Wi-Fi networks using OS-native tools (no libraries).
    On macOS this can only report the currently connected network -- Apple
    removed the `airport` nearby-scan tool from recent macOS versions, so
    that's a platform limitation, not a bug in this code.
    """
    networks = []
    try:
        if SYSTEM == "Windows":
            out = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"], text=True, errors="ignore")
            current = {}
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("SSID"):
                    if current:
                        networks.append(current)
                    current = {"ssid": line.split(":", 1)[1].strip()}
                elif line.startswith("Signal"):
                    current["signal"] = line.split(":", 1)[1].strip()
                elif line.startswith("Authentication"):
                    current["security"] = line.split(":", 1)[1].strip()
                elif line.startswith("Channel"):
                    current["channel"] = line.split(":", 1)[1].strip()
            if current:
                networks.append(current)

        elif SYSTEM == "Linux":
            try:
                out = subprocess.check_output(
                    ["nmcli", "-t", "-f", "SSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"],
                    text=True, errors="ignore",
                )
                for line in out.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 4 and parts[0]:
                        networks.append({
                            "ssid": parts[0],
                            "signal": parts[1],
                            "channel": parts[2],
                            "security": parts[3] or "Open",
                        })
            except (subprocess.SubprocessError, FileNotFoundError):
                out = subprocess.check_output(["iwlist", "scan"], text=True, errors="ignore", stderr=subprocess.DEVNULL)
                current = {}
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("Cell"):
                        if current:
                            networks.append(current)
                        current = {}
                    elif line.startswith("ESSID"):
                        current["ssid"] = line.split(":", 1)[1].strip('"')
                    elif "Signal level" in line:
                        m = re.search(r"Signal level=(-?\d+)", line)
                        if m:
                            current["signal"] = m.group(1)
                    elif line.startswith("Channel:"):
                        current["channel"] = line.split(":", 1)[1]
                if current:
                    networks.append(current)

        elif SYSTEM == "Darwin":
            # No nearby-scan tool available on modern macOS -- only report
            # the currently connected network, per the platform limitation.
            iface_out = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
            iface_m = re.search(r"Hardware Port: Wi-Fi\nDevice: (\w+)", iface_out)
            iface = iface_m.group(1) if iface_m else "en0"
            out = subprocess.check_output(["networksetup", "-getairportnetwork", iface], text=True, errors="ignore")
            m = re.search(r"Current Wi-Fi Network:\s*(.+)", out)
            if m:
                networks.append({"ssid": m.group(1).strip(), "note": "current network only (macOS limitation)"})
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return networks


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

    wifi_networks = []
    if not skip_wifi:
        print("\nScanning Wi-Fi networks...")
        wifi_networks = scan_wifi_networks()
        for net in wifi_networks:
            print(f"  {net}")

    return {
        "local_ip": local_ip,
        "subnet": network_str,
        "gateway": gateway_ip,
        "devices": devices,
        "wifi_networks": wifi_networks,
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
