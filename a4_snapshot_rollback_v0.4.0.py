#!/usr/bin/env python3
"""
a4_snapshot_rollback.py -- Module A4 (Snapshot / Rollback Manager) of the
offline network diagnostic app.

VERSION: 0.3.0
CHANGELOG:
  0.3.0 - Ammar's explicit follow-up request, after v0.2.0: don't make
          the caller manually snapshot one named interface ahead of
          time at all. Instead, treat A6's already-stored scan history
          as the baseline, and make rollback automatic -- diff the
          live system against a chosen baseline scan, find whatever
          actually changed, and revert only that.

          take_snapshot()/restore_snapshot() (the old per-interface,
          --snapshot/--restore flow) are removed, replaced by:

            - diff_against_scan(scan_id=None): reads current live state
              and compares it field-by-field against a baseline A6 scan
              (the most recent one, or --scan-id). Returns a list of
              differences, each tagged with whether A4 actually knows
              how to revert it.
            - rollback(scan_id=None, dry_run=False): runs the diff, then
              reverts every revertible difference. Writes a record of
              what it found and did into A6 (the `snapshots` table,
              repurposed from "the before-state" to "a log of what a
              rollback actually did" -- there's no separate before-state
              to store anymore, the baseline scan already is that).

          Expanded scope, at Ammar's explicit request, beyond just
          interface admin_enabled:
            - interface_mtu: netsh interface ipv4 set subinterface /
              ip link set mtu / networksetup -setMTU.
            - interface_dns: needs A1 v0.14.0's new per-interface DNS
              (get_interface_network_config()) -- the old flat
              get_dns_servers() couldn't say which interface to fix.
              netsh interface ip set/add dns / nmcli con mod ipv4.dns /
              networksetup -setdnsservers.
            - interface_ip_mode: static-vs-DHCP, plus the actual
              IP/subnet/gateway when reverting to a specific static
              config -- also needs A1 v0.14.0's richer per-interface
              data, since the old ip_assignment_mode was just a label
              with no values to restore. netsh interface ip set address
              dhcp/static / nmcli ipv4.method / networksetup
              -setdhcp/-setmanual.
            - wifi_radio: Linux via `rfkill block/unblock wifi` -- clean,
              documented, no concerns. Windows via the Native WiFi API
              (WlanSetInterface, wlan_intf_opcode_radio_state) through
              ctypes -- there is no netsh/PowerShell command for this,
              this is the actual underlying API Windows' own network
              flyout uses. Flagged more heavily than anything else in
              this codebase: it's the only function anywhere in A1/A4
              that calls into a DLL instead of a subprocess CLI tool,
              and it cannot be exercised at all outside a real Windows
              machine -- not even by feeding it realistic sample text
              the way the other new parsers/setters were checked, since
              ctypes.windll doesn't exist on Linux. Built against the
              documented struct layouts, wrapped so any failure returns
              a clean error instead of propagating a ctypes exception,
              but genuinely unverified in a stronger sense than "not
              yet tested on real hardware" -- flagged as such rather
              than glossed over.

          What deliberately stayed manual and separate: firewall rule
          fixes. Not part of the generic diff engine at all -- there's
          no safe way to "diff" a firewall ruleset and guess what
          should revert. fix_firewall_rule() only ever acts on the
          exact rule A2's check_firewall_blocking() already identified
          as the cause (from a finding's evidence.firewall_rule), never
          a blind scan. See its own docstring for the full reasoning.

          Verified in this sandbox, stated precisely about what was and
          wasn't real:

            - interface_admin_state and interface_mtu: fully real,
              end-to-end, against a live (virtual, throwaway) veth
              interface -- broke both at once (took it down, changed
              its MTU), ran --diff and confirmed it found both without
              changing anything, ran --rollback and confirmed both
              reverted, confirmed a second --rollback found nothing
              left to do, confirmed --dry-run detects but doesn't act,
              confirmed --list-events shows an accurate history of all
              of it (including the dry run).
            - fix_firewall_finding(): fully real end-to-end against a
              real iptables DROP rule -- ran A1+A2 for real, got a real
              check_firewall_blocking() finding out of A6 by its actual
              finding_id, confirmed the lookup and evidence extraction
              work correctly; the platform guard correctly refused to
              act (Linux isn't implemented), which is the expected,
              correct behavior on this sandbox, not a bug.
            - interface_dns, interface_ip_mode, and wifi_radio's Linux
              path (rfkill): command construction verified by mocking
              subprocess.run and inspecting the exact command lines
              built for known inputs (real DNS/static-IP writes need
              NetworkManager cooperation this container's config
              fights, same limitation A1 v0.14.0 hit; rfkill has no
              actual radio device in this container to block/unblock).
            - wifi_radio's Windows path (_set_wifi_radio_windows,
              ctypes+wlanapi.dll): confirmed it safely no-ops with a
              clean error on non-Windows rather than crashing, which is
              the only thing checkable here. The actual WlanOpenHandle/
              WlanEnumInterfaces/WlanSetInterface call sequence is
              unverified in the stronger sense already flagged above --
              ctypes.windll doesn't exist to even mock on this OS.
            - interface_dns/interface_ip_mode/wifi_radio's Windows and
              macOS command paths (netsh, networksetup): follow the
              same documented syntax used elsewhere in this codebase
              but are not verified on real hardware.

  0.2.0 - Ammar's explicit request: take_snapshot() should build a
          snapshot from A1's already-collected discovery data sitting
          in A6, not from a fresh, separate OS query at snapshot time.
          Rewrote it: reads the interface's state out of a specific A6
          scan (--scan-id) or the most recent one by default, instead
          of calling get_interface_status() live. If A6 has no scans
          yet, this now raises a clear A4Error telling you to run A1
          --cache first -- it does not fall back to a live OS read,
          since that fallback is exactly the behavior being removed.

          Two real benefits beyond just "don't touch the OS twice":
          every snapshot now carries provenance (which exact scan
          justified taking it, via A6 v0.3.0's new source_scan_id
          column) instead of being a freestanding capture with no link
          back to what was actually detected; and take_snapshot() no
          longer needs A1 at all -- only A6 -- which is a real
          simplification, not just a style change.

          What deliberately did NOT change: restore_snapshot() still
          reads live OS state, twice -- once to check idempotency
          (is the interface already in the target state), once after
          running the set-state command to verify it actually took
          effect. verify_reachability_and_maybe_rollback() still checks
          live gateway/internet reachability. Neither of those can be
          answered from stored discovery data; "is this real, right
          now" is exactly what they need to know, and only a live read
          can say that. Ammar's request was specifically about where
          the snapshot's own state comes from, not about restore's
          verification step.

          A6 gets a matching v0.3.0: get_scan(id) (a direct lookup,
          same shape as v0.2.0's get_snapshot(id) -- closes a gap
          flagged twice before but never fixed since nothing needed it
          until now) and the new source_scan_id column.

          Verified end-to-end in this sandbox: ran A1 --cache for a
          real scan, took a snapshot of a real (virtual, throwaway)
          interface from that exact scan's data with --scan-id, broke
          the interface manually, restored it, confirmed it matched
          the snapshot again -- and confirmed --list-snapshots shows
          which scan each snapshot came from. Also confirmed
          take_snapshot() now fails cleanly (no OS query attempted) if
          A6 has no scans yet.

  0.1.0 - First version. CLAUDE.md places A4 before A3 (Fix Engine) on
          purpose: "rollback has to exist before anything is allowed to
          touch a device's config", and auto-rollback-if-unreachable is
          one of the architecture's explicitly non-negotiable
          safeguards. A3 doesn't exist yet, so this version is built to
          be fully testable standalone -- take a snapshot, verify it,
          restore it, verify the restore -- without needing a fix
          engine to drive it.

          Scope, deliberately narrow for v1: local-machine network
          settings only (this machine's own interfaces), not router
          config. Router-side snapshot/restore needs the router web-UI
          scraping CLAUDE.md already flagged as deferred until the
          Credential Manager exists -- no point building rollback for
          something A3 can't touch yet either. Within "local machine",
          v1 only covers one thing: an interface's admin_enabled state
          (enabled/disabled) -- the exact finding that's already fired
          for real on Ammar's hardware (a disabled Ethernet adapter).
          Two other candidates were considered and deliberately left
          out, both flagged rather than silently skipped:

            - DNS servers: A1's get_dns_servers() reads DNS as one flat
              list across the whole machine (ipconfig /all merges every
              adapter's DNS lines together), not per-interface. A
              restorable DNS snapshot needs to know which interface a
              server belongs to, which A1 doesn't capture today -- that
              would be an A1 change first, not something to guess at
              here.
            - Wi-Fi radio software on/off: A1's own get_wifi_radio_state()
              docstring already explains why it doesn't touch Windows'
              real Airplane Mode flag -- there's no clean, documented
              netsh command to *set* the software radio state back
              either (unlike admin_enabled, which netsh interface set
              does support). Same reasoning applies here: a
              confidently-wrong restore is worse than not having it.

          Reuses A1 and A6 by dynamically loading whichever
          network_discovery_v*.py / a6_encrypted_cache_v*.py sits next
          to this file, same _import_a1()/_import_a6() trick A1/A2
          already use for A6 -- so A4 never needs editing just because
          A1 or A6 bump their own version. Every dynamic-import call is
          wrapped immediately in _load_a1()/_load_a6(), which convert
          any failure (missing file, missing 'cryptography', bad key)
          into a clear A4Error -- learned directly from the real bug
          just fixed in A1 v0.13.1/A2 v0.7.2, where leaving an import
          call outside its try/except crashed with a raw traceback
          instead of a clean message. Not repeating that here.

          A6 gets a new `snapshots` table for this (A6 v0.2.0) -- see
          its own changelog. macOS needs its own small
          _macos_service_name_for_interface() helper: A1's own macOS
          code only keeps the wifi/ethernet *type* per interface, not
          the actual "Hardware Port" name (e.g. "Wi-Fi", "Thunderbolt
          Ethernet") that `networksetup -setnetworkserviceenabled`
          needs as an argument, so restoring on macOS needs that
          looked up separately rather than guessed at.

          Every restore is idempotent (if the interface is already in
          the snapshotted state, does nothing and says so) and
          verifies the OS actually applied the change before reporting
          success, rather than trusting the command's exit code alone.

          verify_reachability_and_maybe_rollback() is the standalone
          exercise of the "auto-rollback if the device becomes
          unreachable" safeguard: checks gateway packet loss and
          internet reachability (both via A1), and restores the given
          snapshot automatically if the gateway is unreachable. This is
          what A3 will eventually call after every fix attempt; for
          now it's callable directly so the mechanism itself is real
          and testable before A3 exists to drive it.

          Verified in this sandbox on Linux: took a snapshot of a real
          interface, disabled it, restored it via --restore, confirmed
          admin_enabled matched the snapshot again afterward.
          restore_snapshot()'s idempotent no-op path (restoring when
          already in the target state) and verify_reachability_and_
          maybe_rollback()'s "still reachable, no rollback" path both
          verified too. Windows/macOS command paths follow A1's own
          established read-side commands exactly but are **not yet
          verified on real hardware** -- flagged the same way A1 flags
          its own unverified platform paths, not silently assumed
          correct.
"""

import argparse
import platform
import re
import subprocess
import sys

SYSTEM = platform.system()


class A4Error(Exception):
    """Raised for A4-specific failures (missing A1/A6, unknown interface, bad snapshot)."""


def _import_a1():
    """
    Dynamically loads whichever network_discovery_v*.py sits next to
    this file, picking the highest (major, minor, patch) version
    present -- same reasoning A2 already uses to avoid hardcoding A1's
    version. Returns None if no A1 file is found.
    """
    import glob
    import importlib.util
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    candidates = glob.glob(os.path.join(here, "network_discovery_v*.py"))
    if not candidates:
        return None

    def _version_key(path):
        m = re.search(r"_v(\d+)\.(\d+)\.(\d+)\.py$", path)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    path = max(candidates, key=_version_key)
    spec = importlib.util.spec_from_file_location("network_discovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _import_a6():
    """Same trick as _import_a1(), for a6_encrypted_cache_v*.py."""
    import glob
    import importlib.util
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    candidates = glob.glob(os.path.join(here, "a6_encrypted_cache_v*.py"))
    if not candidates:
        return None

    def _version_key(path):
        m = re.search(r"_v(\d+)\.(\d+)\.(\d+)\.py$", path)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    path = max(candidates, key=_version_key)
    spec = importlib.util.spec_from_file_location("a6_encrypted_cache", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_a1():
    """
    Wraps _import_a1() so every call site is exception-safe by
    construction -- the exact gap that crashed A1 v0.13.0/A2 v0.7.1
    with a raw traceback instead of a clean message.
    """
    try:
        a1 = _import_a1()
    except Exception as e:
        raise A4Error(f"Could not load A1 (network_discovery): {e}")
    if a1 is None:
        raise A4Error("No network_discovery_v*.py found next to this file.")
    return a1


def _load_a6_cache(cache_db, cache_key):
    """Same wrapping as _load_a1(), for opening an A6Cache."""
    try:
        a6 = _import_a6()
    except Exception as e:
        raise A4Error(f"Could not load A6 (a6_encrypted_cache): {e}")
    if a6 is None:
        raise A4Error("No a6_encrypted_cache_v*.py found next to this file.")
    kwargs = {}
    if cache_db:
        kwargs["db_path"] = cache_db
    if cache_key:
        kwargs["key_path"] = cache_key
    try:
        return a6.A6Cache(**kwargs)
    except Exception as e:
        raise A4Error(f"Could not open A6 cache: {e}")


def _macos_service_name_for_interface(name):
    """
    Looks up the "Hardware Port" name (e.g. "Wi-Fi", "Thunderbolt
    Ethernet") networksetup needs for a given interface device name
    (e.g. "en0"). A1's own macOS code discards this in favor of just a
    wifi/ethernet type, so this is its own small lookup rather than an
    A1 change just for this one restore path.
    """
    try:
        out = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return None
    for block in out.split("\n\n"):
        port_m = re.search(r"Hardware Port: (.+)", block)
        dev_m = re.search(r"Device: (\w+)", block)
        if port_m and dev_m and dev_m.group(1) == name:
            return port_m.group(1).strip()
    return None


def _set_interface_admin_state(name, enabled):
    """
    Enables or disables one network interface. Returns (ok, message).
    Unlike A1's read-only interface detection, this needs elevated
    privileges on every platform -- an Administrator Command Prompt on
    Windows, root on Linux, an admin account on macOS.
    """
    try:
        if SYSTEM == "Windows":
            state = "enable" if enabled else "disable"
            result = subprocess.run(
                ["netsh", "interface", "set", "interface", name, f"admin={state}"],
                capture_output=True, text=True, errors="ignore", timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, (f"netsh interface set interface failed: {err} -- "
                                "this needs an elevated (Administrator) Command Prompt")
            return True, f'Ran: netsh interface set interface "{name}" admin={state}'

        elif SYSTEM == "Linux":
            state = "up" if enabled else "down"
            result = subprocess.run(
                ["ip", "link", "set", name, state],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, f"ip link set {name} {state} failed: {err} -- this needs root"
            return True, f"Ran: ip link set {name} {state}"

        elif SYSTEM == "Darwin":
            service = _macos_service_name_for_interface(name)
            if service is None:
                return False, (f"Could not find a networksetup hardware port for interface "
                                f"{name!r} -- can't restore its admin state on macOS")
            state = "on" if enabled else "off"
            result = subprocess.run(
                ["networksetup", "-setnetworkserviceenabled", service, state],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, f"networksetup -setnetworkserviceenabled failed: {err} -- this needs admin"
            return True, f'Ran: networksetup -setnetworkserviceenabled "{service}" {state}'

        return False, f"Unsupported platform: {SYSTEM}"
    except FileNotFoundError as e:
        return False, f"Required command not found: {e}"
    except subprocess.SubprocessError as e:
        return False, f"Command failed: {e}"


def _set_interface_mtu(name, mtu, connection_name=None):
    """Sets one interface's MTU. Returns (ok, message)."""
    try:
        if SYSTEM == "Windows":
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "set", "subinterface", name,
                 f"mtu={mtu}", "store=persistent"],
                capture_output=True, text=True, errors="ignore", timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, (f"netsh interface ipv4 set subinterface failed: {err} -- "
                                "this needs an elevated (Administrator) Command Prompt")
            return True, f'Ran: netsh interface ipv4 set subinterface "{name}" mtu={mtu} store=persistent'

        elif SYSTEM == "Linux":
            result = subprocess.run(
                ["ip", "link", "set", name, "mtu", str(mtu)],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, f"ip link set {name} mtu {mtu} failed: {err} -- this needs root"
            return True, f"Ran: ip link set {name} mtu {mtu}"

        elif SYSTEM == "Darwin":
            service = connection_name or _macos_service_name_for_interface(name)
            if service is None:
                return False, f"Could not find a networksetup hardware port for interface {name!r}"
            result = subprocess.run(
                ["networksetup", "-setMTU", service, str(mtu)],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, f"networksetup -setMTU failed: {err} -- this needs admin"
            return True, f'Ran: networksetup -setMTU "{service}" {mtu}'

        return False, f"Unsupported platform: {SYSTEM}"
    except FileNotFoundError as e:
        return False, f"Required command not found: {e}"
    except subprocess.SubprocessError as e:
        return False, f"Command failed: {e}"


def _set_interface_dns(name, dns_servers, connection_name=None):
    """
    Sets one interface's DNS servers. dns_servers=[] means "clear back
    to automatic/DHCP-provided DNS", not "no DNS at all". Returns
    (ok, message).
    """
    try:
        if SYSTEM == "Windows":
            if not dns_servers:
                result = subprocess.run(
                    ["netsh", "interface", "ip", "set", "dns", name, "dhcp"],
                    capture_output=True, text=True, errors="ignore", timeout=15,
                )
                if result.returncode != 0:
                    err = (result.stderr or result.stdout).strip()
                    return False, (f"netsh interface ip set dns dhcp failed: {err} -- "
                                    "this needs an elevated (Administrator) Command Prompt")
                return True, f'Ran: netsh interface ip set dns "{name}" dhcp'

            result = subprocess.run(
                ["netsh", "interface", "ip", "set", "dns", name, "static", dns_servers[0]],
                capture_output=True, text=True, errors="ignore", timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, (f"netsh interface ip set dns failed: {err} -- "
                                "this needs an elevated (Administrator) Command Prompt")
            for i, ip in enumerate(dns_servers[1:], start=2):
                add_result = subprocess.run(
                    ["netsh", "interface", "ip", "add", "dns", name, ip, f"index={i}"],
                    capture_output=True, text=True, errors="ignore", timeout=15,
                )
                if add_result.returncode != 0:
                    err = (add_result.stderr or add_result.stdout).strip()
                    return False, f"netsh interface ip add dns failed for {ip}: {err}"
            return True, f'Ran: netsh interface ip set/add dns "{name}" {", ".join(dns_servers)}'

        elif SYSTEM == "Linux":
            if not connection_name:
                return False, f"No nmcli connection name known for {name!r} -- can't set DNS"
            dns_value = " ".join(dns_servers)
            mod_result = subprocess.run(
                ["nmcli", "con", "mod", connection_name,
                 "ipv4.dns", dns_value,
                 "ipv4.ignore-auto-dns", "yes" if dns_servers else "no"],
                capture_output=True, text=True, errors="ignore", timeout=15,
            )
            if mod_result.returncode != 0:
                err = (mod_result.stderr or mod_result.stdout).strip()
                return False, f"nmcli con mod (DNS) failed: {err} -- this needs root"
            up_result = subprocess.run(
                ["nmcli", "con", "up", connection_name],
                capture_output=True, text=True, errors="ignore", timeout=15,
            )
            if up_result.returncode != 0:
                err = (up_result.stderr or up_result.stdout).strip()
                return False, f"nmcli con up failed after setting DNS: {err}"
            return True, f'Ran: nmcli con mod "{connection_name}" ipv4.dns "{dns_value}"'

        elif SYSTEM == "Darwin":
            service = connection_name or _macos_service_name_for_interface(name)
            if service is None:
                return False, f"Could not find a networksetup hardware port for interface {name!r}"
            args = dns_servers if dns_servers else ["empty"]
            result = subprocess.run(
                ["networksetup", "-setdnsservers", service, *args],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, f"networksetup -setdnsservers failed: {err} -- this needs admin"
            return True, f'Ran: networksetup -setdnsservers "{service}" {" ".join(args)}'

        return False, f"Unsupported platform: {SYSTEM}"
    except FileNotFoundError as e:
        return False, f"Required command not found: {e}"
    except subprocess.SubprocessError as e:
        return False, f"Command failed: {e}"


def _netmask_to_cidr(mask):
    """'255.255.255.0' -> 24. Inverse of A1's _cidr_to_netmask()."""
    return sum(bin(int(octet)).count("1") for octet in mask.split("."))


def _set_interface_ip_mode(name, mode, ip=None, subnet_mask=None, gateway=None, connection_name=None):
    """
    Switches an interface between DHCP and static, and for static, sets
    the actual IP/subnet/gateway. Returns (ok, message).
    """
    try:
        if SYSTEM == "Windows":
            if mode == "dhcp":
                result = subprocess.run(
                    ["netsh", "interface", "ip", "set", "address", name, "dhcp"],
                    capture_output=True, text=True, errors="ignore", timeout=15,
                )
                if result.returncode != 0:
                    err = (result.stderr or result.stdout).strip()
                    return False, (f"netsh interface ip set address dhcp failed: {err} -- "
                                    "this needs an elevated (Administrator) Command Prompt")
                return True, f'Ran: netsh interface ip set address "{name}" dhcp'

            if not (ip and subnet_mask and gateway):
                return False, f"Reverting {name} to static needs ip/subnet_mask/gateway -- one or more missing"
            result = subprocess.run(
                ["netsh", "interface", "ip", "set", "address", name, "static", ip, subnet_mask, gateway],
                capture_output=True, text=True, errors="ignore", timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, (f"netsh interface ip set address static failed: {err} -- "
                                "this needs an elevated (Administrator) Command Prompt")
            return True, f'Ran: netsh interface ip set address "{name}" static {ip} {subnet_mask} {gateway}'

        elif SYSTEM == "Linux":
            if not connection_name:
                return False, f"No nmcli connection name known for {name!r} -- can't change IP mode"
            if mode == "dhcp":
                mod_result = subprocess.run(
                    ["nmcli", "con", "mod", connection_name, "ipv4.method", "auto"],
                    capture_output=True, text=True, errors="ignore", timeout=15,
                )
            else:
                if not (ip and subnet_mask and gateway):
                    return False, f"Reverting {name} to static needs ip/subnet_mask/gateway -- one or more missing"
                prefix = _netmask_to_cidr(subnet_mask)
                mod_result = subprocess.run(
                    ["nmcli", "con", "mod", connection_name,
                     "ipv4.method", "manual",
                     "ipv4.addresses", f"{ip}/{prefix}",
                     "ipv4.gateway", gateway],
                    capture_output=True, text=True, errors="ignore", timeout=15,
                )
            if mod_result.returncode != 0:
                err = (mod_result.stderr or mod_result.stdout).strip()
                return False, f"nmcli con mod (IP mode) failed: {err} -- this needs root"
            up_result = subprocess.run(
                ["nmcli", "con", "up", connection_name],
                capture_output=True, text=True, errors="ignore", timeout=15,
            )
            if up_result.returncode != 0:
                err = (up_result.stderr or up_result.stdout).strip()
                return False, f"nmcli con up failed after changing IP mode: {err}"
            return True, f"Ran: nmcli con mod \"{connection_name}\" ipv4.method {'auto' if mode == 'dhcp' else 'manual'}"

        elif SYSTEM == "Darwin":
            service = connection_name or _macos_service_name_for_interface(name)
            if service is None:
                return False, f"Could not find a networksetup hardware port for interface {name!r}"
            if mode == "dhcp":
                result = subprocess.run(
                    ["networksetup", "-setdhcp", service],
                    capture_output=True, text=True, timeout=15,
                )
            else:
                if not (ip and subnet_mask and gateway):
                    return False, f"Reverting {name} to static needs ip/subnet_mask/gateway -- one or more missing"
                result = subprocess.run(
                    ["networksetup", "-setmanual", service, ip, subnet_mask, gateway],
                    capture_output=True, text=True, timeout=15,
                )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, f"networksetup IP-mode command failed: {err} -- this needs admin"
            cmd_desc = "-setdhcp" if mode == "dhcp" else f"-setmanual {ip} {subnet_mask} {gateway}"
            return True, f'Ran: networksetup {cmd_desc} "{service}"'

        return False, f"Unsupported platform: {SYSTEM}"
    except FileNotFoundError as e:
        return False, f"Required command not found: {e}"
    except subprocess.SubprocessError as e:
        return False, f"Command failed: {e}"


def _set_wifi_radio_software_state(enabled):
    """
    Turns the Wi-Fi radio's software kill-switch on/off -- the same
    mechanism Airplane Mode and Fn-key Wi-Fi toggles use, distinct from
    an adapter's admin_enabled state. Returns (ok, message).
    """
    try:
        if SYSTEM == "Linux":
            action = "unblock" if enabled else "block"
            result = subprocess.run(
                ["rfkill", action, "wifi"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                return False, f"rfkill {action} wifi failed: {err} -- this usually needs root"
            return True, f"Ran: rfkill {action} wifi"

        elif SYSTEM == "Windows":
            return _set_wifi_radio_windows(enabled)

        return False, (
            f"Wi-Fi radio software state isn't settable on {SYSTEM} through this app -- "
            "macOS has no separate software-radio-kill concept (see A1's get_wifi_radio_state())"
        )
    except FileNotFoundError as e:
        return False, f"Required command not found: {e}"
    except subprocess.SubprocessError as e:
        return False, f"Command failed: {e}"


def _set_wifi_radio_windows(enabled):
    """
    Sets the Wi-Fi software radio state via Windows' Native WiFi API
    (wlanapi.dll's WlanSetInterface, wlan_intf_opcode_radio_state) --
    the same underlying mechanism Windows' own network flyout uses.
    There is no netsh or PowerShell command for this specific thing.

    This is the only function in the entire A1/A4 codebase that calls
    into a DLL instead of a subprocess CLI tool, and the only one that
    genuinely cannot be exercised at all outside a real Windows machine
    -- not real hardware, not a mock, not realistic sample text, since
    ctypes.windll doesn't exist on any other OS. Built against the
    documented WLAN_INTERFACE_INFO_LIST / WLAN_PHY_RADIO_STATE struct
    layouts (MSDN's Native WiFi API reference), with every ctypes call
    wrapped so a failure returns a clean error instead of propagating a
    raw ctypes exception -- but this is unverified in a stronger sense
    than "not yet tested on real hardware" elsewhere in this codebase.
    Treat it with real caution until confirmed on a real machine.

    Returns (ok, message).
    """
    if SYSTEM != "Windows":
        return False, "wlanapi.dll is Windows-only"

    try:
        import ctypes
        from ctypes import wintypes
    except ImportError as e:
        return False, f"ctypes not available: {e}"

    try:
        wlanapi = ctypes.windll.wlanapi
    except (AttributeError, OSError) as e:
        return False, f"Could not load wlanapi.dll: {e}"

    try:
        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [
                ("InterfaceGuid", GUID),
                ("strInterfaceDescription", ctypes.c_wchar * 256),
                ("isState", ctypes.c_uint),
            ]

        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
            ]

        class WLAN_PHY_RADIO_STATE(ctypes.Structure):
            _fields_ = [
                ("dwPhyIndex", wintypes.DWORD),
                ("dot11SoftwareRadioState", ctypes.c_uint),
                ("dot11HardwareRadioState", ctypes.c_uint),
            ]

        WLAN_INTF_OPCODE_RADIO_STATE = 6
        DOT11_RADIO_STATE_ON = 1
        DOT11_RADIO_STATE_OFF = 2

        handle = wintypes.HANDLE()
        negotiated = wintypes.DWORD()
        ret = wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle))
        if ret != 0:
            return False, f"WlanOpenHandle failed with Windows error code {ret}"

        try:
            iface_list_ptr = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
            ret = wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(iface_list_ptr))
            if ret != 0:
                return False, f"WlanEnumInterfaces failed with Windows error code {ret}"

            try:
                iface_list = iface_list_ptr.contents
                if iface_list.dwNumberOfItems == 0:
                    return False, "No Wi-Fi interfaces found via WlanEnumInterfaces"
                guid = iface_list.InterfaceInfo[0].InterfaceGuid

                radio_state = WLAN_PHY_RADIO_STATE()
                radio_state.dwPhyIndex = 0
                radio_state.dot11SoftwareRadioState = DOT11_RADIO_STATE_ON if enabled else DOT11_RADIO_STATE_OFF

                ret = wlanapi.WlanSetInterface(
                    handle, ctypes.byref(guid), WLAN_INTF_OPCODE_RADIO_STATE,
                    ctypes.sizeof(radio_state), ctypes.byref(radio_state), None,
                )
                if ret != 0:
                    return False, f"WlanSetInterface (radio state) failed with Windows error code {ret}"
                return True, f"Set Wi-Fi software radio state to {'on' if enabled else 'off'} via WlanSetInterface"
            finally:
                wlanapi.WlanFreeMemory(iface_list_ptr)
        finally:
            wlanapi.WlanCloseHandle(handle, None)
    except Exception as e:
        return False, f"Unexpected error calling wlanapi: {e}"


def _get_baseline_scan(scan_id, cache):
    if scan_id is not None:
        scan = cache.get_scan(scan_id)
        if scan is None:
            raise A4Error(f"No scan with id {scan_id} in A6.")
        return scan
    scans = cache.get_scans(limit=1)
    if not scans:
        raise A4Error("A6 has no scans yet -- run A1 with --cache first.")
    return scans[0]


def diff_against_scan(scan_id=None, cache_db=None, cache_key=None):
    """
    Reads current live state and compares it against a baseline A6 scan
    (the most recent one, or a specific --scan-id). Returns
    (differences, scan_used) -- differences is a list of dicts:
    {"category", "target", "baseline", "current", "revertible", "note",
    "connection_name" (only for interface_dns/interface_ip_mode)}.

    Scope: interface admin_enabled, interface MTU, per-interface DNS,
    per-interface static/DHCP mode (+ values), and the Wi-Fi radio's
    software state -- the fields A1 discovers that are actually local
    "settings" in the sense of something to revert. Everything else A1
    discovers (devices seen, nearby Wi-Fi networks, gateway latency,
    pool usage, firewall rules, router/UPnP data) is either a live
    metric that fluctuates on its own, an observation rather than a
    setting, or (firewall rules, router config) handled through a
    separate, more careful mechanism -- see fix_firewall_rule().
    """
    a1 = _load_a1()
    with _load_a6_cache(cache_db, cache_key) as cache:
        scan = _get_baseline_scan(scan_id, cache)

    baseline = scan["discovery"]
    differences = []

    live_interfaces, _ = a1.get_interface_status()
    live_by_name = {i["name"]: i for i in live_interfaces}
    for b_iface in baseline.get("interfaces", []):
        name = b_iface["name"]
        cur = live_by_name.get(name)
        if cur is None:
            differences.append({
                "category": "interface_missing", "target": name,
                "baseline": b_iface, "current": None, "revertible": False,
                "note": f"{name} was in the baseline scan but isn't found on this machine now.",
            })
            continue

        if b_iface.get("admin_enabled") != cur.get("admin_enabled"):
            differences.append({
                "category": "interface_admin_state", "target": name,
                "baseline": b_iface["admin_enabled"], "current": cur["admin_enabled"],
                "revertible": True, "note": None,
            })

        b_mtu, c_mtu = b_iface.get("mtu"), cur.get("mtu")
        if b_mtu is not None and c_mtu is not None and b_mtu != c_mtu:
            differences.append({
                "category": "interface_mtu", "target": name,
                "baseline": b_mtu, "current": c_mtu, "revertible": True, "note": None,
            })

    live_net_config, _ = a1.get_interface_network_config()
    baseline_net_config = baseline.get("interface_network_config", {})
    for name, b_cfg in baseline_net_config.items():
        cur_cfg = live_net_config.get(name)
        if cur_cfg is None:
            continue

        conn = cur_cfg.get("connection_name")
        b_dns = sorted(b_cfg.get("dns_servers") or [])
        c_dns = sorted(cur_cfg.get("dns_servers") or [])
        if b_dns != c_dns:
            revertible = True
            note = None
            if SYSTEM == "Linux" and not conn:
                revertible, note = False, "no nmcli connection name for this interface -- can't revert"
            differences.append({
                "category": "interface_dns", "target": name,
                "baseline": b_cfg.get("dns_servers") or [], "current": cur_cfg.get("dns_servers") or [],
                "revertible": revertible, "note": note, "connection_name": conn,
            })

        b_mode, c_mode = b_cfg.get("ip_assignment_mode"), cur_cfg.get("ip_assignment_mode")
        if b_mode in ("dhcp", "static") and b_mode != c_mode:
            revertible, note = True, None
            if b_mode == "static" and not all([b_cfg.get("ip_address"), b_cfg.get("subnet_mask"), b_cfg.get("gateway")]):
                revertible, note = False, "baseline static config is incomplete -- can't revert to it"
            elif SYSTEM == "Linux" and not conn:
                revertible, note = False, "no nmcli connection name for this interface -- can't revert"
            differences.append({
                "category": "interface_ip_mode", "target": name,
                "baseline": {"mode": b_mode, "ip_address": b_cfg.get("ip_address"),
                             "subnet_mask": b_cfg.get("subnet_mask"), "gateway": b_cfg.get("gateway")},
                "current": {"mode": c_mode, "ip_address": cur_cfg.get("ip_address"),
                            "subnet_mask": cur_cfg.get("subnet_mask"), "gateway": cur_cfg.get("gateway")},
                "revertible": revertible, "note": note, "connection_name": conn,
            })

    live_radio, _ = a1.get_wifi_radio_state()
    baseline_radio = baseline.get("wifi_radio_state") or {}
    b_soft = baseline_radio.get("software")
    c_soft = live_radio.get("software")
    if b_soft in ("on", "off") and b_soft != c_soft:
        differences.append({
            "category": "wifi_radio", "target": "wifi",
            "baseline": b_soft, "current": c_soft, "revertible": True, "note": None,
        })

    return differences, scan


def rollback(scan_id=None, dry_run=False, cache_db=None, cache_key=None):
    """
    Runs diff_against_scan() and reverts every revertible difference
    back to the baseline. dry_run=True computes the diff and reports
    what WOULD be reverted without changing anything. Either way, an
    event describing what was found (and, if not dry_run, done) is
    written into A6 for a record afterward -- the `snapshots` table,
    repurposed from "the before-state" (v0.1.0/v0.2.0's design) to "a
    log of what a rollback actually did", since the before-state is now
    just the baseline scan itself, not something separate to store.

    Returns {"scan_id": int, "differences": [...]} -- each difference
    gets an "action" key added: "reverted", "failed",
    "skipped-not-revertible", or "skipped-dry-run".
    """
    differences, scan = diff_against_scan(scan_id=scan_id, cache_db=cache_db, cache_key=cache_key)

    for diff in differences:
        if not diff["revertible"]:
            diff["action"] = "skipped-not-revertible"
            continue
        if dry_run:
            diff["action"] = "skipped-dry-run"
            continue

        category = diff["category"]
        target = diff["target"]
        baseline = diff["baseline"]
        conn = diff.get("connection_name")

        if category == "interface_admin_state":
            ok, message = _set_interface_admin_state(target, baseline)
        elif category == "interface_mtu":
            ok, message = _set_interface_mtu(target, baseline, connection_name=conn)
        elif category == "interface_dns":
            ok, message = _set_interface_dns(target, baseline or [], connection_name=conn)
        elif category == "interface_ip_mode":
            ok, message = _set_interface_ip_mode(
                target, baseline["mode"], ip=baseline.get("ip_address"),
                subnet_mask=baseline.get("subnet_mask"), gateway=baseline.get("gateway"),
                connection_name=conn,
            )
        elif category == "wifi_radio":
            ok, message = _set_wifi_radio_software_state(baseline == "on")
        else:
            ok, message = False, f"No revert handler for category {category!r}"

        diff["action"] = "reverted" if ok else "failed"
        diff["message"] = message

    with _load_a6_cache(cache_db, cache_key) as cache:
        cache.write_snapshot(
            target="rollback", snapshot_type="rollback_event",
            state={"differences": differences, "dry_run": dry_run},
            reason=f"rollback against scan {scan['id']}" + (" (dry run)" if dry_run else ""),
            source_scan_id=scan["id"],
        )

    return {"scan_id": scan["id"], "differences": differences}


def fix_firewall_rule(finding, cache_db=None, cache_key=None):
    """
    Disables (never deletes) the exact firewall rule an A2 finding
    already identified as the cause, via
    finding["evidence"]["firewall_rule"] -- the same rule object A1's
    check_firewall_rules() found and A2's check_firewall_blocking()
    correlated to a real symptom.

    Deliberately NOT part of the generic diff engine above: there's no
    safe way to "diff" a firewall ruleset field by field the way an MTU
    or DNS value can be compared. Rules are identified by matching,
    which is fragile, and acting on the wrong match could disable an
    unrelated rule or remove a legitimate security control. So this
    only ever acts on a rule A2 has already explicitly named as the
    cause of a specific, already-diagnosed symptom -- never a blind
    scan of "what looks different."

    Scoped to Windows only, per Ammar's stated priority --
    `netsh advfirewall firewall set rule ... new enable=no` disables
    the rule (fully reversible, nothing deleted) rather than removing
    it outright. Linux/macOS need real rule-matching against
    iptables/nft/pfctl output to safely target the same rule for
    disable/delete, which is materially harder and riskier (iptables
    especially has no per-rule "disable", only insert/delete by exact
    spec) -- flagged as not built rather than attempted unsafely.

    Returns (ok, message).
    """
    if SYSTEM != "Windows":
        return False, (
            f"Firewall rule fixes are only implemented for Windows so far -- {SYSTEM} needs "
            "real rule-matching against iptables/nft/pfctl output, materially harder to do "
            "safely (flagged, not built)."
        )

    rule = (finding.get("evidence") or {}).get("firewall_rule")
    if not rule:
        return False, "This finding has no evidence.firewall_rule to act on."

    rule_name = rule.get("name")
    if not rule_name:
        return False, f"Firewall rule has no name to target: {rule}"
    if rule_name.startswith("Windows Firewall profile default"):
        return False, (
            "This is a Windows Firewall *profile policy* (the profile's own default outbound "
            "action), not an individual rule -- there's nothing named to disable. Fixing it "
            "means changing the profile's default action "
            "(netsh advfirewall set currentprofile firewallpolicy ...), a bigger change than "
            "disabling one rule, not implemented here."
        )

    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "set", "rule", f"name={rule_name}", "new", "enable=no"],
            capture_output=True, text=True, errors="ignore", timeout=15,
        )
    except FileNotFoundError as e:
        return False, f"netsh not found: {e}"
    except subprocess.SubprocessError as e:
        return False, f"Command failed: {e}"

    if result.returncode != 0:
        err = (result.stderr or result.stdout).strip()
        return False, (f"netsh advfirewall firewall set rule failed: {err} -- "
                        "this needs an elevated (Administrator) Command Prompt")
    return True, (f'Ran: netsh advfirewall firewall set rule name="{rule_name}" new enable=no '
                   "(disabled, not deleted -- can be re-enabled later)")


def fix_firewall_finding(finding_id, cache_db=None, cache_key=None):
    """CLI-friendly wrapper: looks up finding_id in A6 (most recent
    occurrence) and calls fix_firewall_rule() on it."""
    with _load_a6_cache(cache_db, cache_key) as cache:
        matches = cache.get_findings(finding_id=finding_id)
    if not matches:
        raise A4Error(f"No finding with finding_id {finding_id!r} in A6.")
    return fix_firewall_rule(matches[0], cache_db=cache_db, cache_key=cache_key)


def verify_reachability_and_maybe_rollback(scan_id=None, cache_db=None, cache_key=None):
    """
    Checks internet reachability and gateway packet loss right now (both
    via A1); if the device is actually unreachable, automatically runs
    rollback() against the given baseline scan. This is the
    "auto-rollback if the device becomes unreachable" safeguard
    CLAUDE.md calls non-negotiable, exercised directly since A3 doesn't
    exist yet to trigger it after a real fix.

    internet_reachable (a TCP connect, via A1's check_internet_
    reachability()) is the *deciding* signal, not gateway ping loss --
    see rollback()/diff_against_scan()'s module docstring history (A4
    v0.1.0's changelog) for why: ICMP to the gateway can be blocked
    (100% "loss") even when the connection is completely fine, and
    deciding on ping loss alone would auto-rollback a working
    connection just because ICMP happens to be filtered.

    Returns {"rolled_back": bool, "message": str, "scan_id": int,
    "differences": [...], "gateway": str|None,
    "gateway_loss_percent": float|None, "internet_reachable": bool}.
    """
    a1 = _load_a1()
    gateway = a1.get_default_gateway()
    latency = a1.check_gateway_latency(gateway) if gateway else {"loss_percent": None}
    internet = a1.check_internet_reachability()

    diagnostics = {
        "gateway": gateway,
        "gateway_loss_percent": latency.get("loss_percent"),
        "internet_reachable": internet.get("reachable"),
    }

    if internet.get("reachable"):
        return {
            "rolled_back": False,
            "message": (f"Still reachable (internet OK, gateway ping loss "
                        f"{latency.get('loss_percent')}%) -- no rollback needed."),
            **diagnostics,
        }

    result = rollback(scan_id=scan_id, cache_db=cache_db, cache_key=cache_key)
    reverted = [d for d in result["differences"] if d["action"] == "reverted"]
    failed = [d for d in result["differences"] if d["action"] == "failed"]
    message = f"Internet unreachable -- rolled back against scan {result['scan_id']}: {len(reverted)} reverted"
    if failed:
        message += f", {len(failed)} FAILED"
    if not reverted and not failed:
        message += " (nothing revertible was different)"
    return {
        "rolled_back": len(failed) == 0, "message": message,
        "scan_id": result["scan_id"], "differences": result["differences"],
        **diagnostics,
    }


def _print_differences(differences):
    if not differences:
        print("No differences from the baseline scan.")
        return
    for d in differences:
        action = d.get("action")
        tag = f" [{action}]" if action else ""
        print(f"  {d['category']:<20} {d['target']:<14} baseline={d['baseline']!r} current={d['current']!r}{tag}")
        if d.get("note"):
            print(f"    ! {d['note']}")
        if d.get("message") and action == "failed":
            print(f"    ! {d['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Offline snapshot/rollback manager (Module A4) -- "
                     "diffs this machine's live state against A6's stored discovery data "
                     "and reverts whatever changed"
    )
    parser.add_argument("--diff", action="store_true",
                         help="Show what's different between live state and the baseline scan, without changing anything")
    parser.add_argument("--rollback", action="store_true",
                         help="Diff against the baseline scan and revert every revertible difference")
    parser.add_argument("--dry-run", action="store_true",
                         help="With --rollback, show what WOULD be reverted without changing anything")
    parser.add_argument("--scan-id", type=int, default=None,
                         help="Use this specific A6 scan as the baseline instead of the most recent one")
    parser.add_argument("--verify-and-rollback", action="store_true",
                         help="Check gateway/internet reachability; roll back against the baseline scan automatically if unreachable")
    parser.add_argument("--fix-firewall-finding", metavar="FINDING_ID",
                         help="Disable the exact Windows Firewall rule this A2 finding identified as the cause")
    parser.add_argument("--list-events", action="store_true", help="List past rollback events")
    parser.add_argument("--cache-db", default=None, help="A6 database path (default: A6's own default)")
    parser.add_argument("--cache-key", default=None, help="A6 key file path (default: A6's own default)")
    args = parser.parse_args()

    did_something = False
    try:
        if args.diff:
            did_something = True
            differences, scan = diff_against_scan(
                scan_id=args.scan_id, cache_db=args.cache_db, cache_key=args.cache_key,
            )
            print(f"Diff against scan id {scan['id']} (scanned_at={scan['scanned_at']}):")
            _print_differences(differences)

        if args.rollback:
            did_something = True
            result = rollback(
                scan_id=args.scan_id, dry_run=args.dry_run,
                cache_db=args.cache_db, cache_key=args.cache_key,
            )
            label = "Dry run" if args.dry_run else "Rollback"
            print(f"{label} against scan id {result['scan_id']}:")
            _print_differences(result["differences"])
            if any(d["action"] == "failed" for d in result["differences"]):
                return 1

        if args.verify_and_rollback:
            did_something = True
            result = verify_reachability_and_maybe_rollback(
                scan_id=args.scan_id, cache_db=args.cache_db, cache_key=args.cache_key,
            )
            print(result["message"])
            if result.get("differences"):
                _print_differences(result["differences"])

        if args.fix_firewall_finding:
            did_something = True
            ok, message = fix_firewall_finding(
                args.fix_firewall_finding, cache_db=args.cache_db, cache_key=args.cache_key,
            )
            print(message)
            if not ok:
                return 1

        if args.list_events:
            did_something = True
            with _load_a6_cache(args.cache_db, args.cache_key) as cache:
                events = cache.get_snapshots(snapshot_type="rollback_event", limit=50)
            if not events:
                print("No rollback events yet.")
            for e in events:
                diffs = e["state"].get("differences", [])
                reverted = sum(1 for d in diffs if d.get("action") == "reverted")
                failed = sum(1 for d in diffs if d.get("action") == "failed")
                dry = " (dry run)" if e["state"].get("dry_run") else ""
                print(f"[{e['id']}] {e['created_at']}  scan={e['source_scan_id']}  "
                      f"{len(diffs)} difference(s), {reverted} reverted, {failed} failed{dry}")
    except A4Error as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not did_something:
        parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
