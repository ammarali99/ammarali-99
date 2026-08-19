#!/usr/bin/env python3
"""
a4_snapshot_rollback.py -- Module A4 (Snapshot / Rollback Manager) of the
offline network diagnostic app.

VERSION: 0.1.0
CHANGELOG:
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


def take_snapshot(interface_name, reason=None, cache_db=None, cache_key=None):
    """
    Reads the named interface's current state via A1 and stores it in
    A6 as a snapshot. Returns (snapshot_id, errors) -- errors is
    whatever get_interface_status() reported, even on success (same
    pattern A1/A2 use throughout: report partial trouble, don't hide it).
    """
    a1 = _load_a1()
    interfaces, errors = a1.get_interface_status()
    match = next((i for i in interfaces if i["name"] == interface_name), None)
    if match is None:
        names = ", ".join(i["name"] for i in interfaces) or "(none found)"
        raise A4Error(f"No interface named {interface_name!r} found. Available: {names}")

    with _load_a6_cache(cache_db, cache_key) as cache:
        snapshot_id = cache.write_snapshot(
            target=interface_name, snapshot_type="interface_admin_state",
            state=match, reason=reason,
        )
    return snapshot_id, errors


def restore_snapshot(snapshot_id, cache_db=None, cache_key=None):
    """
    Re-applies a stored snapshot's admin_enabled state to its interface.
    Idempotent: if the interface is already in the snapshotted state,
    does nothing. Verifies the OS actually applied the change before
    reporting success -- doesn't trust the command's exit code alone.

    Returns {"changed": bool, "message": str, "error": bool (only present
    if something went wrong)}.
    """
    with _load_a6_cache(cache_db, cache_key) as cache:
        snapshot = cache.get_snapshot(snapshot_id)
        if snapshot is None:
            raise A4Error(f"No snapshot with id {snapshot_id}.")
        if snapshot["snapshot_type"] != "interface_admin_state":
            raise A4Error(
                f"Snapshot {snapshot_id} is a {snapshot['snapshot_type']!r} snapshot -- "
                "restore_snapshot() only handles interface_admin_state so far."
            )

        interface_name = snapshot["target"]
        wanted_enabled = snapshot["state"]["admin_enabled"]

        a1 = _load_a1()
        interfaces, _ = a1.get_interface_status()
        current = next((i for i in interfaces if i["name"] == interface_name), None)
        if current is None:
            raise A4Error(f"Interface {interface_name!r} not found on this machine anymore.")

        if current["admin_enabled"] == wanted_enabled:
            cache.mark_snapshot_restored(snapshot_id)
            state_word = "enabled" if wanted_enabled else "disabled"
            return {"changed": False, "message": f"{interface_name} is already {state_word} -- nothing to do."}

        ok, message = _set_interface_admin_state(interface_name, wanted_enabled)
        if not ok:
            return {"changed": False, "message": message, "error": True}

        interfaces, _ = a1.get_interface_status()
        current = next((i for i in interfaces if i["name"] == interface_name), None)
        if current is None or current["admin_enabled"] != wanted_enabled:
            return {
                "changed": False,
                "message": f"Ran the restore command but {interface_name}'s state doesn't match "
                           f"the snapshot afterward -- {message}",
                "error": True,
            }

        cache.mark_snapshot_restored(snapshot_id)
        return {"changed": True, "message": message}


def verify_reachability_and_maybe_rollback(snapshot_id, cache_db=None, cache_key=None):
    """
    Checks internet reachability and gateway packet loss right now (both
    via A1); if the device is actually unreachable, automatically
    restores the given snapshot. This is the "auto-rollback if the
    device becomes unreachable" safeguard CLAUDE.md calls non-negotiable,
    exercised directly since A3 doesn't exist yet to trigger it after a
    real fix.

    internet_reachable (a TCP connect, via A1's check_internet_
    reachability()) is the *deciding* signal, not gateway ping loss.
    Caught in this sandbox during testing: ICMP to the gateway can be
    blocked (100% "loss") even when the connection is completely fine --
    confirmed here by internet reachability succeeding at the same time.
    Deciding on ping loss alone would auto-rollback a working connection
    just because ICMP happens to be filtered -- the exact confident-
    false-alarm shape A2's own _connectivity_context() (v0.2.0) already
    exists to avoid for severity, applied here to something that
    actually takes an action, where a false positive is worse. Gateway
    loss is still reported for diagnostics, it just isn't what decides
    whether to roll back.

    Returns {"rolled_back": bool, "message": str, "gateway": str|None,
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

    result = restore_snapshot(snapshot_id, cache_db=cache_db, cache_key=cache_key)
    return {
        "rolled_back": not result.get("error", False),
        "message": f"Internet unreachable -- rolling back. {result['message']}",
        **diagnostics,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Offline snapshot/rollback manager (Module A4) -- "
                     "captures and restores this machine's own interface state"
    )
    parser.add_argument("--snapshot", metavar="INTERFACE",
                         help="Snapshot the named interface's current admin_enabled state")
    parser.add_argument("--reason", default=None, help="Plain-language reason to store with --snapshot")
    parser.add_argument("--restore", metavar="ID", type=int, help="Restore a snapshot by id")
    parser.add_argument("--verify-and-rollback", metavar="ID", type=int,
                         help="Check gateway/internet reachability; restore this snapshot automatically if unreachable")
    parser.add_argument("--list-snapshots", action="store_true", help="List stored snapshots")
    parser.add_argument("--target", default=None, help="Filter --list-snapshots by interface name")
    parser.add_argument("--cache-db", default=None, help="A6 database path (default: A6's own default)")
    parser.add_argument("--cache-key", default=None, help="A6 key file path (default: A6's own default)")
    args = parser.parse_args()

    did_something = False
    try:
        if args.snapshot:
            did_something = True
            snapshot_id, errors = take_snapshot(
                args.snapshot, reason=args.reason, cache_db=args.cache_db, cache_key=args.cache_key,
            )
            for e in errors:
                print(f"  ! {e}", file=sys.stderr)
            print(f"Snapshot {snapshot_id} taken for interface {args.snapshot!r}"
                  + (f" ({args.reason})" if args.reason else ""))

        if args.restore is not None:
            did_something = True
            result = restore_snapshot(args.restore, cache_db=args.cache_db, cache_key=args.cache_key)
            print(result["message"])
            if result.get("error"):
                return 1

        if args.verify_and_rollback is not None:
            did_something = True
            result = verify_reachability_and_maybe_rollback(
                args.verify_and_rollback, cache_db=args.cache_db, cache_key=args.cache_key,
            )
            print(result["message"])

        if args.list_snapshots:
            did_something = True
            with _load_a6_cache(args.cache_db, args.cache_key) as cache:
                snaps = cache.get_snapshots(target=args.target, limit=50)
            if not snaps:
                print("No snapshots match.")
            for s in snaps:
                restored = f"restored {s['restored_at']}" if s["restored_at"] else "not restored"
                print(f"[{s['id']}] {s['created_at']}  {s['snapshot_type']:<24} "
                      f"target={s['target']:<12} {restored}  state={s['state']}")
    except A4Error as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not did_something:
        parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
