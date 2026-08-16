#!/usr/bin/env python3
"""
a2_rule_engine.py -- Module A2 (Rule Engine) of the offline network
diagnostic app.

VERSION: 0.3.0
CHANGELOG:
  0.3.0 - A1 v0.9.0 added dns_resolution (servers_tested, any_working) --
          whether each configured DNS server actually resolves names, not
          just whether one is configured. Added check_dns_not_resolving():
          flags "internet is reachable but no configured DNS server is
          working," which looks like "internet is down" to a non-technical
          user but needs a completely different fix (switch DNS server,
          not touch Wi-Fi/Ethernet). Kept separate from
          check_internet_reachability() rather than folded in, since it's
          a distinct root cause with a distinct guided-fix. Doesn't need
          connectivity-context scaling like v0.2.0's interface/radio
          rules -- its trigger condition (internet reachable, DNS not) is
          already specific enough to always be worth surfacing, same as
          check_dns_missing() and check_pool_usage().
  0.2.0 - Ammar's first real-hardware test (a machine with Wi-Fi switched
          off in software but Ethernet providing a working internet
          connection) surfaced a real design problem, not a bug: A2 was
          reporting "Wi-Fi radio off" as CRITICAL and "Wi-Fi adapter not
          connected" as WARNING even though neither was actually affecting
          the customer -- their internet worked fine. A finding engine
          that cries wolf about component-level state that isn't causing
          any real problem is exactly the kind of thing CLAUDE.md flags as
          the biggest non-technical risk in this market: it erodes trust.

          Added _connectivity_context(data): a coarse read of whether the
          customer's internet is actually working right now (from A1's
          internet reachability check), used only to decide how *alarming*
          an interface/radio-level finding should be -- not whether to
          detect it at all. Wi-Fi radio off and "adapter enabled but not
          connected" (check_wifi_radio_off, check_interfaces) now scale
          their severity by this context: still flagged plainly, but as
          info instead of critical/warning when the internet is
          confirmed working (something else -- probably Ethernet -- is
          carrying the connection), and unchanged (critical/warning) when
          the internet is confirmed down, where they're a plausible cause
          worth surfacing loudly. When the internet check itself was
          skipped (--no-internet), severity stays at the original,
          unconditional default -- we genuinely don't know either way,
          and guessing wrong is worse than not adjusting at all.

          This is deliberately still a deterministic A2 rule, not AI1's
          job: it doesn't correlate across scans or learn anything, it
          just reads one extra field (internet.reachable) already sitting
          in A1's discovery dict before deciding severity. AI1 (deferred)
          will eventually do richer, learned correlation on top of this;
          this is the simple, obvious version that doesn't need to wait
          for it.

          Every other rule (gateway latency, IP pool usage, insecure
          Telnet, DNS missing, UPnP notes, channel congestion) is
          deliberately left unconditional -- these matter regardless of
          whether the internet happens to be up right now (a nearly-full
          DHCP pool or high gateway latency is a real, standing problem
          even on a connection that currently "works"), which is exactly
          Ammar's second point: show real degradation always, don't only
          gate on "is there an outage."
  0.1.0 - First version. Deterministic, known-issue rules that turn A1's
          discovery data into a list of structured Findings.

          Deliberately decoupled from A1's file: this script never imports
          network_discovery_v0.8.0.py directly. It reads the same dict A1's
          --json export already produces (from a file via --input, or from
          stdin, so the two can be piped together). A1 gets a new filename
          every version bump per this project's versioning convention, so
          importing it directly would mean editing A2's import on every A1
          release -- exactly the coupling we don't want. This also matches
          how CLAUDE.md says modules are meant to talk: through data, not
          through calling each other's code.

          The Finding schema below is deliberately built to already be the
          row shape A6 (the encrypted local SQLite cache) will store, once
          A6 exists: a stable finding_id (so the same issue re-detected on
          a later scan is recognizable as the same finding, not a new
          unrelated one -- needed for AI1's later cross-scan correlation),
          a category tag (for AI1 to group findings by subsystem, and for
          A5 to section a report, without re-parsing prose), a plain-
          language summary (for A5), and a fix_classification per finding
          (auto-fix / guided-fix / not-fixable, for A3 -- decided here,
          not left for A3 to figure out). When A4/A6 land, the only change
          needed is where evaluate()'s output goes (json.dump() here
          becomes a6.write_findings() there) -- not the rule logic itself.

Standard-library only. No pip installs, same reason as A1 -- see CLAUDE.md.

Run it against a saved scan:
    python3 network_discovery_v0.9.0.py --json scan.json
    python3 a2_rule_engine_v0.3.0.py --input scan.json

Note: this has to be a two-step, file-based handoff, not a direct pipe.
A1's `--json` with no path still prints its normal plain-language output
to stdout first and *then* appends the JSON -- piping that straight into
A2 hands it a mix of prose and JSON, not valid JSON on its own. Always
give A1 a real path (`--json scan.json`) when the output is meant for A2.

Dump findings as JSON instead of/alongside the plain-language printout:
    python3 a2_rule_engine_v0.3.0.py --input scan.json --json findings.json
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

# Fix classifications a finding can carry. A3 (Fix Engine, not built yet)
# will act on these later; A2's job is only to decide the classification,
# not to act on it.
FIX_AUTO = "auto-fix"
FIX_GUIDED = "guided-fix"
FIX_NONE = "not-fixable"

# Severities, most to least urgent.
SEV_CRITICAL = "critical"
SEV_WARNING = "warning"
SEV_INFO = "info"

_SEVERITY_ORDER = {SEV_CRITICAL: 0, SEV_WARNING: 1, SEV_INFO: 2}


def _finding_id(rule_id, target):
    """
    Stable ID for a (rule, target) pair -- the same issue re-detected on a
    later scan produces the same finding_id, which is what lets A6 dedupe
    findings across scans and AI1 correlate a finding's history over time,
    instead of every scan producing a pile of unrelated-looking findings.
    Not a security hash, just a short stable fingerprint.
    """
    digest = hashlib.sha256(f"{rule_id}:{target}".encode()).hexdigest()
    return digest[:12]


def make_finding(rule_id, category, severity, target, summary, detail,
                  fix_classification, evidence=None):
    """Builds one Finding dict -- see the module docstring for why each
    field exists and who reads it downstream."""
    return {
        "finding_id": _finding_id(rule_id, target),
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "target": target,
        "summary": summary,
        "detail": detail,
        "fix_classification": fix_classification,
        "evidence": evidence or {},
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------
# Rules. Each takes A1's full discovery dict and returns a list of
# Findings (usually 0 or 1, but rules that loop over devices/interfaces
# can return several). Kept as small, independent functions on purpose --
# easy to test one at a time against a real scan, and one rule raising an
# exception doesn't take down the rest (see evaluate()).
# ---------------------------------------------------------------------

def _connectivity_context(data):
    """
    Coarse read of whether the customer's internet is actually working
    right now, used only to decide how alarming an interface/radio-level
    finding should be -- not whether to detect it at all. A1 doesn't tell
    us which interface is actually carrying the connection, so this isn't
    per-interface attribution, just "is the network working overall."

    Returns "ok" (internet reachable), "broken" (confirmed unreachable),
    or "unknown" (the internet check was skipped with --no-internet, so
    we genuinely don't know either way -- treated the same as A1 treats
    an unreadable field: don't guess, use the original unconditional
    severity instead of silently downgrading it).
    """
    reachable = (data.get("internet") or {}).get("reachable")
    if reachable is True:
        return "ok"
    if reachable is False:
        return "broken"
    return "unknown"


def check_wifi_radio_off(data):
    """
    Flags the Wi-Fi radio being off in hardware or software. Severity
    scales with whether the customer's internet is actually working:
    Wi-Fi off while the internet works fine (something else is carrying
    the connection, usually Ethernet) is background state, not a
    problem -- reported as info, not critical. Wi-Fi off while the
    internet is confirmed down is a plausible cause worth surfacing
    loudly -- unchanged critical severity. See _connectivity_context().
    """
    findings = []
    radio = data.get("wifi_radio_state") or {}
    context = _connectivity_context(data)
    kinds = (
        ("software", "in software (Airplane Mode or an Fn-key toggle)"),
        ("hardware", "at the hardware level -- check for a physical Wi-Fi switch"),
    )
    for key, phrase in kinds:
        if radio.get(key) != "off":
            continue
        if context == "ok":
            severity = SEV_INFO
            summary = (f"Wi-Fi is off {phrase}, but this isn't affecting your connection "
                       "right now -- your internet is working (probably via another connection).")
        elif context == "broken":
            severity = SEV_CRITICAL
            summary = f"Wi-Fi is off {phrase} -- likely why there's no internet connection."
        else:
            severity = SEV_CRITICAL
            summary = f"Wi-Fi is off {phrase}."
        findings.append(make_finding(
            rule_id=f"wifi_radio_{key}_off", category="wifi", severity=severity,
            target="wifi_radio", summary=summary,
            detail=f"wifi_radio_state.{key} == 'off', connectivity_context={context}",
            fix_classification=FIX_GUIDED,
            evidence={"wifi_radio_state": radio, "internet": data.get("internet")},
        ))
    return findings


def check_interfaces(data):
    """
    Flags a disabled adapter, or one that's enabled but not connected.
    Same severity-scaling reasoning as check_wifi_radio_off(): background
    state when the internet works fine regardless, a plausible cause when
    it's confirmed down.
    """
    findings = []
    context = _connectivity_context(data)
    for iface in data.get("interfaces") or []:
        name = iface.get("name", "unknown")
        if iface.get("admin_enabled") is False:
            if context == "ok":
                severity = SEV_INFO
                summary = (f"Network adapter '{name}' is disabled, but this isn't affecting "
                           "your connection right now -- your internet is working.")
            elif context == "broken":
                severity = SEV_WARNING
                summary = f"Network adapter '{name}' is disabled -- possibly why there's no internet connection."
            else:
                severity = SEV_WARNING
                summary = f"Network adapter '{name}' is disabled."
            findings.append(make_finding(
                rule_id="interface_disabled", category="interface", severity=severity,
                target=name, summary=summary,
                detail=f"admin_enabled == False, connectivity_context={context}",
                fix_classification=FIX_GUIDED,
                evidence={"interface": iface, "internet": data.get("internet")},
            ))
        elif iface.get("admin_enabled") is True and iface.get("connected") is False:
            if context == "ok":
                severity = SEV_INFO
                summary = (f"Network adapter '{name}' is enabled but not connected, but this "
                           "isn't affecting your connection right now -- your internet is "
                           "working (probably via another connection).")
            elif context == "broken":
                severity = SEV_WARNING
                summary = (f"Network adapter '{name}' is enabled but not connected "
                           "(cable unplugged, or nothing in Wi-Fi range) -- possibly why "
                           "there's no internet connection.")
            else:
                severity = SEV_WARNING
                summary = (f"Network adapter '{name}' is enabled but not connected "
                           "(cable unplugged, or nothing in Wi-Fi range).")
            findings.append(make_finding(
                rule_id="interface_not_connected", category="interface", severity=severity,
                target=name, summary=summary,
                detail=f"admin_enabled == True, connected == False, connectivity_context={context}",
                fix_classification=FIX_GUIDED,
                evidence={"interface": iface, "internet": data.get("internet")},
            ))
        # connected is None means "unknown" (see A1) -- deliberately not
        # flagged, same reasoning A1 uses: a confidently-wrong finding is
        # worse than no finding.
    return findings


def check_gateway_missing(data):
    if not data.get("gateway"):
        return [make_finding(
            rule_id="gateway_not_found", category="lan", severity=SEV_CRITICAL,
            target="network", summary="No default gateway/router was found on this network.",
            detail="gateway is None/empty",
            fix_classification=FIX_GUIDED, evidence={},
        )]
    return []


def check_gateway_latency(data):
    findings = []
    lat = data.get("gateway_latency") or {}
    target = lat.get("target")
    if not target:
        return findings

    loss = lat.get("loss_percent")
    if loss == 100:
        findings.append(make_finding(
            rule_id="gateway_unreachable", category="lan", severity=SEV_CRITICAL,
            target=target,
            summary=f"The router ({target}) did not answer any of {lat.get('sent')} pings.",
            detail=str(lat), fix_classification=FIX_GUIDED, evidence={"gateway_latency": lat},
        ))
    elif loss is not None and loss >= 20:
        findings.append(make_finding(
            rule_id="gateway_packet_loss", category="lan", severity=SEV_WARNING,
            target=target,
            summary=f"Losing {loss}% of pings to the router -- possible interference or cabling issue.",
            detail=str(lat), fix_classification=FIX_GUIDED, evidence={"gateway_latency": lat},
        ))

    avg_ms = lat.get("avg_ms")
    if avg_ms is not None and avg_ms > 100:
        findings.append(make_finding(
            rule_id="gateway_high_latency", category="lan", severity=SEV_INFO,
            target=target,
            summary=f"Average latency to the router is {avg_ms}ms, higher than normal for a local network.",
            detail=str(lat), fix_classification=FIX_NONE, evidence={"gateway_latency": lat},
        ))
    return findings


def check_internet_reachability(data):
    internet = data.get("internet") or {}
    if internet.get("reachable") is None:
        return []  # skipped (--no-internet) -- nothing to evaluate
    if internet.get("reachable") is False:
        lat = data.get("gateway_latency") or {}
        gateway_ok = (lat.get("received") or 0) > 0
        if gateway_ok:
            summary = "No internet connection, but the router itself is reachable -- looks like a WAN/ISP-side issue."
            classification = FIX_GUIDED
        else:
            summary = "No internet connection, and the router itself isn't reachable either -- looks like a local network issue."
            classification = FIX_NONE
        return [make_finding(
            rule_id="internet_unreachable", category="wan", severity=SEV_CRITICAL,
            target="internet", summary=summary, detail=str(internet),
            fix_classification=classification,
            evidence={"internet": internet, "gateway_latency": lat},
        )]
    return []


def check_pool_usage(data):
    pool = data.get("pool_usage") or {}
    pct = pool.get("percent_used")
    if pct is not None and pct >= 90:
        return [make_finding(
            rule_id="ip_pool_near_exhaustion", category="dhcp", severity=SEV_WARNING,
            target=pool.get("subnet", "subnet"),
            summary=f"IP address pool is {pct}% used ({pool.get('used')}/{pool.get('total_usable')}) "
                    "-- may run out of addresses soon.",
            detail=str(pool), fix_classification=FIX_GUIDED, evidence={"pool_usage": pool},
        )]
    return []


def check_upnp_notes(data):
    """Surfaces A1's UPnP sanity-check notes (double-NAT, implausible
    uptime, wrapped traffic counters) as individual info findings. Kept
    deliberately dumb -- it doesn't re-parse the note text to classify
    which specific quirk it is, it just passes each note through. That
    avoids a second, fragile copy of A1's detection logic living here."""
    findings = []
    upnp = data.get("upnp_gateway") or {}
    for i, note in enumerate(upnp.get("notes") or []):
        findings.append(make_finding(
            rule_id="upnp_sanity_note", category="wan", severity=SEV_INFO,
            target="router", summary=note,
            detail=f"flagged by A1's UPnP sanity check (note #{i})",
            fix_classification=FIX_NONE,
            evidence={"upnp_gateway": {k: v for k, v in upnp.items() if k != "notes"}},
        ))
    return findings


def check_insecure_ports(data):
    findings = []
    for device in data.get("devices") or []:
        if 23 in (device.get("open_ports") or []):
            ip = device.get("ip", "unknown")
            findings.append(make_finding(
                rule_id="telnet_open", category="security", severity=SEV_WARNING,
                target=ip,
                summary=f"Telnet (insecure, unencrypted) is open on {ip} ({device.get('vendor') or 'unknown vendor'}).",
                detail=str(device), fix_classification=FIX_GUIDED, evidence={"device": device},
            ))
    return findings


def check_wifi_channel_recommendation(data):
    findings = []
    rec = data.get("channel_recommendation") or {}
    for band, info in rec.items():
        findings.append(make_finding(
            rule_id="wifi_channel_recommendation", category="wifi", severity=SEV_INFO,
            target=band,
            summary=f"For {band}, channel {info.get('recommended_channel')} looks least congested nearby.",
            detail=str(info), fix_classification=FIX_GUIDED,
            evidence={"channel_recommendation": info},
        ))
    return findings


def check_dns_missing(data):
    if not data.get("dns_servers"):
        return [make_finding(
            rule_id="dns_not_configured", category="dhcp", severity=SEV_WARNING,
            target="network", summary="No DNS server is configured on this machine.",
            detail=str(data.get("dns_scan_errors")),
            fix_classification=FIX_GUIDED, evidence={"dns_scan_errors": data.get("dns_scan_errors")},
        )]
    return []


def check_dns_not_resolving(data):
    """
    Flags "internet is reachable but no configured DNS server actually
    resolves names" -- ISP DNS down, DNS hijacked, a captive portal. This
    looks identical to "internet is down" to a non-technical user, but
    needs a completely different fix (switch DNS server, not touch
    Wi-Fi/Ethernet), so it's worth its own finding rather than folding
    into check_internet_reachability(). Only fires when A1's
    dns_resolution check actually ran -- any_working is None (not False)
    when it was skipped (--no-internet) or there were no servers to test.
    """
    internet = data.get("internet") or {}
    dns_res = data.get("dns_resolution") or {}
    if internet.get("reachable") is True and dns_res.get("any_working") is False:
        tested = dns_res.get("servers_tested") or []
        servers = ", ".join(r["server"] for r in tested) or "the configured server(s)"
        return [make_finding(
            rule_id="dns_not_resolving", category="dhcp", severity=SEV_WARNING,
            target="dns",
            summary=(f"Internet is working, but DNS isn't resolving names ({servers}) "
                     "-- try switching to a different DNS server."),
            detail=str(dns_res), fix_classification=FIX_GUIDED,
            evidence={"dns_resolution": dns_res, "internet": internet},
        )]
    return []


# Every rule the engine runs. Add new checks here.
RULES = [
    check_wifi_radio_off,
    check_interfaces,
    check_gateway_missing,
    check_gateway_latency,
    check_internet_reachability,
    check_pool_usage,
    check_upnp_notes,
    check_insecure_ports,
    check_wifi_channel_recommendation,
    check_dns_missing,
    check_dns_not_resolving,
]


def evaluate(data):
    """
    Runs every rule against the discovery data and collects Findings.
    Each rule is wrapped individually so one rule raising an exception
    (e.g. an unexpected field shape from an older A1 export) doesn't stop
    the rest from running -- same defensive pattern A1 uses for its own
    scan steps: report the failure, don't let it take down everything
    else.

    Returns (findings, errors).
    """
    findings = []
    errors = []
    for rule_fn in RULES:
        try:
            findings.extend(rule_fn(data) or [])
        except Exception as e:
            errors.append(f"rule '{rule_fn.__name__}' raised an error: {e}")
    return findings, errors


def _load_input(path):
    if path in (None, "-"):
        raw = sys.stdin.read()
    else:
        with open(path) as f:
            raw = f.read()
    return json.loads(raw)


def _print_findings(findings, errors):
    if errors:
        print("Rule engine errors:")
        for e in errors:
            print(f"  ! {e}")
        print()

    if not findings:
        print("No issues found.")
        return

    for f in sorted(findings, key=lambda x: _SEVERITY_ORDER.get(x["severity"], 3)):
        print(f"[{f['severity'].upper():<8}] {f['category']:<10} {f['target']:<15} {f['summary']}")

    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in _SEVERITY_ORDER}
    print(f"\n{len(findings)} finding(s): "
          f"{counts[SEV_CRITICAL]} critical, {counts[SEV_WARNING]} warning, {counts[SEV_INFO]} info")


def main():
    parser = argparse.ArgumentParser(
        description="Offline rule engine (Module A2) -- reads A1's discovery JSON and flags known issues"
    )
    parser.add_argument("--input", default=None,
                         help="Path to A1's --json output. Omit to read from stdin.")
    parser.add_argument("--json", nargs="?", const="-", default=None,
                         help="Export findings as JSON. Give a path to write to a file, "
                              "or omit the path to print JSON to stdout.")
    args = parser.parse_args()

    try:
        data = _load_input(args.input)
    except FileNotFoundError:
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Input was not valid JSON: {e}", file=sys.stderr)
        return 1

    findings, errors = evaluate(data)
    _print_findings(findings, errors)

    if args.json:
        payload = json.dumps({"findings": findings, "errors": errors}, indent=2)
        if args.json == "-":
            print("\n" + payload)
        else:
            with open(args.json, "w") as f:
                f.write(payload)
            print(f"\nWrote JSON results to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
