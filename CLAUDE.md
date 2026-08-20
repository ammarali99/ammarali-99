# Project Brief: Offline Network Diagnostic & Self-Healing App

Drop this file as `CLAUDE.md` in the root of your project folder. Claude Code
reads it automatically when you start a session there, so you won't need to
re-explain any of this.

## What this product is

A proprietary, plug-and-play network diagnostic and self-healing application
for non-technical customers in Iraq's market: small business owners, local
FTTH resellers/distributors, building/enterprise internal network operators,
and local ISPs.

Core vision: auto-discover devices on a network, build a visual topology
map, detect faults and misconfigurations, and let non-technical users fix
issues themselves via a one-click **Fix** button with full **rollback**
capability.

## The one constraint that drives every architecture decision

**The app must work entirely offline** — it has to be able to diagnose and
fix network issues even when the internet connection is itself the problem.
Any component that would need to call out to the internet during an outage
is architecturally wrong for this product. This ruled out cloud AI inference,
cloud credential storage, and anything else that assumes connectivity.

## Business context (why it's built this way)

- Started as managed IT/MSP services -> pivoted to remote-only -> settled on
  a standalone software product. Each pivot pushed toward "must work without
  us being reachable."
- Iraq's WISP market is shrinking due to FTTH expansion. The durable target
  segments are FTTH resellers, building/enterprise networks, and
  non-technical small business owners — not WISPs.
- Consumer-grade routers (Tenda, TP-Link) need a *guided/assistive* UX, not
  full automation — access and control are more limited than managed gear
  (MikroTik, Cisco).
- Trust is the biggest non-technical risk in this market. Mitigation:
  plain-language output, transparency about what the app is doing, and
  word-of-mouth distribution (local Facebook/WhatsApp business groups,
  hardware shop partnerships) over technical feature depth.
- v1 ships **without** the AI layer, to get to market faster. AI is a
  planned later addition, not a launch blocker.

## Architecture

**Hybrid client-server. Local Core Engine is a modular monolith** (explicitly
not microservices — keep it simple, one process, one deployable). Full
reference diagram: the "Network Diagnostic App — Final Architecture"
flowchart Ammar provided (rendered as Panel 01 in the Core Engine Console
dashboard artifact — keep that panel in sync with this section).

| Module | Name | Role |
|---|---|---|
| A1 | Discovery | Finds devices on the network. Current: ARP, ping, hostname, MAC vendor, port probing, Wi-Fi scan, mDNS. Planned additions: SNMP |
| A2 | Rule Engine | Deterministic known-issue rules. Decides what needs fixing from A1's structured data |
| AI1 | AI Advisory Layer | **Deferred to post-v1.** Runs locally on-device (never cloud — see constraint above). Does anomaly detection on A1's raw data and correlation on A2's findings, outputs confidence-scored *suggestions only* — never executes fixes itself. Versioned, with rollback, same as rules |
| A3 | Fix Engine | Executes fixes, classified per-finding as **auto-fix**, **guided-fix**, or **not-fixable**. Idempotent, with a circuit-breaker that stops itself if a fix loops. Draws credentials from the Credential Manager |
| A4 | Snapshot/Rollback Manager | Pre-fix snapshot before A3 touches anything, config rollback on demand, and **auto-rollback if the device becomes unreachable** after a fix attempt |
| A5 | Report Generator | Plain-language findings for non-technical users, with an **offline template fallback** (canned templates) if nothing richer is available |
| A6 | Encrypted local cache | SQLite, encrypted at rest. **Every module writes here first** — scan data, findings, fix outcomes, snapshots, AI suggestions, reports |
| A7 | Sync Layer | The *only* module allowed to touch the internet, and it's opportunistic/optional — never required for a fix to work. **Push:** logs + fix outcomes (queued if offline). **Pull:** updated rules + retrained AI models, handed off to A2/A3 (and AI1) locally |

**Client UI — Local App Screen:** what the customer actually sees on the
device. Shows the topology map and findings (pulled from A6), and the
Fix/Rollback buttons the customer clicks, which call into A3/A4.

**Data flow:** every module writes to A6 first. Only A7 ever touches the
internet, and only opportunistically. Nothing else is allowed to make an
outbound call — that's not a style preference, it's the core offline-first
constraint.

**One narrow, deliberate exception, now seven instances of it (expanded
from two in A1 v0.15.0):** A1's `check_internet_reachability()` does a
lightweight TCP-connect reachability *test* (not ICMP, no data sent beyond
the handshake) to a couple of well-known IPs on port 443, and
`check_dns_resolution()` sends a raw DNS query directly to each configured
DNS server to check it actually resolves names (catches "internet works
but DNS doesn't," which looks identical to "internet is down" otherwise).
v0.15.0 added five more diagnostic tests of the same kind, each answering
a question that genuinely can't be answered without one outbound probe:
`traceroute_to_internet()` (hop-by-hop path to a known target, LAN-only
`traceroute_to_gateway()` is a separate, non-exception function), 
`check_pmtu_blackhole()` (a DF-set ping-size ladder against a known
target, to catch a silently-dropped-oversized-packet path — logic-
reviewed only so far, no real blackholed path exists to test against),
`check_captive_portal()` (a plain HTTP GET to a well-known
captive-portal-detection endpoint, since "internet looks connected but
nothing works" needs distinguishing from a real outage), `measure_throughput()`
(a real download-speed measurement against a public test endpoint), and
`check_nat_type()` (a hand-built STUN request for public-address discovery
and a coarse cone-vs-symmetric NAT guess). All seven are diagnostic
checks, not dependencies — A1 doesn't need any of them to succeed for
anything else it does. Unlike the original two, which share `--no-internet`,
**each of the five new ones gets its own individual `--no-X` flag**
(`--no-traceroute`, `--no-pmtu`, `--no-captive-portal`, `--no-throughput`,
`--no-nat-type`) — Ammar's explicit choice, for finer per-check control
than one blanket flag would give. This exists because the product's whole
vision is diagnosing network issues *including* when the internet
connection itself is the problem, which needs actual checks of whether the
WAN path, DNS, and now the deeper quality/interception picture are up.
That's a decided, repeatedly-revisited carve-out rather than an unnoticed
rule break. No other module gets this exception.

**Credential Manager** lives locally inside the Core Engine (not the cloud) —
device/router login credentials, encrypted at rest, never leave the device.
Feeds A3 so fixes on managed devices still work during an outage.

**Safeguards that are non-negotiable:** idempotent fixes, circuit-breaker on
fix attempts, auto-rollback if a fixed device goes unreachable, versioned
rules/AI models with rollback, encrypted credentials at rest.

### Cloud Backend (optional, opportunistic — never required for a fix)

Only ever reached through A7. Stack: **FastAPI monolith** in front of
**PostgreSQL**. Pieces:

- **Auth Module** — remote dashboard login only, nothing device-local depends on it
- **Rule Repository** — master copy of the rules A2 runs, versioned with rollback, pulled down by A7
- **AI Model Training** — retrains AI1's models from aggregated, anonymized outcome data pushed up by A7
- **PostgreSQL** — users, scans, findings, fix history
- **Web Dashboard** — remote view of a customer's network for the business (MSP-style oversight), **requires internet**, separate from the on-device Local App Screen

The cloud backend existing at all doesn't weaken the offline constraint: the
Core Engine has to fully diagnose and fix without it, and the backend only
ever sees what A7 chooses to push, on its own schedule.

## Current state

**A1 (Discovery module) is built and being iterated on.** Standard-library-
only Python (no pip installs — deliberate, keeps setup friction at zero for
a non-technical install target later; the one opt-in exception is `--cache`,
which lazily needs A6's `cryptography` dependency only when that flag is
actually used — see below). Current version does:

- Local IP/subnet detection, default gateway detection
- Threaded ping sweep + ARP table cross-reference (catches devices with
  ping/ICMP disabled — a real gap that was fixed, since ARP resolution
  happens below the firewall at Layer 2 regardless of ICMP filtering)
- MAC vendor lookup (small seed OUI table — **known gap**, needs a full
  offline OUI database, not yet done)
- Hostname resolution (offline, via OS resolver — no internet call)
- Common-port probing (22/23/53/80/443/8080) to guess device role
  (router/gateway, web-admin device, SSH host, end-user device)
- Wi-Fi network scanning (SSID/signal/channel/security) via OS-native tools
  — `netsh` on Windows, `nmcli`/`iw`/`iwlist` on Linux (tried in that
  order), `networksetup` on macOS (macOS can only report the *currently
  connected* network — Apple removed the nearby-scan tool `airport` from
  recent macOS versions, this is a platform limitation, not a bug). Every
  scan failure now reports the actual error instead of failing silently
  — v0.1.0 swallowed all exceptions, so a broken scan looked identical to
  "zero networks found" (real bug, caught by Ammar testing on real
  hardware)
- Wi-Fi channel recommendation: `suggest_best_channel()` looks at every
  network the scan found and recommends the least congested 2.4GHz
  channel (only ever from 1/6/11, the non-overlapping set) and 5GHz
  channel
- DNS server detection (offline — reads local config/OS state, doesn't
  query DNS itself)
- IP pool usage (`calculate_pool_usage()`) — used/free/percent across the
  *scanned subnet*. **Known gap:** not the router's actual configured
  DHCP range, which we can't know without asking the router directly
- Network interface status (`get_interface_status()`) — a best-effort
  ethernet/wifi guess per interface (exact on macOS via a hardware-port
  lookup, name-based guess elsewhere — **known gap** on Windows/Linux if
  a machine uses non-obvious interface naming), plus two *separate*
  signals per interface rather than one collapsed up/down bool:
  `admin_enabled` (was the adapter itself turned on/off — this is what
  answers "were the adapters set to on or off in Windows") and
  `connected` (is it actually carrying a link right now). An adapter can
  be enabled but not connected — different situation from disabled
  outright, worth telling apart
- Wi-Fi radio hardware/software kill state (`get_wifi_radio_state()`,
  `netsh`/`rfkill`). **Deliberately does not read Windows' actual
  system-wide Airplane Mode flag** — no reliable stdlib-only way to do
  that (the documented method needs fragile WinRT/PowerShell interop
  unverifiable without a Windows machine; the alternative is an
  undocumented registry key whose on/off value mapping can't be
  confirmed without hardware either, and a confidently-wrong reading is
  worse than not having it). Software-radio-off is the actual mechanism
  Airplane Mode and Fn-key Wi-Fi toggles both use, so this answers the
  practical question without claiming to read the OS flag. Not
  applicable on macOS — no OS-level Airplane Mode exists there
- Static-vs-DHCP detection (`get_ip_assignment_mode()`). **Known gap:**
  Linux detection needs NetworkManager (`nmcli`) managing the interface;
  returns `"unknown"` rather than guessing wrong if it's not present
  (e.g. servers using netplan/systemd-networkd directly)
- DNS/interface-status/DHCP-mode detection all now report the actual
  error instead of failing silently, same fix as the Wi-Fi scan got in
  v0.2.0 — `get_interface_status()` came back completely empty on
  Ammar's real Windows machine with zero explanation (same silent-
  failure shape, caught by testing on real hardware again). Each one
  also flags it when the command *succeeds* but nothing matches the
  expected output format, since that's a second, quieter way to end up
  with an empty result that isn't an exception at all
- Gateway latency check (`check_gateway_latency()`) — several pings
  against just the gateway (not the whole subnet, too slow), reporting
  packet loss % and average round-trip time instead of a single-ping
  alive/dead
- MTU per interface, folded into `get_interface_status()`'s existing
  per-interface data
- Internet reachability check (`check_internet_reachability()`) — see
  "One narrow, deliberate exception" in the Architecture section above.
  TCP-connect test (not ICMP) to a couple of well-known IPs on port 443,
  skippable with `--no-internet`
- DNS resolution check (`check_dns_resolution()`) — A1's *second*
  instance of that same exception (still gated under `--no-internet`,
  not a new flag). Tests whether each *configured* DNS server actually
  resolves names, by sending it a hand-built raw DNS query directly (the
  OS resolver can't be pointed at one specific server) — catches
  "internet is reachable but DNS is broken" (ISP DNS down, hijacked DNS,
  captive portal), which looks identical to "internet is down" to a
  non-technical user but has a completely different fix. Verified with a
  real successful query against a real DNS server; the failure/timeout
  path is **not verified** — this sandbox transparently intercepts
  outbound DNS the same way it intercepts outbound TCP, so a query to a
  non-existent server still returned a fake success
- Router WAN info via UPnP IGD (`query_upnp_gateway()`) — external IP,
  connection status, uptime, and (best-effort, **not yet verified on real
  hardware**) traffic byte counters, via SSDP discovery + SOAP calls to
  the router's WANIPConnection/WANPPPConnection service (and
  WANCommonInterfaceConfig for traffic, if the router implements it).
  **No router credentials needed** — UPnP is unauthenticated on the LAN
  by design, that's what makes this different from the web-UI-scraping
  approach flagged below. Doesn't get the DHCP client list or the
  router's actual configured DHCP range; UPnP doesn't expose that (see
  Flagged decisions). Skippable with `--no-upnp`
- UPnP response sanity-checking (`_upnp_sanity_notes()`) — a successful
  UPnP response isn't necessarily a *trustworthy* one. Caught on Ammar's
  real Tenda router: `external_ip` came back as a private address
  (double-NAT — this router is itself behind another router, common with
  FTTH ONT/modem setups), `uptime_seconds` came back as ~26.6 years
  (impossible — a firmware counter bug), and a traffic byte counter came
  back as exactly 2^32-1 (an overflowed/wrapped 32-bit counter, or a
  "not really supported" sentinel). All three are now flagged in plain
  language instead of printed as if they were real data
- Local firewall rule scan (`check_firewall_rules()`) — reads the actual
  firewall ruleset (`netsh advfirewall` on Windows, `iptables`/`nft` on
  Linux, `pfctl` on macOS) for any rule that blocks one of a small,
  named set of connectivity-relevant ports (v0.11.0): DNS (53), HTTP
  (80), HTTPS (443, including UDP for HTTP/3-QUIC), DHCP server/client
  (67/68), plus ICMP. Deliberately not "every port" — each one maps to a
  symptom A1/A2 can already detect and correlate against (see A2's
  `check_firewall_blocking()` below); a wider net would mean flagging a
  customer's legitimate custom rule as if it explained a problem it has
  nothing to do with. Pure data gathering, no verdict attached — A2 is
  what decides a matching rule actually explains a connectivity failure
  (same A1-gathers/A2-decides split as everything else in the
  architecture). Only returns that small subset of rules, not a full
  ruleset dump. **Known limitation:** reading the full ruleset needs
  root on Linux/macOS (Windows' `netsh advfirewall` doesn't need
  elevation) — without it, the errors list says so instead of silently
  reporting "no blocking rules found." Verified against a real ruleset
  in this sandbox: caught a real parsing gap along the way — `iptables
  -L -n` printed protocol *numbers* (17, 1) instead of names (udp,
  icmp) here despite a populated `/etc/protocols`, which the parser now
  maps back to names instead of silently missing the rule. Re-verified
  after the port-set widening (rules for udp/53, tcp/80, tcp/443,
  udp/67, and icmp all correctly caught; an unrelated tcp/8080 rule
  still correctly ignored). **v0.12.0** added a sixth category, "ALL"
  (blocks everything): a rule with no protocol/port restriction, a
  chain/table default-deny policy (`Chain OUTPUT (policy DROP)` on
  Linux — a genuinely different mechanism from an individual rule,
  previously invisible for a second reason: the chain-header parser
  only ever captured the chain name, never the policy verdict next to
  it), or on Windows a rule with `Protocol=Any`/`RemotePort=Any`
  (Ammar's specific example) plus a new check of the Windows Firewall
  profile's own default outbound action, which is a policy setting, not
  a rule, so no amount of per-rule parsing could ever have caught it.
  "ALL" is the one deliberate exception to "curated by specific
  service" — a blanket block isn't a legitimate unrelated custom rule,
  it's evidence against every connectivity symptom at once. Verified
  against a real bare `-j DROP` rule and a real chain default policy of
  DROP in this sandbox; also caught a second real parsing gap along the
  way — this container's iptables printed protocol `0` (not the
  expected string `all`) for an unrestricted rule, now mapped
  alongside the earlier 17/1 → udp/icmp fix. Windows/macOS parsing is
  **not yet verified on real hardware**. Skippable with `--no-firewall`
- JSON export (`--json`), still fully supported
- `--cache` (v0.13.0) writes the scan straight into A6 via `write_scan()`,
  alongside or instead of `--json`. Dynamically loads whichever
  `a6_encrypted_cache_v*.py` is present rather than hardcoding a version
  (`--cache-db` / `--cache-key` to override A6's default paths)
- **Real bug (v0.13.1 fix):** found while chasing why `--cache` "kept not
  working" for Ammar. `a6 = _import_a6()` sat *outside* the try/except
  meant to catch A6-related failures. `_import_a6()` can itself raise --
  most likely `ImportError`, since A6's own module-level code does
  `from cryptography.fernet import Fernet` and re-raises if that package
  isn't installed/working. With the call outside the try, that exception
  was completely unhandled: instead of the clean `--cache: ... -- scan
  not cached` message, A1 crashed with a raw Python traceback -- even
  though the scan itself had already finished successfully. On Windows
  this likely showed as the console flashing a wall of text and closing
  before it could be read. Fixed by moving `_import_a6()` inside the
  same try block. Reproduced the original crash first (in this sandbox,
  by shadowing the real `cryptography` package with a stub module that
  raises `ImportError`, then running `--cache` for real as a subprocess)
  to confirm it crashed before the fix and prints the clean message
  after.
- `--no-ports` / `--no-wifi` / `--no-internet` / `--no-upnp` /
  `--no-firewall` flags to skip slower or internet/LAN-broadcast-touching
  steps
- **New in v0.14.0:** `get_interface_network_config()` -- per-interface
  DNS servers, IP assignment mode, and (when static) the actual static
  IP/subnet/gateway, keyed by the same interface names
  `get_interface_status()` already uses. Built for A4's expanded
  diff-and-rollback work (Ammar's request to cover DNS and static/DHCP
  mode, not just interface enable/disable): the existing
  `get_dns_servers()` reads DNS as one flat list across the whole
  machine, and `get_ip_assignment_mode()` only returns a mode label for
  one IP -- neither says *which* interface's DNS to restore, or what
  static values to restore it to. Both existing functions are
  unchanged and still used exactly as before; this is additive. One
  Windows pass over `ipconfig /all` captures DNS/DHCP-or-static/IP/
  mask/gateway together per adapter block, instead of three separate
  parses. Linux is per-device via `nmcli device show` plus the
  connection's `ipv4.method`, with the same NetworkManager-only
  limitation `get_ip_assignment_mode()` already has -- an interface
  nmcli doesn't manage just doesn't appear, rather than guessing wrong.
  Also captures `connection_name` (the nmcli connection id on Linux,
  the networksetup service name on macOS) since A4's write side needs
  to address the *connection*, not just the device. macOS via
  `networksetup -getinfo`/`-getdnsservers` -- not yet verified on real
  macOS hardware, and `-getdnsservers` specifically only shows
  manually-set DNS overrides, not DHCP-provided ones (a real limitation
  of that command, not a parsing gap). **Verification, stated
  honestly:** this sandbox's NetworkManager wouldn't cooperate with a
  live managed test interface (a container-specific `managed=false`
  default), so all three platform parsers were verified by feeding
  them realistic captured command output and checking the parsed
  result field-by-field, rather than against a live managed interface
  -- weaker than this codebase's usual real-hardware bar, flagged as
  such rather than overstated.
- **New in v0.15.0: a large batch of ~21 new discovery functions**, prompted
  by Ammar asking what other network details would help diagnose precisely,
  and then asking for all of them built. Grouped by category:
    - **Layer 2/topology:** `get_interface_link_info()` (speed/duplex per
      interface — Windows duplex deliberately declined, no reliable
      non-PowerShell source, same call as the Airplane Mode decision below),
      `get_dhcp_lease_info()` (which server issued the lease, and its
      obtained/expires timestamps on Windows/macOS or just a lease
      *duration* on Linux — `nmcli` genuinely doesn't expose absolute
      timestamps, not a parsing shortfall), `detect_rogue_dhcp_servers()`
      (broadcasts a hand-built DHCPDISCOVER and counts distinct DHCPOFFER
      responders — needs root/admin to bind UDP port 68, flagged the same
      way `check_firewall_rules()` flags its own root requirement),
      `detect_duplicate_ip()` (best-effort only — compares two ARP-table
      reads taken a few seconds apart, catches a MAC change in that window,
      nothing more, stated as such rather than as a guarantee), the ARP
      table itself now surfaced in the output (it was already being
      computed internally, just never returned), `discover_upnp_devices()`
      (generalizes the existing gateway-only SSDP discovery to every LAN
      device that answers), and `discover_mdns_devices()` (new — resolves
      the "add mDNS" item that had been on the horizon; needed a real
      DNS-wire-format answer-record walker, not just the header parse the
      existing raw-DNS-query code already had).
    - **Routing:** `get_routing_table()`, `traceroute_to_gateway()`
      (LAN-only, not an exception) and `traceroute_to_internet()` (one of
      the five new exceptions, see the Architecture section above) — both
      shell out to the OS `tracert`/`traceroute` binary and regex hop
      lines, same no-raw-socket house style as `check_gateway_latency()`.
    - **DNS (deeper):** `read_hosts_file()` (runs on *every* scan,
      unconditionally — A4's new hosts-file fix needs a baseline),
      `dump_dns_cache()` (a real tool on Windows, aggregate stats only on
      Linux, an honestly-stated gap on macOS — no clean non-root option
      exists there), `get_dns_suffix_search_list()`. Per-DNS-server
      latency needed no new function — `check_dns_resolution()` already
      returns it.
    - **Proxy/VPN/interception:** `get_system_proxy_config()` (runs every
      scan, unconditionally, for the same A4-baseline reason as the hosts
      file — Windows uses the stdlib `winreg` module directly rather than
      shelling out to `reg query`, a deliberate one-off departure from this
      file's usual style since `winreg` exists exactly for this),
      `detect_vpn_adapters()` (a classification pass over data
      `get_interface_status()` already returns, not a new OS query), and
      two of the five new exceptions: `check_pmtu_blackhole()` and
      `check_captive_portal()` (see the Architecture section above for
      both).
    - **Wi-Fi (deeper):** `get_wifi_connection_details()` (link
      rate/signal/noise/802.11 standard for the *currently associated*
      network only — deliberately separate from `scan_wifi_networks()`,
      which describes nearby SSIDs with no live link-quality data
      available for them), WPS-enabled detection folded into
      `scan_wifi_networks()`'s existing per-SSID dicts but **Linux-only**
      (Windows/macOS scan tools don't expose it cleanly, stated as a gap
      rather than guessed at), and `get_wifi_power_management()`
      (**Linux-only** by explicit decision — Windows has no clean
      non-PowerShell source, same reasoning as the declined Windows
      Airplane Mode read below; macOS ties this to system-wide Energy
      Saver with no discrete per-adapter toggle. Runs unconditionally on
      Linux every scan, for A4's new Linux-only fix).
    - **IPv6:** `get_ipv6_status()` — per-interface addresses, default
      gateway, DNS servers, plus a pure-logic dual-stack/IPv4-only/IPv6-only
      classification.
    - **Time:** `check_clock_drift()` — deliberately reads the OS's own
      already-computed sync status rather than independently querying a
      live NTP server, since that would have been an unapproved *sixth*
      internet exception beyond the five actually approved.
    - **Quality:** jitter added directly to the existing
      `check_gateway_latency()` return (mean absolute difference between
      consecutive RTT samples, zero new subprocess calls), plus the last
      two of the five new exceptions: `measure_throughput()` (a real 2MB
      download against a public Cloudflare speed-test endpoint) and
      `check_nat_type()` (a hand-built RFC 5389 STUN request against
      Google's public STUN server, parsing the XOR-MAPPED-ADDRESS to learn
      this machine's own public IP:port — full RFC 3489 NAT-type
      classification wasn't attempted, a second-server comparison gives
      only a coarse cone-vs-symmetric guess, stated as such).
    - **Host-level:** `get_driver_info()` (Windows via the now-deprecated
      `wmic`, flagged as such; Linux via `ethtool -i`, the cleanest of the
      three; macOS best-effort via `system_profiler`).
  Seven new `--no-X` CLI flags total (`--no-dhcp-probe`, `--no-mdns`,
  `--no-traceroute`, `--no-pmtu`, `--no-captive-portal`, `--no-throughput`,
  `--no-nat-type`); `read_hosts_file()`, `get_system_proxy_config()`, and
  (on Linux) `get_wifi_power_management()` are **not** gated by any flag,
  since A4 needs them captured every scan regardless.
  **Real bug caught and fixed during testing:** `discover_mdns_devices()`
  initially reported this machine's own outgoing multicast query as if it
  were a responding device — IP multicast loopback delivering the query
  back into the same socket. Fixed with `IP_MULTICAST_LOOP=0`, reverified
  it correctly reports zero devices when nothing actually responds.
  **Verified, stated honestly:** the full `run_discovery()` pipeline ran
  end-to-end in this sandbox with all new fields included; real
  `/sys`/`ethtool` link-info reads, real routing table/traceroute/hosts-file/
  resolv.conf/proxy-env-var/IPv6 reads, a real (root) DHCP broadcast probe,
  real mDNS/SSDP socket round-trips, a real 2MB throughput download, and a
  real captive-portal check (which also confirmed this sandbox's outbound
  proxy doesn't intercept plain HTTP, so the true-negative path is
  trustworthy here) all ran for real. STUN/NAT-type packet construction and
  parsing were verified by hand-building and round-tripping the packets
  locally, but the live UDP round-trip to Google's public STUN server
  timed out in this sandbox — outbound UDP isn't cooperative here. Every
  Windows/macOS-specific path (and the Linux paths needing a live
  NetworkManager connection) is command-construction-verified only, same
  standard as every previous round — no real Windows/macOS machine
  available in this environment.

**A2 (Rule Engine) is started (v0.9.0).** Standard-library-only Python,
in its own file (`a2_rule_engine_v0.9.0.py`), deliberately never importing
A1's file directly -- it reads the same dict A1's `--json` export produces
(file-based handoff: A1 writes `--json scan.json`, A2 reads `--input
scan.json`), so A1 can keep bumping its own version/filename with zero
changes needed in A2. Current version does:

- A Finding schema (`finding_id`, `rule_id`, `category`, `severity`,
  `target`, `summary`, `detail`, `fix_classification`, `evidence`,
  `detected_at`) designed to already be the row shape A6 will store, once
  A6 exists -- `finding_id` is a stable hash of (rule, target) so the same
  issue re-detected on a later scan is recognizable as the same finding
  (needed for AI1's later cross-scan correlation), `category` groups
  findings by subsystem (wifi/wan/lan/interface/dhcp/security) for AI1 and
  for A5's report sectioning, and `fix_classification`
  (auto-fix/guided-fix/not-fixable) is decided here for A3 to act on later
- `evaluate()`: runs every registered rule against A1's discovery dict,
  wrapping each one individually so one rule raising an exception doesn't
  take down the rest (same defensive pattern as A1's own scan steps)
- Rule set (27 rules): Wi-Fi radio off (hardware/software), adapter
  disabled, adapter enabled-but-not-connected, no gateway found, gateway
  unreachable/high packet loss/high latency, internet unreachable (with a
  WAN-vs-LAN distinction based on whether the gateway itself is reachable),
  IP pool near exhaustion, UPnP sanity notes surfaced as findings (passed
  through from A1's `_upnp_sanity_notes()` rather than re-parsed here, to
  avoid a second, fragile copy of that detection logic), insecure Telnet
  port open, Wi-Fi channel congestion recommendation, DNS not configured,
  a specific interface set to static with no DNS configured (v0.8.0, see
  below), DNS configured but not resolving (v0.3.0, see below), a local
  firewall rule blocking DNS/ICMP (v0.4.0, see below), plus 14 more rules
  added in v0.9.0 (see below)
- CLI: prints findings sorted by severity with a summary count, `--json`
  export in the same shape A6 will eventually store directly
- `--cache` (v0.7.0): skips `--input` entirely, reads the most recent scan
  straight out of A6 (or a specific one via `--cache-scan-id`), evaluates
  it unchanged, and writes findings back into A6 via `write_findings()`.
  Same dynamic `_import_a6()` loader A1 v0.13.0 uses, for the same reason
- **New rule (v0.8.0): a specific interface set to static with no DNS
  configured.** Ammar's question after A1 v0.14.0 added
  `get_interface_network_config()`: does A2 need updating every time A1
  gains a new discovery function, since A2's whole job is to evaluate
  A1's output? Checked, and the answer here was yes -- nothing in the
  existing rule set read `interface_network_config` at all.
  `check_dns_missing()` only ever read the old flat, whole-machine
  `dns_servers` field, which can say "DNS isn't configured anywhere" but
  never "DNS isn't configured on *this* interface" -- and A4 v0.3.0's
  `_set_interface_dns()` fix acts per-interface, so it needs to know
  which one. `check_interface_dns_missing()` fills that gap, but
  deliberately only for interfaces in **static** IP mode: DHCP-mode
  interfaces are skipped on purpose, since on macOS
  `networksetup -getdnsservers` only shows manually-set DNS overrides,
  never DHCP-provided ones (an already-flagged A1 limitation) -- an
  empty reading there means the tool can't see the DNS servers, not that
  they're missing. Static-mode interfaces have no such ambiguity on any
  platform. Also considered a matching rule for `interfaces[].mtu`
  (also never read by any rule) and deliberately didn't add one -- no
  safe heuristic exists for "wrong" MTU (VPNs and jumbo-frame setups
  legitimately use non-1500 values), and guessing wrong risks exactly
  the kind of confidently-wrong finding this codebase keeps catching and
  fixing elsewhere. Tested with synthetic data covering static+missing
  (fires), DHCP+missing (correctly doesn't fire), and down-interface
  (correctly doesn't fire); re-ran against this session's real A1 output
  as a regression check with no change in the existing 12 rules' output
  -- this sandbox's `interface_network_config` comes back empty (the
  same NetworkManager-non-cooperation limitation A1 v0.14.0 already
  flagged), so the new rule itself is only verified against synthetic
  data so far, not a live scan that actually triggers it.
- **Real bug (v0.7.2 fix):** the same class of bug as A1 v0.13.1, found in
  the same debugging session. `a6 = _import_a6()` and `cache.get_scans()`
  both sat outside real exception handling -- either one could raise
  (`ImportError` if `cryptography` isn't installed; `CacheError` on a
  wrong key or tampered database) and crash A2 with a raw traceback
  instead of a clean `--cache: ...` message. Rewrote the `--cache` branch
  so `_import_a6()`, `A6Cache()`, and `get_scans()` are all inside one
  try -- `cache` is deliberately left open on the success path so
  `write_findings()` can still use it further down, and only gets closed
  on each early-failure return. Reproduced the original crash first
  (shadowing `cryptography` with a stub module that raises `ImportError`,
  then running `--cache` as a real subprocess), confirmed the crash
  before the fix and the clean message after.
- **Severity now scales with actual connectivity impact (v0.2.0), not just
  raw component state.** Ammar's first real-hardware test (Wi-Fi switched
  off in software, but Ethernet was providing a working internet
  connection) surfaced a real trust problem: A2 was reporting "Wi-Fi radio
  off" as CRITICAL even though it wasn't affecting him at all. A confident
  false alarm on working hardware is exactly the kind of thing that erodes
  the non-technical trust CLAUDE.md flags as the biggest risk in this
  market. `_connectivity_context()` reads A1's internet-reachability
  result and scales `check_wifi_radio_off()` / `check_interfaces()`
  accordingly: info-level (not critical/warning) when the internet is
  confirmed working -- something else is carrying the connection --
  unchanged critical/warning when the internet is confirmed down, where
  they're a plausible cause worth surfacing loudly, and unchanged
  critical/warning (the safe default) when the internet check itself was
  skipped (`--no-internet`) and there's genuinely no way to know. This is
  still a deterministic A2 rule, not AI1's job -- it doesn't correlate
  across scans or learn anything, it just reads one more field already in
  A1's discovery dict before deciding severity. Every other rule (gateway
  latency, IP pool usage, insecure Telnet, DNS missing, UPnP notes,
  channel congestion) is deliberately left unconditional, since those
  matter regardless of whether the internet happens to be up right now --
  Ammar's second point from the same test.
- **New rule (v0.3.0): DNS configured but not resolving.** A1 v0.9.0 added
  `dns_resolution` (whether each configured DNS server actually resolves
  names, not just whether one is configured -- see A1's current-state
  entry below). `check_dns_not_resolving()` flags "internet is reachable
  but no configured DNS server is working" -- looks like "internet is
  down" to a non-technical user, but needs a completely different fix
  (switch DNS server, not touch Wi-Fi/Ethernet), so it's a separate
  finding from `check_internet_reachability()`, not folded into it. This
  one doesn't need v0.2.0's connectivity-context scaling -- its own
  trigger condition (internet reachable, DNS specifically not) is already
  precise enough to always be worth surfacing, the same reasoning as
  `check_pool_usage()` and `check_dns_missing()`.
- **New rule (v0.4.0): a local firewall rule blocking DNS or ICMP.** A1
  v0.10.0 added `check_firewall_rules()` -- the actual local firewall
  ruleset (`netsh advfirewall` / `iptables`+`nft` / `pfctl`), filtered
  down to rules that block DNS (port 53) or ICMP. That's pure data
  gathering with no verdict attached, same as everything else A1 does --
  `check_firewall_blocking()` is what correlates a matching rule against
  an actual DNS/internet failure (from the same discovery dict) and
  produces a specific "this rule is likely why" finding, instead of
  leaving the customer with just a bare "DNS isn't resolving." Severity
  matches whatever it's explaining (critical if the internet itself is
  unreachable, warning if only DNS is) rather than a new scale of its
  own. This is the same A1-gathers/A2-decides split the architecture
  table already draws for every module -- A1 has no opinion about
  whether a rule matters, A2 does. Tested against a real iptables
  ruleset in this sandbox (see A1's entry above for the real parsing
  gap that testing caught) plus synthetic fixtures for all three
  correlation cases (DNS-broken, internet-broken, rule-present-but-
  nothing-actually-wrong -- confirmed the last one correctly produces no
  finding).
- **Widened rule (v0.5.0): per-service firewall correlation, not one
  blanket gate.** A1 v0.11.0 widened `check_firewall_rules()` to a small
  named set of connectivity-relevant ports (DNS, HTTP, HTTPS, DHCP
  client/server) alongside ICMP -- see A1's entry above. The old v0.4.0
  blanket "DNS broken OR internet broken" gate was actually imprecise
  even for the original DNS/ICMP-only set: it would have credited an
  ICMP-blocking rule for "the internet is unreachable" even though
  `check_internet_reachability()` never uses ICMP at all (TCP connect
  only). Rewritten so each service correlates against the specific
  symptom it would actually cause: DNS against
  `check_dns_not_resolving()`'s own trigger, HTTPS against
  `check_internet_reachability()`'s (a direct match -- that check's own
  test is a TCP connect to port 443), ICMP against
  `check_gateway_latency()`'s 100%-loss trigger (ICMP is what ping
  uses), DHCP against `check_gateway_missing()`'s (no DHCP means no
  IP/gateway/DNS server in the first place). HTTP (port 80) is gathered
  by A1 but deliberately never correlated -- no existing A1 check tests
  port 80, so there's no symptom to attach it to yet; a stated gap, not
  a guessed-at one. Tested against all four now-correlated services with
  both matching and deliberately-mismatched connectivity contexts (e.g.
  an ICMP-blocking rule present while the gateway is actually fine --
  confirmed no finding).
- **New branch (v0.6.0): a firewall rule that blocks everything.** A1
  v0.12.0 added an "ALL" service to `check_firewall_rules()` for a rule
  with no protocol/port restriction, a chain/profile default-deny, or
  (Ammar's specific example) a Windows rule with
  `Protocol=Any`/`RemotePort=Any` -- see A1's entry above.
  `check_firewall_blocking()` fires this branch against *any* of the
  four existing broken conditions, not just one specific symptom like
  the other services, since a blanket block is consistent with all of
  them at once rather than pointing at one narrowly; whichever symptom
  is actually present is what the finding names. Tested against a real
  bare `-j DROP` rule and a real chain default policy of DROP in this
  sandbox (both produce a critical finding); confirmed the five
  per-service detections from v0.5.0 are unaffected.
- Tested end-to-end against this file's own A1 output, synthetic data
  covering every rule, and Ammar's first real hardware scan (which is what
  surfaced the v0.2.0 fix) -- next up: run the current version against
  real hardware again to confirm the v0.2.0 through v0.6.0 changes, then
  expand the rule set further
- **New in v0.9.0: 14 more rules**, matching A1 v0.15.0's big discovery
  expansion one-for-one against the same "does this new field have a safe,
  non-guessing trigger condition" test v0.8.0 already established (the
  MTU-rule rejection is the precedent): `check_rogue_dhcp`,
  `check_duplicate_ip`, `check_multiple_default_routes`,
  `check_hosts_file_hijack` (deliberately narrow -- only fires if one of
  A1's *own* known-good hostnames, like its DNS test host or the
  captive-portal/throughput endpoints, is redirected to a real non-loopback
  address in the hosts file; declines the broader "any suspicious entry"
  idea since there's no safe way to tell a legitimate ad-block hosts file
  apart from real hijacking without an internet-connected reputation
  service), `check_proxy_configured` and `check_vpn_active` (both scaled
  by `_connectivity_context()`, same pattern as the original v0.2.0 fix),
  `check_pmtu_blackhole_finding` (routes to A4's *existing*
  `_set_interface_mtu()` fix -- no new A4 category needed), 
  `check_captive_portal_finding`, `check_wifi_weak_signal` (an SNR
  threshold, not raw RSSI), `check_wifi_power_saving_enabled`
  (deliberately correlated against an actual gateway-latency/jitter
  symptom before firing -- power-save being on by itself is normal, not a
  problem), `check_wps_enabled` (the router's own setting, no credentials
  to change it -- same territory as the flagged web-UI-scraping decision),
  `check_clock_not_synced`, `check_high_jitter`, and
  `check_throughput_critically_low`. Several new A1 fields were
  deliberately left evidence-only with no new rule -- link speed/duplex,
  DHCP lease time, ARP/UPnP/mDNS device inventories, both traceroutes, DNS
  cache/suffix-list contents, 802.11 standard by itself, IPv6/dual-stack
  status, NAT type, and driver version -- same "no safe non-guessing
  threshold" discipline as the MTU decision.
- **`check_clock_not_synced` and the upgraded `check_dns_not_resolving`
  (see next bullet) are the first two uses of `FIX_AUTO` anywhere in this
  codebase.** Every rule before v0.9.0 used `FIX_GUIDED` or `FIX_NONE` --
  `FIX_AUTO` existed in the schema from day one but had never actually been
  assigned. Both are judged safe/reversible with no real user tradeoff
  (an NTP resync, a DNS cache flush), unlike every `FIX_GUIDED` rule, which
  touches interface/firewall/Wi-Fi config with a real tradeoff attached.
  A3 (Fix Engine) doesn't exist yet, so today this only labels data --
  nothing auto-executes until A3 is built to read `fix_classification` and
  act on it.
- **`check_dns_not_resolving()` upgraded from `FIX_GUIDED` to `FIX_AUTO`**
  (v0.9.0) -- a deliberate change to existing behavior, not a new rule,
  now that A4 v0.4.0 has a real, safe `flush_dns_cache()` one-shot action
  to back it. Trigger logic unchanged.
- **Regression-tested against a real A1 v0.15.0 scan from this sandbox:**
  all 13 pre-existing rules produced byte-identical findings. Of the 14
  new rules, `check_proxy_configured` genuinely fired against real data
  (this sandbox's own outbound agent-proxy env var, correctly detected via
  the Linux code path, severity `info` since the internet was reachable at
  the time) -- the other 13 correctly did not fire, verified against this
  sandbox's actual field values (single default route, no rogue DHCP/
  duplicate IPs/VPN interfaces, no captive portal, `clock_drift.synchronized`
  was `None` not `False` so it correctly didn't fire, etc.). Synthetic
  fixtures cover every new rule's firing and non-firing paths.

**A6 (Encrypted local cache) is started (v0.3.0).** Own file
(`a6_encrypted_cache_v0.3.0.py`). Handles what actually exists so far --
A1 scans, A2 findings, and (new in v0.2.0) A4 snapshots -- rather than
pre-building tables for fix_outcomes/AI suggestions/reports before
A3/AI1/A5 exist to write them. Current version does:

- SQLite for storage, `cryptography` (Fernet/AES-128-CBC+HMAC) for
  encryption at rest -- Python's standard library has no safe symmetric
  cipher, and hand-rolling one for a database meant to eventually hold
  router credentials was the wrong place to save a dependency. This is a
  **deliberate, flagged exception** to the standard-library-only
  convention, approved by Ammar: `cryptography` is a build-time
  dependency that ships bundled inside the final installer, so it costs
  nothing in install friction for the non-technical end user, only in
  dev setup now.
- **Not every column is encrypted.** `finding_id` / `rule_id` /
  `category` / `severity` / `fix_classification` / `detected_at` /
  `source_version` / `scanned_at` stay in the clear, since A3 and AI1
  will need to filter and join on exactly those later (e.g. "every
  auto-fixable finding," or trend a `finding_id` across scans) without
  decrypting every row to check a severity level, and none of them
  reveal anything about the customer's network. Everything that could --
  the full A1 discovery dict, and a finding's `target`/`summary`/
  `detail`/`evidence` -- goes into one encrypted BLOB column per row.
  Verified: imported a real A1 scan + A2 finding (a missing-gateway
  critical) from this session's sandbox network, round-tripped both back
  out correctly, then grepped the raw `.db` file bytes for the scan's
  real local IP and confirmed it does not appear in plaintext.
- **Key management is a known, flagged gap for v1.** The Fernet key is a
  random 32 bytes generated on first run, stored in a sibling file next
  to the database with owner-only permissions (`chmod 600`) on
  Linux/macOS. That protects the data if the `.db` file alone leaks or
  gets copied elsewhere, but **not** against someone with full
  filesystem access to this machine, since the key sits right next to
  what it unlocks -- and `chmod 600` is a no-op on Windows (no POSIX
  permission bits there). Real protection needs OS-keychain integration
  (DPAPI / Keychain / Secret Service, likely via the `keyring` package)
  -- deferred rather than bolted on silently, since the Credential
  Manager will need the same answer and it deserves its own decision.
- `write_scan()` / `write_findings()` / `get_scans()` / `get_findings()`
  (filterable by scan/severity/category/fix_classification) as the
  Python API.
- **New in v0.2.0, for A4:** `write_snapshot()` / `get_snapshots()`
  (filterable by target/snapshot_type) / `get_snapshot(id)` (direct
  lookup by id -- A2 v0.7.0 had to work around A6 not having this for
  scans; A4's restore/verify functions need to fetch one exact snapshot,
  so this version adds it properly) / `mark_snapshot_restored()`. Same
  plaintext/encrypted split as findings: a snapshot's `target` (e.g. an
  interface name) and `snapshot_type` stay in the clear for filtering;
  the actual captured state and the human-readable `reason` a snapshot
  was taken go into one encrypted BLOB. `--selftest` now also covers the
  snapshots table with its own canary check.
- **New in v0.3.0, driven by A4's redesign:** `get_scan(id)` -- a direct
  lookup for the scans table, same shape as v0.2.0's `get_snapshot(id)`.
  Closes a gap flagged twice before (A2 v0.7.0's changelog, A4 v0.1.0's
  own code) but never fixed since nothing needed it until A4's new
  `take_snapshot()` became its first real caller. Also adds
  `snapshots.source_scan_id` (nullable) recording which A1 scan a
  snapshot's state was read from -- a snapshot now carries its own
  provenance instead of being a freestanding capture with no link back
  to what was actually detected. Existing v0.2.0 rows are unaffected
  (`source_scan_id` is just `NULL` on them). Also adds a `finding_id`
  filter to `get_findings()`, needed by A4's new `fix_firewall_finding()`
  to look up one specific finding by its stable hash (a `finding_id`
  can recur across scans, so this combines with the existing
  newest-first ordering to naturally pick the most recent occurrence).
- CLI is a bridge, not the final design: `--import-scan` / `--import-
  findings` read A1's/A2's existing `--json` exports, so the whole
  encrypt/store/retrieve path is testable today without changing A1/A2
  yet. Also `--list-scans` / `--list-findings` for inspection, and
  `--selftest` (writes a throwaway scan+finding with a canary string,
  reads it back, confirms the canary never appears in the raw `.db`
  bytes) so this module's own correctness doesn't depend on having A1/A2
  output on hand.
- **Needed no changes for A1 v0.15.0 / A2 v0.9.0 / A4 v0.4.0's big diagnostic-
  detail batch.** Every new A1 field, new A2 finding category, and new A4
  `snapshot_type` (`"one_shot_action"`, see A4's entry below) fits the
  existing schema-free design: `scans.payload`/`findings.payload`/
  `snapshots.payload` are arbitrary encrypted JSON blobs, and `category`/
  `snapshot_type` are plain free-text columns, not enums -- confirmed
  explicitly rather than assumed, so A6 stays at v0.3.0 through this round.

**A1 and A2 are now wired directly into A6 (v0.13.0 / v0.7.0).** The old
JSON file handoff (`--json scan.json` / `--input scan.json`) still works
exactly as before -- this was additive, not a replacement, so nothing
that already depended on the JSON files broke. New:

- A1's `--cache` flag writes the scan straight into A6 via
  `write_scan()`, right alongside (or instead of) `--json`.
- A2's `--cache` flag skips `--input` entirely: it reads the most recent
  scan straight out of A6 (or a specific one via `--cache-scan-id`),
  runs the exact same `evaluate()` unchanged, and writes findings back
  into A6 via `write_findings()`, linked to that scan's id.
- Neither file hardcodes A6's version number in an import statement --
  same reasoning A2 already used to avoid hardcoding A1's: a
  `_import_a6()` helper (identical in both files) globs for
  `a6_encrypted_cache_v*.py` next to itself and loads whichever one has
  the highest version, so A6 can keep bumping its own filename with zero
  changes needed in A1 or A2.
- `cryptography` (A6's dependency) is only ever imported lazily, inside
  `_import_a6()`, and only when `--cache` is actually passed -- A1 and
  A2 both stay standard-library-only otherwise, and a scan/evaluation
  still completes normally (with a clear stderr message) if A6 or
  `cryptography` isn't available.
- Verified end-to-end in this sandbox: `network_discovery_v0.14.0.py
  --cache` wrote a real scan into a fresh A6 database, then
  `a2_rule_engine_v0.7.2.py --cache` (no `--input` given at all) picked
  up that exact scan, evaluated it, and wrote the resulting finding back
  linked to the right scan id -- confirmed via A6's own `--list-scans`/
  `--list-findings`. Also re-confirmed `--json` still works unchanged on
  its own (regression check), and that the raw `.db` file still doesn't
  leak the scan's real IP in plaintext.
- **Real bug, caught by Ammar on his first run (v0.7.1 fix):** running A2
  with no `--input`, no `--cache`, and nothing piped in looked like a
  dead, black `cmd` window -- no crash, no message. Cause: `_load_input()`
  fell back to `sys.stdin.read()`, which blocks forever on a real
  terminal with nothing piped in. Same silent-failure shape as A1's
  Wi-Fi-scan and DNS-detection bugs, just wearing a hang's clothes
  instead of an empty result. Fixed: `_load_input()` now checks
  `sys.stdin.isatty()` and raises a clear `NoInputError` telling you what
  to pass instead of blocking silently, when stdin is a live terminal and
  neither `--input` nor `--cache` was given. Piped stdin (`cat scan.json |
  a2 ...`) is unaffected. Verified with a real pty in this sandbox (a
  plain subprocess pipe doesn't reproduce `isatty()==True` -- needed
  `pty.spawn()` to actually simulate a bare interactive terminal):
  confirmed the old code hung with zero output, confirmed this version
  prints the message and exits immediately. Re-confirmed `--input`,
  `--cache`, and piped stdin all still work unchanged.

**A4 (Snapshot/Rollback Manager) is started (v0.4.0).** Own file
(`a4_snapshot_rollback_v0.4.0.py`). Built before A3 on purpose --
CLAUDE.md already called this order out ("rollback has to exist before
anything is allowed to touch a device's config"), and A3 doesn't exist
yet, so this version is built to be fully testable standalone.

**v0.3.0 is a real redesign, at Ammar's explicit follow-up request.**
v0.1.0/v0.2.0 required manually snapshotting one named interface ahead
of time (`--snapshot INTERFACE`, then `--restore ID`). Ammar didn't
want that -- he wanted rollback to be automatic: diff the live system
against A6's already-stored scan history, find whatever actually
changed, and revert only that, with no manual pre-snapshot step. That
manual flow is gone, replaced by:

- `diff_against_scan(scan_id=None)` -- reads current live state and
  compares it field-by-field against a baseline A6 scan (the most
  recent one, or `--scan-id`). Returns a list of differences, each
  tagged with whether A4 actually knows how to revert it.
- `rollback(scan_id=None, dry_run=False)` -- runs the diff, then
  reverts every revertible difference. Writes a record of what it
  found and did into A6 (the `snapshots` table, repurposed from "the
  before-state" to "a log of what a rollback actually did" -- there's
  no separate before-state to store anymore, the baseline scan already
  is that).

**Scope expanded well beyond just interface enable/disable, also at
Ammar's explicit request** ("do all fixes on windows... i want all the
mentioned things to be done"), after he was walked through the real
feasibility/risk tradeoffs for each:

**Flagged after the fact: the new `_set_interface_mtu()` /
`_set_interface_dns()` / `_set_interface_ip_mode()` functions, and the
Linux `rfkill` branch of `_set_wifi_radio_software_state()`, were built
for all 3 platforms even though "do all fixes on windows" only asked for
Windows.** Cross-platform support was added to match A1's existing
convention rather than because it was requested. Ammar caught this and
was asked directly: keep it, or strip it back to Windows-only. His call:
**keep it** -- no extra dependencies, matches how A1 already covers all 3
OSes everywhere else, and the Linux/macOS paths were already tested via
command-construction mocking (see below). Noted here since building past
what was actually asked is exactly the kind of thing that should be
flagged, not quietly left in.

- `interface_admin_state` / `interface_mtu` -- unchanged mechanism from
  v0.1.0, now driven by the diff engine.
- `interface_dns` -- needed A1 v0.14.0's new per-interface DNS
  (`get_interface_network_config()`) first; the old flat
  `get_dns_servers()` couldn't say which interface to fix.
  `netsh interface ip set/add dns` / `nmcli con mod ipv4.dns` /
  `networksetup -setdnsservers`.
- `interface_ip_mode` -- static-vs-DHCP, plus the actual
  IP/subnet/gateway when reverting to a specific static config -- also
  needed A1 v0.14.0's richer data, since the old `ip_assignment_mode`
  was just a label with no values to restore.
  `netsh interface ip set address dhcp/static` /
  `nmcli ipv4.method` / `networksetup -setdhcp`/`-setmanual`.
- `wifi_radio` -- Linux via `rfkill block/unblock wifi`, clean and
  documented, no concerns. **Windows via the Native WiFi API
  (`WlanSetInterface`, `wlan_intf_opcode_radio_state`) through
  `ctypes`** -- there is no netsh/PowerShell command for this; this is
  the actual API Windows' own network flyout uses internally. Flagged
  more heavily than anything else in this codebase: it's the only
  function anywhere in A1/A4 that calls into a DLL instead of a
  subprocess CLI tool, and it cannot be exercised at all outside a real
  Windows machine -- not even by feeding it realistic sample text the
  way the other new parsers/setters were checked, since `ctypes.windll`
  doesn't exist on Linux. Built against the documented struct layouts,
  every call wrapped so a failure returns a clean error instead of
  propagating a raw ctypes exception -- but genuinely unverified in a
  stronger sense than "not yet tested on real hardware" elsewhere in
  this codebase. **Ammar asked for this despite the risk being
  explained** (a wrong read just misinforms; a wrong write actually
  changes something with no way to verify it did the right thing) --
  flagged clearly rather than silently built or silently refused.

**What deliberately stayed separate from the generic diff engine:
firewall rule fixes.** `fix_firewall_rule()` / `fix_firewall_finding()`
only ever act on the *exact* rule A2's `check_firewall_blocking()`
already identified as the cause (via a finding's
`evidence.firewall_rule`, looked up from A6 by `finding_id`) -- never a
blind diff of "what looks different" in the ruleset, since rules are
identified by matching (fragile) and a wrong match could disable an
unrelated rule or remove a real security control. Windows-only for now,
per Ammar's stated priority: `netsh advfirewall firewall set rule ...
new enable=no` **disables, never deletes** -- fully reversible, nothing
lost. A synthetic "profile policy" pseudo-rule (the Windows Firewall
profile's own default outbound action, not a real named rule -- see
A1's `_windows_firewall_profile_policy()`) is detected and refused with
a clear explanation rather than sent to netsh to fail confusingly.
Linux/macOS need real rule-matching against iptables/nft/pfctl output
to safely target the same rule, materially harder and riskier
(iptables especially has no per-rule "disable", only insert/delete by
exact spec) -- flagged as not built rather than attempted unsafely.

- Reuses A1 and A6 by dynamically loading whichever
  `network_discovery_v*.py` / `a6_encrypted_cache_v*.py` sits next to
  this file, every import wrapped immediately in `_load_a1()` /
  `_load_a6_cache()` (the A1 v0.13.1/A2 v0.7.2 fix, applied from day
  one here instead of shipping the same bug a third time).
- macOS needs its own small `_macos_service_name_for_interface()`
  lookup for admin-state changes specifically: A1's macOS code only
  keeps the wifi/ethernet *type* per interface, not the actual
  "Hardware Port" name `networksetup -setnetworkserviceenabled` needs.
  (The newer DNS/MTU/IP-mode setters get the service name for free from
  A1 v0.14.0's `connection_name` field instead.)
- Every restore is **idempotent** and **verifies the OS actually
  applied the change** before reporting success, rather than trusting a
  command's exit code alone.
- CLI: `--diff [--scan-id N]`, `--rollback [--scan-id N] [--dry-run]`,
  `--verify-and-rollback [--scan-id N]`,
  `--fix-firewall-finding FINDING_ID`, `--list-events`, plus
  `--cache-db`/`--cache-key` overrides.
- **Real bug caught by testing, fixed before it shipped:**
  `verify_reachability_and_maybe_rollback()` originally decided
  "unreachable" from gateway ping loss alone. Testing in this sandbox
  caught a live false positive -- ICMP to the gateway was blocked (100%
  "loss") even though the internet was completely fine (confirmed by
  `check_internet_reachability()` succeeding at the same time). Fixed:
  `internet_reachable` (A1's TCP-connect check) is now the deciding
  signal; gateway ping loss is still reported for diagnostics but
  doesn't trigger a rollback by itself -- same confident-false-alarm
  shape A2's `_connectivity_context()` already exists to avoid, except
  here a false positive would take a real action, not just misreport
  severity.
- **Verified in this sandbox, stated precisely about what was and
  wasn't real:**
    - `interface_admin_state` and `interface_mtu`: fully real,
      end-to-end, against a live (virtual, throwaway) veth interface --
      broke both at once, `--diff` found both without changing
      anything, `--rollback` reverted both, a second `--rollback` found
      nothing left, `--dry-run` detected but didn't act, `--list-events`
      showed an accurate history including the dry run.
    - `fix_firewall_finding()`: fully real end-to-end against a real
      iptables DROP rule -- ran A1+A2 for real, looked up a real
      `check_firewall_blocking()` finding from A6 by its actual
      `finding_id`, confirmed the lookup/evidence extraction work; the
      platform guard correctly refused on this Linux sandbox (expected,
      correct behavior, not a bug).
    - `interface_dns`, `interface_ip_mode`, and `wifi_radio`'s Linux
      path (`rfkill`): command construction verified by mocking
      `subprocess.run` and inspecting the exact command lines built for
      known inputs -- real writes need NetworkManager cooperation this
      container's config fights (same limitation A1 v0.14.0 hit), and
      this container has no real radio device for `rfkill` to act on.
    - `wifi_radio`'s Windows path: confirmed it fails cleanly rather
      than crashing on non-Windows, which is the only thing checkable
      here -- the actual `WlanOpenHandle`/`WlanEnumInterfaces`/
      `WlanSetInterface` call sequence is unverified in the stronger
      sense already flagged above.
    - Windows/macOS `netsh`/`networksetup` command paths (DNS, MTU, IP
      mode) follow the same documented syntax used elsewhere in this
      codebase but are not verified on real hardware.

**v0.4.0 adds 3 more `diff_against_scan()`/`rollback()` categories and 2
new one-shot corrective actions**, matching A1 v0.15.0's new discovery
fields that turned out to be genuinely fixable (most of the new fields
aren't -- see A2's v0.9.0 evidence-only list above, the same discipline
applied here):

- `hosts_file_entries` -- flags active hosts-file entries present live
  but not in the baseline scan (A1's `read_hosts_file()` now runs every
  scan specifically for this). `_set_hosts_file_entries()` removes them
  by exact line match, a plain file edit, not a subprocess call --
  **one-directional on purpose**: it only removes entries added since the
  baseline, it never restores entries that were removed. Verified for
  real against a throwaway `/tmp` test file (confirmed every other line
  survives byte-identical); the real system hosts file was never touched
  in testing (confirmed via `md5sum` before/after).
- `system_proxy_config` -- Windows (`winreg` write, no `InternetSetOption`
  refresh broadcast -- flagged as a future addition, same caution class as
  `_set_wifi_radio_windows()` below) and macOS (`networksetup
  -setwebproxystate`/`-setsecurewebproxystate off`, disable-only) diffs
  are revertible. **Linux diffs are always marked non-revertible, with an
  explanatory note** -- `http_proxy`/`https_proxy` are environment
  variables of an already-running process, and nothing can change another
  process's environment from outside it after the fact; marking this
  revertible would misreport what a rollback actually did. Best-effort
  GNOME-only `gsettings` is attempted anyway where it's plausibly useful,
  but the diff's own `revertible` flag stays honest about the real
  limitation.
- `wifi_power_management` -- **Linux-only**, matching A1's Linux-only
  read side. `_set_wifi_power_management()` reuses A1's own Wi-Fi-
  interface-name lookup so the read and write sides can't disagree about
  which interface is "the" Wi-Fi one.
- `flush_dns_cache()` / `sync_system_clock()` -- two new one-shot
  corrective actions (not diff/rollback -- same shape as
  `fix_firewall_rule()`: an engine function plus a thin CLI wrapper), new
  CLI flags `--flush-dns-cache` / `--sync-clock`. **Both now write an A6
  audit row on every call, success or failure** (`snapshot_type=
  "one_shot_action"`) -- a new decision this round, and a deliberate
  improvement over `fix_firewall_rule()`'s current silence (not
  retrofitted onto the firewall fix this round, just noted as an
  inconsistency). These are what back A2 v0.9.0's two new `FIX_AUTO`
  classifications (`check_dns_not_resolving`, `check_clock_not_synced`).
- **Verified in this sandbox:** `_set_hosts_file_entries()` for real
  (throwaway file, see above); `flush_dns_cache()` for real (a real
  failure here, since this container has neither `systemd-resolve` nor
  `resolvectl` -- the failure path and its A6 audit row both confirmed
  working); `sync_system_clock()` for real (a real failure here too --
  `timedatectl` can't reach D-Bus since this container doesn't run
  systemd as PID 1 -- same "verified the real failure path, not the
  success path" honesty as the DNS flush); `_set_wifi_power_management()`
  fails cleanly for real (no `iw` in this container); a full real
  A1→A6→A4 CLI run (`--diff`, `--flush-dns-cache`, `--sync-clock` against
  a live scan) completed with zero crashes and zero false positives.
  `_set_system_proxy_config()` on all three platforms, and
  `_set_wifi_power_management()`'s actual `iw` command line, are
  command-construction-verified only (mocked `subprocess.run`) -- no
  Windows/macOS machine and no real wireless interface available here.
  `eth0` and the real `/etc/hosts` confirmed byte-identical before and
  after all testing.

Everything else (A3, A5, A7, the Credential Manager, AI1) is not
started yet.

## Flagged / open decisions

- **Gateway-MAC-stability-across-scans (ARP-spoofing-style detection) —
  flagged, not built.** A2's `evaluate(data)` only ever sees one scan's
  discovery dict; `RULES` are all single-scan functions with no
  `previous_scan` parameter anywhere in the contract. Checked this
  carefully during A2 v0.9.0's batch of new rules: `check_rogue_dhcp()`
  turned out not to need it (a single-scan active broadcast probe, not a
  comparison), and `check_hosts_file_hijack()` turned out not to need it
  either (a single-scan, self-referential check against A1's own
  known-good hostnames) — but "did the gateway's MAC address change since
  the last scan" genuinely can't be answered without comparing against a
  previous scan, and there's no minimal way to bolt that onto the
  existing single-scan rule contract without either special-casing one
  rule or widening `evaluate()`'s signature for everyone. The minimal
  future shape, if this gets built: `evaluate(data, previous_scan=None)`,
  used only by the 2-3 rules that actually need history, not a blanket
  contract change for the other 25+ rules that don't. Matches AI1's
  already-stated deferred cross-scan-correlation roadmap — this is
  arguably AI1's job once it exists, not a reason to build a parallel
  mechanism in A2 first.
- **CDP and LLDP discovery — flagged, not built.** Both need raw Layer-2
  packet capture (passively listening for frames switches broadcast),
  which needs root/admin on every desktop OS, and has **no viable path at
  all on iOS** (Apple's app sandbox blocks raw sockets structurally — no
  permission can unlock it short of jailbreaking) or on a **non-rooted
  Android** phone (blocked by SELinux policy since roughly Android 8/9).
  Adding a dependency like `scapy` would make the Windows/Linux/macOS code
  easier to write, but doesn't remove either constraint — the root/admin
  requirement and the mobile-OS block are both below what any Python
  library can reach.
- **Open question this raises: is iOS/Android a target platform for this
  app at all?** Nothing in A1 today assumes mobile — `netsh`/`ip`/
  `ifconfig` are all desktop-native tools. If mobile ends up in scope,
  it's a bigger conversation than just CDP/LLDP: even basic local network
  scanning is restricted on iOS (explicit "Local Network" permission
  required since iOS 14, multicast/broadcast limited) and behaves
  differently on Android. Not yet decided — revisit before building
  anything that assumes a target platform.
- **Web-UI scraping for consumer routers (Tenda/TP-Link) — flagged, not
  built.** UPnP IGD (built, see A1's current state above) covers WAN
  IP/connection status/traffic with zero router credentials, but it
  doesn't expose the DHCP client list or the router's actual configured
  DHCP range — the exact gap `calculate_pool_usage()` already flags.
  Getting that data means logging into the router's own web admin panel
  and calling its undocumented endpoints (`/goform/...` on Tenda,
  `/cgi-bin/...` on TP-Link) directly — no clean API exists for either
  brand. Those endpoints are unofficial, vary by model/region/firmware,
  and need per-model reverse engineering (capturing what the router's
  own admin UI does via browser dev tools) rather than one integration
  that works everywhere. Deferred until the Credential Manager exists —
  no point building something that needs a stored router login before
  there's a safe place to keep one.
- **Router/device-side fix and rollback (A3 and A4 both) needs to cover
  two genuinely different device classes, not just consumer routers —
  flagged, not built.** Ammar's explicit ask: A4 should eventually be
  able to snapshot/rollback issues caused by the router itself, not only
  this machine's own settings, and the same is true for A3's fixes. That
  splits into two different mechanisms, matching the existing
  Tenda/TP-Link vs. MikroTik/Cisco distinction in Working Conventions
  below:
    - **Consumer (Tenda, TP-Link):** the web-UI scraping approach flagged
      directly above — no clean API, per-model reverse engineering,
      *guided*-fix UX since access is limited (per Business Context: this
      segment needs assistive UX, not full automation).
    - **Managed (MikroTik, Cisco):** a real, documented API/SSH interface
      instead of scraping (MikroTik's RouterOS API; Cisco depending on
      platform — SSH/CLI, NETCONF, or REST). Technically more
      straightforward than the consumer path once credentials exist, and
      *full automation* is reasonable here (per Working Conventions) —
      a plausible actual A3/A4 v2 candidate once the Credential Manager
      exists, likely before the harder consumer web-UI work.
  Both branches share the same blocker: neither can start before the
  Credential Manager exists, and A4's snapshot/rollback side specifically
  needs a way to read a device's current config *before* a fix and
  restore it after, which for managed devices likely means exporting the
  running config via the same API/SSH path (e.g., MikroTik's
  `/export`-style config dump) rather than the individual-setting
  read/write A4 v1 does for this machine's own interfaces.

## Working conventions

- **Module-by-module, tested against real hardware before moving on.**
  Ammar (the person you're working with) tests each module on his actual
  network and reports results back — don't assume a module works until
  it's been run against real devices.
- **Ammar can read code but isn't a professional coder.** Explain what code
  does clearly, without being condescending, and without assuming deep
  Python/networking-library familiarity.
- **Standard-library-only Python** for v1 modules unless there's a specific
  reason to add a dependency — flag it explicitly if you think one's needed,
  don't just add it. (First exception: A6 uses `cryptography` for
  encryption at rest — flagged and approved, see A6's current-state entry.
  It's a build-time dependency bundled into the final installer, so it
  doesn't add install friction for the end user.)
- **Versioning:** every file gets a version number in its own filename and a
  short changelog in its header comment (e.g. `network_discovery.py` ->
  `network_discovery_v0.4.0.py` next time it changes, with a `VERSION:` /
  `CHANGELOG:` block at the top listing what changed in each version and
  why). No separate archive folder or spreadsheet needed — conversation/
  commit history is the source of truth for old versions.
- Target device ecosystem to keep in mind: Tenda, TP-Link (consumer, more
  limited access — needs guided UX); MikroTik, Cisco (managed, more capable
  automation is reasonable here).

## On the horizon

- **`--cache` wiring confirmed on Ammar's real hardware.** Ran
  `run_scan.bat` (A1 `--cache` then A2 `--cache`) on his actual Windows
  machine: A1 wrote a real scan into A6 as scan id 1, A2 read it back out
  of A6 with no `--input`/JSON file involved, evaluated it, and wrote the
  finding back linked to scan id 1 -- the full write/read/evaluate/
  write-back round trip works end to end outside this sandbox, not just
  in it. Also confirmed the v0.2.0 severity-scaling fix is doing its job
  for real: adapter `Ethernet` was disabled but the internet was
  confirmed working (Wi-Fi carrying the connection), and it correctly
  showed as `info`, not `critical`/`warning` -- the exact false-alarm
  shape Ammar's original hardware test caught.
- **Still outstanding: the rest of the v0.3.0–v0.6.0 rule set hasn't been
  exercised on real hardware yet** -- this run only triggered the
  interface/severity-scaling rule (1 info finding, 0 critical/warning).
  DNS-not-resolving, firewall correlation (including the v0.6.0 "ALL"
  blanket-block branch), and the other rules still need a real scenario
  that actually triggers them before they're considered hardware-checked.
- **A4 v0.3.0's full diff-and-rollback engine, and its expanded fix scope
  (interface admin_enabled/MTU/DNS/static-DHCP mode, Wi-Fi radio, and
  firewall rule disabling), all still need real-hardware confirmation on
  Ammar's actual Windows machine** — this is the single biggest
  outstanding verification gap right now, since v0.3.0 was built and
  tested entirely in this sandbox:
    - `admin_enabled` and MTU set/restore: real end-to-end verified here,
      but only against a throwaway Linux `veth` pair — needs the same
      test on Ammar's real Windows adapter (elevated/Administrator
      Command Prompt required, same as v0.2.0's known requirement).
    - DNS and static/DHCP IP-mode set functions: command construction
      only verified via mocking on all three platforms — never run
      against a real interface anywhere, Windows included.
    - `_set_wifi_radio_windows()` (the ctypes/`wlanapi.dll` software
      radio toggle): the highest-risk, least-verified piece in the
      codebase. Only checked that it fails cleanly and doesn't crash
      when *not* running on Windows — the actual `WlanOpenHandle` →
      `WlanEnumInterfaces` → `WlanSetInterface` sequence has never run
      against a real Wi-Fi adapter. Needs deliberate, careful testing on
      real Windows hardware before it's trusted in front of a
      non-technical customer — a wrong radio-state write is exactly the
      kind of thing that erodes the trust CLAUDE.md flags as the biggest
      risk in this market.
    - `fix_firewall_rule()` / `fix_firewall_finding()`: the
      `netsh advfirewall firewall set rule ... enable=no` command itself
      has never run on a real Windows firewall — only verified end-to-end
      on this sandbox's Linux `iptables` path (which the function
      correctly refuses to touch, since it's Windows-only by design), and
      via mocking for the actual Windows command.
- Now that A4 has a real fix-and-rollback path (not just rollback), **A3
  (Fix Engine) is next** — it can wrap A4's `diff_against_scan()` /
  `rollback()` / `_set_*` / `fix_firewall_rule()` functions with the
  auto-fix / guided-fix / not-fixable classification, idempotency, and
  circuit-breaker behavior CLAUDE.md's architecture section calls for,
  instead of Ammar driving A4's CLI by hand. Both A3 and A4 are still
  PC-side only by explicit choice — router/device-side fix and rollback
  (consumer web-UI scraping *and* managed MikroTik/Cisco API access) is
  flagged above under "Router/device-side fix and rollback," not
  forgotten, just correctly sequenced behind the Credential Manager.
- **Extend the firewall fix beyond Windows** — `fix_firewall_rule()` is
  Windows-only for now (matching A2's `check_firewall_blocking()` finding
  shape, which already fires on all three platforms). Linux
  (`iptables`/`nft`) and macOS (`pfctl`) rule-disabling need their own
  safe, disable-not-delete implementations.
- **Re-test A1 v0.14.0's `get_interface_network_config()`** (DNS servers,
  static/DHCP mode, IP/subnet/gateway per interface) against a real
  managed NetworkManager connection on Linux — this sandbox's
  NetworkManager wouldn't actually manage the test interface (flagged in
  A1's own changelog), so the Linux parsing path was only verified
  against realistic mocked `nmcli` output, not a live connection. Windows
  (`ipconfig /all`) and macOS (`networksetup`) parsing are in the same
  boat — real-hardware confirmation still pending for all three.
- **A1 v0.15.0 / A2 v0.9.0 / A4 v0.4.0's entire ~21-function diagnostic-
  detail batch needs real-hardware confirmation** — built and tested
  entirely in this sandbox, same biggest-outstanding-gap shape as every
  previous round, but larger:
    - Most Windows-specific reads (link speed/duplex, DHCP lease via
      `ipconfig`, DNS suffix list, proxy via `winreg`, driver info via
      `wmic`, Wi-Fi connection details via `netsh`) and all macOS-specific
      reads are command-construction-verified only.
    - `detect_rogue_dhcp_servers()`'s true-positive path (a second real
      DHCP server actually responding) has never been exercised — this
      sandbox has no second DHCP server to test against.
    - `check_pmtu_blackhole()`, `check_captive_portal()`'s true-positive
      path, `measure_throughput()` against a genuinely degraded link, and
      `check_nat_type()`'s full classification accuracy are all
      logic-reviewed only — none of these has a real trigger condition
      available in this sandbox (no real blackholed path, no real captive
      portal, no real slow link, and this sandbox's own NAT setup isn't
      necessarily representative of a customer's router).
    - The live STUN UDP round-trip specifically timed out in this
      sandbox (outbound UDP isn't cooperative here) — packet
      construction/parsing were verified by hand, but a real round-trip
      against a real STUN server has never succeeded here.
    - A4's `_set_system_proxy_config()` (all 3 platforms) and
      `_set_wifi_power_management()`'s real `iw` command are
      command-construction-verified only — no real Windows/macOS machine
      and no real wireless interface in this sandbox.
    - `flush_dns_cache()` and `sync_system_clock()` were only exercised
      via their *failure* paths here (this container has neither
      `systemd-resolve`/`resolvectl` nor a working `timedatectl`) — the
      success path on a real system with those tools present is
      unverified.
- Expand the MAC vendor OUI table (known gap, flagged above)
- Add SNMP to A1's discovery methods (mDNS shipped in v0.15.0)
- Expand A2's rule set further, once the real-hardware retest confirms the
  current rules
- AI layer (AI1) stays deferred until after a working core (A1-A7 minus AI1)
  exists end-to-end
- Cloud backend (FastAPI + PostgreSQL) is last — it's opportunistic/optional
  by design, so it shouldn't block or shape the on-device core
