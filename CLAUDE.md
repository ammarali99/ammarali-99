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
| A1 | Discovery | Finds devices on the network. Current: ARP, ping, hostname, MAC vendor, port probing, Wi-Fi scan. Planned additions: mDNS, SNMP |
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

**One narrow, deliberate exception, two instances of it:** A1's
`check_internet_reachability()` does a lightweight TCP-connect reachability
*test* (not ICMP, no data sent beyond the handshake) to a couple of
well-known IPs on port 443, and `check_dns_resolution()` sends a raw DNS
query directly to each configured DNS server to check it actually resolves
names (catches "internet works but DNS doesn't," which looks identical to
"internet is down" otherwise). Both are diagnostic checks, not dependencies
— A1 doesn't need either to succeed for anything else it does, and both are
skippable together with `--no-internet`. This exists because the product's
whole vision is diagnosing network issues *including* when the internet
connection itself is the problem, which needs an actual check of whether
the WAN path — and DNS specifically — is up. That's a decided carve-out
rather than an unnoticed rule break. No other module gets this exception.

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
a non-technical install target later). Current version does:

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
- JSON export (`--json`) in the shape that will eventually be handed to A6
  directly instead of a file
- `--no-ports` / `--no-wifi` / `--no-internet` / `--no-upnp` flags to
  skip slower or internet/LAN-broadcast-touching steps

**A2 (Rule Engine) is started (v0.3.0).** Standard-library-only Python,
in its own file (`a2_rule_engine_v0.3.0.py`), deliberately never importing
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
- Rule set (11 rules): Wi-Fi radio off (hardware/software), adapter
  disabled, adapter enabled-but-not-connected, no gateway found, gateway
  unreachable/high packet loss/high latency, internet unreachable (with a
  WAN-vs-LAN distinction based on whether the gateway itself is reachable),
  IP pool near exhaustion, UPnP sanity notes surfaced as findings (passed
  through from A1's `_upnp_sanity_notes()` rather than re-parsed here, to
  avoid a second, fragile copy of that detection logic), insecure Telnet
  port open, Wi-Fi channel congestion recommendation, DNS not configured,
  DNS configured but not resolving (v0.3.0, see below)
- CLI: prints findings sorted by severity with a summary count, `--json`
  export in the same shape A6 will eventually store directly
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
- Tested end-to-end against this file's own A1 output, synthetic data
  covering every rule, and Ammar's first real hardware scan (which is what
  surfaced the v0.2.0 fix) -- next up: run the current version against
  real hardware again to confirm both the v0.2.0 and v0.3.0 changes, then
  expand the rule set further

**Note: the A1-to-A2 JSON file handoff is temporary, not the final
design.** A1 and A2 currently pass data through a JSON file
(`--json scan.json` / `--input scan.json`) because A6 (the encrypted local
cache) doesn't exist yet. Once A6 is built, this gets fixed: both A1 and
A2 write/read through A6 directly instead of a JSON file, matching the
architecture's real rule that every module writes to A6 first. This is a
small plumbing change, not a rewrite -- A2's Finding schema is already
designed to be the exact row shape A6 will store, so only the storage
call changes (`json.dump()` -> `a6.write_findings()`), not the rule logic.

Everything else (A3 through A7) is not started yet.

## Flagged / open decisions

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
  don't just add it.
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

- Expand the MAC vendor OUI table (known gap, flagged above)
- Add mDNS and SNMP to A1's discovery methods (currently ARP/ping/hostname/
  port-probe/Wi-Fi only)
- Test A2 against Ammar's real hardware scans, then expand its rule set
- A4 (Snapshot/Rollback) before A3 (Fix Engine) — rollback has to exist
  before anything is allowed to touch a device's config
- AI layer (AI1) stays deferred until after a working core (A1-A7 minus AI1)
  exists end-to-end
- Cloud backend (FastAPI + PostgreSQL) is last — it's opportunistic/optional
  by design, so it shouldn't block or shape the on-device core
