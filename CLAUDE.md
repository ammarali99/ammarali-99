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

**A2 (Rule Engine) is started (v0.7.2).** Standard-library-only Python,
in its own file (`a2_rule_engine_v0.7.2.py`), deliberately never importing
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
- Rule set (12 rules): Wi-Fi radio off (hardware/software), adapter
  disabled, adapter enabled-but-not-connected, no gateway found, gateway
  unreachable/high packet loss/high latency, internet unreachable (with a
  WAN-vs-LAN distinction based on whether the gateway itself is reachable),
  IP pool near exhaustion, UPnP sanity notes surfaced as findings (passed
  through from A1's `_upnp_sanity_notes()` rather than re-parsed here, to
  avoid a second, fragile copy of that detection logic), insecure Telnet
  port open, Wi-Fi channel congestion recommendation, DNS not configured,
  DNS configured but not resolving (v0.3.0, see below), a local firewall
  rule blocking DNS/ICMP (v0.4.0, see below)
- CLI: prints findings sorted by severity with a summary count, `--json`
  export in the same shape A6 will eventually store directly
- `--cache` (v0.7.0): skips `--input` entirely, reads the most recent scan
  straight out of A6 (or a specific one via `--cache-scan-id`), evaluates
  it unchanged, and writes findings back into A6 via `write_findings()`.
  Same dynamic `_import_a6()` loader A1 v0.13.0 uses, for the same reason
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

**A6 (Encrypted local cache) is started (v0.2.0).** Own file
(`a6_encrypted_cache_v0.2.0.py`). Handles what actually exists so far --
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
- CLI is a bridge, not the final design: `--import-scan` / `--import-
  findings` read A1's/A2's existing `--json` exports, so the whole
  encrypt/store/retrieve path is testable today without changing A1/A2
  yet. Also `--list-scans` / `--list-findings` for inspection, and
  `--selftest` (writes a throwaway scan+finding with a canary string,
  reads it back, confirms the canary never appears in the raw `.db`
  bytes) so this module's own correctness doesn't depend on having A1/A2
  output on hand.

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
- Verified end-to-end in this sandbox: `network_discovery_v0.13.1.py
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

**A4 (Snapshot/Rollback Manager) is started (v0.1.0).** Own file
(`a4_snapshot_rollback_v0.1.0.py`). Built before A3 on purpose --
CLAUDE.md already called this order out ("rollback has to exist before
anything is allowed to touch a device's config"), and A3 doesn't exist
yet, so this version is built to be fully testable standalone: take a
snapshot, break something, restore it, verify the restore -- all without
needing a fix engine to drive it. Current version does:

- **Scope, deliberately narrow for v1: this machine's own network
  settings only, not router config**, and within that, only one thing --
  an interface's `admin_enabled` state (enabled/disabled). That's the
  exact finding that's already fired for real on Ammar's hardware (a
  disabled Ethernet adapter). Two other candidates were considered and
  deliberately left out rather than guessed at:
    - **DNS servers** -- A1's `get_dns_servers()` reads DNS as one flat
      list across the whole machine, not per-interface, so there's no
      way yet to know which interface a given server belongs to. That's
      an A1 change first, not something to fake here.
    - **Wi-Fi radio software on/off** -- A1's own `get_wifi_radio_state()`
      already explains why it won't touch Windows' real Airplane Mode
      flag; there's no clean, documented command to *set* the software
      radio state back either (unlike `admin_enabled`, which
      `netsh interface set` does support). A confidently-wrong restore
      is worse than not having the feature -- same reasoning A1 already
      used for the read side.
  Router-side snapshot/restore is blocked on the same thing web-UI
  scraping already is: no point building rollback for something A3
  can't touch until the Credential Manager exists.
- Reuses A1 and A6 by dynamically loading whichever
  `network_discovery_v*.py` / `a6_encrypted_cache_v*.py` sits next to
  this file -- same version-decoupling trick A1/A2 already use for A6.
  Every dynamic-import call is wrapped immediately in `_load_a1()` /
  `_load_a6_cache()`, which convert any failure into a clear `A4Error`
  -- applying the exact fix A1 v0.13.1/A2 v0.7.2 needed *from the
  start*, instead of shipping the same bug a third time.
- macOS needs its own small `_macos_service_name_for_interface()`
  lookup: A1's macOS code only keeps the wifi/ethernet *type* per
  interface, not the actual "Hardware Port" name (e.g. "Wi-Fi",
  "Thunderbolt Ethernet") that `networksetup -setnetworkserviceenabled`
  needs as an argument.
- `take_snapshot()` / `restore_snapshot()` /
  `verify_reachability_and_maybe_rollback()` as the Python API (for A3
  to call later). Every restore is **idempotent** (already-correct state
  -> no-op, reported as such) and **verifies the OS actually applied the
  change** before reporting success, rather than trusting a command's
  exit code alone.
- **Real bug caught by testing, fixed before it shipped:**
  `verify_reachability_and_maybe_rollback()` originally decided
  "unreachable" from gateway ping loss alone. Testing in this sandbox
  caught a live false positive -- ICMP to the gateway was blocked (100%
  "loss") even though the internet was completely fine (confirmed by
  `check_internet_reachability()` succeeding at the same time). Deciding
  on ping loss alone would auto-rollback a working connection just
  because ICMP happens to be filtered -- the same confident-false-alarm
  shape A2's `_connectivity_context()` (v0.2.0) already exists to avoid
  for severity, except here a false positive doesn't just misreport
  something, it takes a real action. Fixed: `internet_reachable` (A1's
  TCP-connect check) is now the deciding signal; gateway ping loss is
  still reported for diagnostics but doesn't trigger a rollback by
  itself.
- CLI: `--snapshot INTERFACE [--reason TEXT]`, `--restore ID`,
  `--verify-and-rollback ID`, `--list-snapshots [--target NAME]`, plus
  `--cache-db`/`--cache-key` overrides matching A1/A2's existing flag
  names.
- Verified in this sandbox on Linux against a real (virtual, throwaway)
  network interface -- a `veth` pair created specifically so testing
  never touched this session's actual connectivity: took a snapshot
  while up, took the interface down manually, restored it via A4,
  confirmed `admin_enabled` matched the snapshot again. Confirmed the
  idempotent no-op restore path, and (via a safe mock of A1's
  reachability check, not by actually breaking real networking) both
  branches of `verify_reachability_and_maybe_rollback()` -- rolls back
  when genuinely unreachable, leaves things alone when still reachable.
  Error paths (unknown interface, unknown snapshot id) tested too.
  **Windows/macOS command paths follow A1's own established read-side
  commands exactly but are not yet verified on real hardware** -- same
  honesty convention A1 already applies to its own unverified platform
  paths.

Everything else (A3, A5, A7, the Credential Manager, AI1) is not
started yet.

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
- **Re-test A4 v0.1.0 against Ammar's real Windows hardware** — verified
  in this sandbox against a real Linux virtual interface, but the
  Windows `netsh interface set interface admin=enable/disable` command
  path (what Ammar will actually use) is not yet confirmed on real
  hardware. Needs an elevated (Administrator) Command Prompt to work at
  all — worth confirming that requirement surfaces a clear error if
  forgotten, not a silent failure.
- Now that A4 exists, **A3 (Fix Engine) is next** — it can finally call
  something real for rollback instead of touching device config with no
  safety net. Both A3 and A4 are currently PC-side only by explicit
  choice — router/device-side fix and rollback (consumer web-UI scraping
  *and* managed MikroTik/Cisco API access) is flagged above under
  "Router/device-side fix and rollback," not forgotten, just correctly
  sequenced behind the Credential Manager.
- Expand A4 beyond interface admin_enabled once the prerequisites it's
  currently blocked on are addressed: per-interface DNS tracking in A1
  (needed before DNS restore is possible), and a real Windows-verified
  Wi-Fi-radio set path if one turns out to exist safely.
- Expand the MAC vendor OUI table (known gap, flagged above)
- Add mDNS and SNMP to A1's discovery methods (currently ARP/ping/hostname/
  port-probe/Wi-Fi only)
- Expand A2's rule set further, once the real-hardware retest confirms the
  current rules
- AI layer (AI1) stays deferred until after a working core (A1-A7 minus AI1)
  exists end-to-end
- Cloud backend (FastAPI + PostgreSQL) is last — it's opportunistic/optional
  by design, so it shouldn't block or shape the on-device core
