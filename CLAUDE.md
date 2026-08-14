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
- JSON export (`--json`) in the shape that will eventually be handed to A6
  directly instead of a file
- `--no-ports` / `--no-wifi` flags to skip slower steps

Everything else (A2 through A7) is not started yet.

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
- Build out A2 (Rule Engine) on top of A1's output
- A4 (Snapshot/Rollback) before A3 (Fix Engine) — rollback has to exist
  before anything is allowed to touch a device's config
- AI layer (AI1) stays deferred until after a working core (A1-A7 minus AI1)
  exists end-to-end
- Cloud backend (FastAPI + PostgreSQL) is last — it's opportunistic/optional
  by design, so it shouldn't block or shape the on-device core
