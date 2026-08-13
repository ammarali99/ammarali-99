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
not microservices — keep it simple, one process, one deployable).

| Module | Name | Role |
|---|---|---|
| A1 | Discovery | Finds devices on the network (IP/MAC/vendor/hostname/open ports/role) |
| A2 | Rule Engine | Turns raw discovery data into structured findings/diagnoses |
| AI1 | AI Advisory Layer | **Deferred to post-v1.** Runs locally on-device (never cloud — see constraint above). Takes A1's raw data + A2's findings, outputs confidence-scored *suggestions only* — never executes fixes itself |
| A3 | Fix Engine | Executes fixes. Must be idempotent, and has a circuit-breaker to stop runaway/looping fix attempts |
| A4 | Snapshot/Rollback Manager | Takes a snapshot before any fix, can roll back |
| A5 | Report Generator | Human-readable output for non-technical users |
| A6 | Encrypted local cache | SQLite, encrypted at rest. **All modules write here first** |
| A7 | Sync Layer | The *only* module allowed to touch the internet. Opportunistically pushes logs when online, pulls updated rules/retrained AI models back down and hands them to A2/A3 locally |

**Data flow:** every module writes to A6 first. Only A7 ever touches the
internet. Nothing else is allowed to make an outbound call — that's not a
style preference, it's the core offline-first constraint.

**Credential Manager** lives locally inside the Core Engine (not the cloud),
so fixes on managed devices still work during an outage.

**Safeguards that are non-negotiable:** idempotent fixes, circuit-breaker on
fix attempts, versioned rules/AI models with rollback, encrypted credentials
at rest.

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
  — `netsh` on Windows, `nmcli`/`iwlist` on Linux, `networksetup` on macOS
  (macOS can only report the *currently connected* network — Apple removed
  the nearby-scan tool `airport` from recent macOS versions, this is a
  platform limitation, not a bug)
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
- Build out A2 (Rule Engine) on top of A1's output
- Eventually A3/A4 (Fix Engine + Rollback) — idempotency and circuit-breaker
  logic matter a lot here, don't skip them for speed
- AI layer (AI1) stays deferred until after a working core (A1-A7 minus AI1)
  exists end-to-end
