#!/usr/bin/env python3
"""
a2_rule_engine.py -- Module A2 (Rule Engine) of the offline network
diagnostic app.

VERSION: 0.9.0
CHANGELOG:
  0.9.0 - Fourteen new rules plus one deliberate change to an existing
          rule, wiring A2 up to the ~21 new fields A1 v0.15.0 added to
          its discovery dict. Per v0.8.0's own precedent (an MTU rule
          was considered and declined for lack of a safe non-guessing
          trigger), not every new A1 field got a rule here -- the ones
          below are the ones judged to have a safe trigger condition; a
          longer list of fields deliberately left evidence-only is at
          the bottom of this entry.

          New rules:

          check_rogue_dhcp() -- fires when A1's detect_rogue_dhcp_servers()
          (needs root to bind UDP port 68, so this only ever fires when
          A1 was actually run with enough privilege) found more than one
          distinct DHCP server answering. category="dhcp",
          severity=critical, target="network" (a network-wide fact, not
          tied to one interface), fix_classification=FIX_GUIDED -- a
          second DHCP server needs a human to find and unplug/reconfigure
          it, not something this app can safely act on itself.

          check_duplicate_ip() -- one finding per conflicting IP in A1's
          best-effort duplicate_ip.conflicts (a MAC-address change on the
          same IP between two ARP reads a few seconds apart -- A1's own
          docstring is explicit this is best-effort, not a guarantee, and
          this rule doesn't claim otherwise). target is the conflicting
          IP itself (the stable identity here, not either MAC, since the
          IP is what a later scan would re-detect against).
          category="lan", severity=warning (not critical -- A1's own
          detection window is narrow enough that this needs a human to
          confirm, not urgent enough to alarm over), FIX_GUIDED.

          check_multiple_default_routes() -- fires when more than one
          family="ipv4" route in routing_table matches a default-route
          destination (Linux "default", Windows "0.0.0.0", per the
          confirmed field shapes). severity=warning, not critical --
          routing table edits are too risky for this app to guide a
          non-technical customer through blind, so
          fix_classification=FIX_NONE; this is a real, surfaceable fact
          ("something on this machine set up two default routes"), not
          something A3 should ever attempt.

          check_hosts_file_hijack() -- deliberately narrow, and the
          docstring on the function itself says why at more length: it
          only checks a hosts-file entry against a small fixed watchlist
          of hostnames this app's own checks already depend on
          (example.com -- A1's _DNS_TEST_HOSTNAME, confirmed by reading
          the real file rather than assumed; connectivitycheck.gstatic.com
          -- the captive-portal check's host; speed.cloudflare.com -- the
          throughput check's host), fires only when the entry is active
          (not commented out) and its redirect target is a real,
          non-loopback IP. Loopback/0.0.0.0 targets are excluded on
          purpose -- that's the standard, legitimate shape of a
          customer's own ad-blocking hosts file, not hijacking, and this
          app has no internet-connected reputation service to tell a
          real hijack from a legitimate block list beyond that one
          heuristic. A broader "any suspicious hosts entry" rule was
          considered and rejected for the same reason v0.8.0 rejected a
          guessing MTU rule: no safe way to draw that line offline.
          category="security", severity=critical (a real redirect of one
          of this app's own trusted checks is a serious, concrete
          finding, not a maybe), target=the hijacked hostname,
          FIX_GUIDED.

          check_proxy_configured() -- fires when A1's
          system_proxy_config indicates an active proxy. Windows:
          proxy_enabled is True. Linux: http_proxy or https_proxy is
          truthy. macOS: NOT detected -- see "Judgment call" below.
          Severity scales via _connectivity_context(), same pattern as
          check_wifi_radio_off(): info when the internet is confirmed
          working or the check was skipped (an active proxy alone isn't
          inherently a problem -- lots of legitimate reasons to run one),
          warning when the internet is confirmed down (a broken/stale
          proxy config is a plausible cause worth surfacing more
          clearly). category="lan", target="system_proxy", FIX_GUIDED.

          check_vpn_active() -- fires when A1's vpn_interfaces is
          non-empty. Same connectivity-context severity scaling as the
          proxy rule, same reasoning (a VPN being up isn't itself a
          problem). fix_classification=FIX_NONE -- this app has no
          business touching VPN configuration, full stop.
          category="lan", target="vpn".

          check_pmtu_blackhole_finding() -- fires when A1's
          pmtu_check.blackhole_suspected is True. category="wan",
          severity=warning, target="pmtu", FIX_GUIDED, and the summary
          explicitly suggests lowering the interface's MTU as the
          workaround -- this routes straight to A4's existing
          _set_interface_mtu() fix from v0.3.0, so no new A4 fix
          category was needed for this one.

          check_captive_portal_finding() -- fires when A1's
          captive_portal.portal_detected is True. severity=critical
          (deliberately higher than most guided-fix findings here: a
          captive portal fully blocks real internet use even though
          internet.reachable can show True, since A1's TCP-connect
          reachability test doesn't itself get intercepted the way an
          HTTP request does -- this is a case where "internet works" and
          "internet is actually usable" diverge, and a customer stuck
          behind a login page needs to know clearly). category="wan",
          target="captive_portal", FIX_GUIDED with a plain-language-only
          summary ("open a browser, look for a login page") -- there's
          nothing here for A3 to automate.

          check_wifi_weak_signal() -- fires when wifi_connection has
          both signal_dbm and noise_dbm and their difference (SNR) is
          under 15dB. 15dB is a conservative, commonly-cited "poor"
          signal-to-noise boundary in Wi-Fi site-survey guidance (roughly:
          25dB+ good, 15-25dB workable, under 15dB unreliable) -- picked
          deliberately conservative so this doesn't flag a merely
          mediocre signal as a problem. severity=info (this is physical/
          positional, advisory only -- nothing to fix in software),
          fix_classification=FIX_NONE, target=the connected SSID (or
          "wifi" if unavailable). category="wifi".

          check_wifi_power_saving_enabled() -- the one new rule built on
          check_firewall_blocking()'s "precompute symptom booleans, then
          a targeted dispatch that declines to fire without
          corroboration" pattern, per the task spec. wifi_power_save ==
          "on" (Linux-only field, per A1) by itself is normal, common,
          and not a problem -- this only fires when it's ALSO paired
          with an actual symptom: gateway_latency.loss_percent >= 20, or
          jitter_ms > 50. category="wifi", severity=warning,
          target="wifi_power_save", FIX_GUIDED, and the summary names
          the actual symptom seen (loss or jitter) so the customer sees
          the reasoning, not just an assertion.

          check_wps_enabled() -- fires per wifi_networks entry with
          wps_enabled is True (Linux-only field from A1's `iw scan`
          parser; absent entirely on Windows/macOS, read via .get() so
          it degrades to "no finding" there rather than guessing).
          Scoping judgment call, explained fully on the function itself:
          scoped to the network matching wifi_connection["ssid"] (the
          customer's own, currently-connected AP) rather than firing for
          every nearby scanned network. fix_classification=FIX_NONE --
          WPS is the router's own setting, and this app has no router
          credentials to change it (same territory as CLAUDE.md's
          already-flagged web-UI-scraping decision for consumer
          routers). category="security", severity=warning,
          target=the SSID.

          check_clock_not_synced() -- fires when clock_drift.synchronized
          is explicitly False (never on None -- None means the OS-level
          check itself couldn't determine sync status, and guessing
          "not synced" from that would be exactly the confidently-wrong
          shape this codebase keeps catching). category="lan",
          severity=warning, target="system_clock".
          fix_classification=FIX_AUTO -- see "First use of FIX_AUTO"
          below.

          check_high_jitter() -- fires when gateway_latency.jitter_ms is
          not None and > 30ms. 30ms clears the same bar v0.8.0's MTU
          rule was rejected on, but the other direction: it's a
          genuinely standard, widely-cited "noticeable for real-time
          traffic" jitter threshold (VoIP/video-call quality guidance
          consistently puts acceptable jitter well under this), not a
          customer/context-specific value the way MTU is. severity=info,
          fix_classification=FIX_NONE -- nothing for this app to act on,
          purely diagnostic. category="lan", target="gateway_jitter".

          check_throughput_critically_low() -- fires when
          throughput.mbps is not None and < 1.0. Deliberately a
          conservative absolute floor -- "basically not working"
          regardless of what plan the customer is paying for, not a
          judgment about being "slow" relative to an unknown ISP speed
          tier this app has no way to know. severity=warning,
          fix_classification=FIX_NONE (same reasoning: no basis to
          suggest a fix beyond "your connection is basically not
          working right now"). category="wan", target="throughput".

          Changed existing rule: check_dns_not_resolving()'s
          fix_classification changes from FIX_GUIDED to FIX_AUTO. This
          is a deliberate change to existing behavior, not a new rule,
          and gets the same explicit reasoning standard v0.8.0's MTU
          rejection got rather than a silent tweak: A4 v0.4.0 (in
          progress in parallel with this version) is adding a
          flush_dns_cache() one-shot action specifically to back this
          up. A stale/poisoned local DNS cache entry is judged safe and
          fully reversible to flush -- unlike every FIX_GUIDED rule in
          this file, which touches interface, firewall, or Wi-Fi-radio
          state with a real tradeoff a human should at least see before
          it happens. Only the classification changed; the rule's
          trigger condition (internet reachable, no configured DNS
          server resolving) is untouched.

          First use of FIX_AUTO: check_clock_not_synced() and the
          check_dns_not_resolving() change above are the first two real
          uses of FIX_AUTO anywhere in this codebase -- flagged
          explicitly, as instructed, rather than left as a silent
          first-time default. Both were judged safe/reversible with no
          real user tradeoff (an NTP resync, a DNS cache flush), unlike
          every existing FIX_GUIDED rule. A3 (Fix Engine) doesn't exist
          yet, so today this only labels data -- it doesn't cause
          anything to actually auto-execute.

          Judgment call: macOS proxy detection. A1's
          get_system_proxy_config() on macOS just dumps whatever raw
          key-value pairs `scutil --proxy` prints, with no A1-side
          normalization the way Windows (proxy_enabled) and Linux
          (http_proxy/https_proxy) get. Nothing in A1's source confirms
          an exact key name for "is a proxy on" on macOS (the likely
          candidate, HTTPEnable, is not something this file's reading of
          A1 could confirm without a real Mac to check against), so
          check_proxy_configured() deliberately does not attempt to
          read it -- treated as insufficient data, not guessed at. A
          real gap, stated as one: a Mac with a proxy configured will
          not get this finding until A1 normalizes that field the way it
          already does for the other two platforms.

          Judgment call: WPS scoping. Scoped to the currently-connected
          SSID (cross-referenced against wifi_connection.ssid) rather
          than firing for every nearby wifi_networks entry with
          wps_enabled. Reasoning: fix_classification is FIX_NONE either
          way (this app has no router credentials to act on any of
          them), and flagging a neighbor's router's WPS setting isn't
          actionable or relevant to this customer -- it would just be
          noise about hardware they don't own. The real tradeoff, stated
          honestly: a customer connected via Ethernet (wifi_connection
          .ssid is None) whose own Wi-Fi AP is still broadcasting WPS
          won't get this finding today, since there's no connected SSID
          to cross-reference against. Judged an acceptable gap over the
          noisier alternative.

          Judgment call: hosts-file known-good hostname list.
          Deliberately just three hostnames this app's own other checks
          already rely on and can name with certainty (see
          check_hosts_file_hijack() above) -- not an attempt at a
          general "known good sites" list, which would need exactly the
          kind of internet-connected reputation data this app doesn't
          have and can't have per CLAUDE.md's offline constraint.

          Considered, not pursued (evidence-only, no rule) -- matching
          v0.8.0's own precedent of explicitly declining rather than
          silently skipping: interface_link_info (link speed/duplex --
          no safe "wrong" threshold without knowing the actual
          negotiated capability of both ends); dhcp_leases (lease time
          remaining -- nothing actionable follows from a low value
          alone); arp_table (no verdict attached to the table's mere
          existence); upnp_devices / mdns_devices (a broader device
          inventory, not a fault signal by itself); gateway_traceroute /
          internet_traceroute (both already visible as raw evidence, no
          safe automated verdict about which hop is "the problem");
          per-DNS-server latency (already covered by the existing
          dns_resolution-driven rules, nothing new needed);  dns_cache
          (a cache dump, not a fault); dns_suffix_search_list (no safe
          "wrong" heuristic); wifi_connection.radio_type (802.11
          standard/band by itself isn't a problem, used only as evidence
          inside other findings if ever needed); ipv6_status (too many
          non-guessable dual-stack misconfiguration shapes -- direct
          parallel to v0.8.0's MTU rejection); nat_type (Symmetric NAT
          is sometimes fine, sometimes not, entirely context-dependent,
          no safe verdict); driver_info (no safe "outdated" threshold
          without an internet-connected version database this app
          doesn't have).

          Explicitly out of scope for this batch, not built: a
          gateway-MAC-stability-across-scans (ARP-spoofing-style)
          rule -- it would need cross-scan history, and evaluate(data)
          only ever sees one scan's dict with no previous_scan
          parameter. evaluate()'s signature is untouched. Tracked
          separately, not forgotten.

          Tested with synthetic fixtures per new rule (a triggering case
          and a non-triggering case for each of the rules with real
          logic -- the threshold rules, the correlation rule, and the
          narrow hijack rule got the most scrutiny, per the task's own
          priority) -- see this version's test run for exactly which
          fired against real A1 v0.15.0 output in this sandbox versus
          only synthetic data. Re-ran the full rule set against this
          session's real A1 output as a regression check: all 13
          pre-existing rules produced unchanged output.

  0.8.0 - New rule: check_interface_dns_missing(). A1 v0.14.0 added
          get_interface_network_config() (per-interface DNS servers,
          static/DHCP mode, IP/subnet/gateway, connection name) -- Ammar's
          question, prompted by that addition: does A2 need updating every
          time A1 gains a new discovery function, since A2's whole job is
          to evaluate A1's output? Checked, and the answer here was yes:
          nothing in the existing 12-rule set read
          interface_network_config at all. check_dns_missing() still only
          reads the old flat, whole-machine dns_servers field
          (get_dns_servers()) -- a coarser reading that can say "DNS isn't
          configured anywhere" but never "DNS isn't configured on *this*
          interface," which matters because A4 v0.3.0's
          _set_interface_dns() fix acts per-interface and needs to know
          which one.

          check_interface_dns_missing() is deliberately scoped to
          static-mode interfaces only. DHCP-mode interfaces are skipped on
          purpose: on macOS, networksetup -getdnsservers only shows
          manually-set DNS overrides, never DHCP-provided ones (a real,
          already-flagged A1 limitation) -- an empty reading there doesn't
          mean DNS is actually missing, it means the tool can't see it.
          Static-mode interfaces have no such ambiguity on any platform,
          since DNS is never auto-provided for a static config. Also only
          checks interfaces that are actually up (admin_enabled and
          connected both True), same criterion check_interfaces() already
          uses.

          Considered a matching rule for interfaces[].mtu (also unread by
          any existing rule) and deliberately did not add one -- there's
          no safe heuristic for "wrong" MTU (VPNs, jumbo frames, and other
          legitimate setups use non-1500 values), and guessing wrong here
          risks exactly the kind of confidently-wrong finding this
          codebase has caught and fixed elsewhere (A2 v0.2.0's severity-
          scaling fix, A1's UPnP sanity notes). fix_classification is left
          at the existing default (FIX_GUIDED) for this new rule -- not
          touching the fact that A2 never actually uses FIX_AUTO anywhere
          today, which is a separate, unresolved question from this one.

          Tested with synthetic data: a static-mode, up interface with no
          DNS servers fires; a DHCP-mode, up interface with no DNS servers
          does not (guards the macOS blind spot); a down/disabled
          interface does not. Re-ran against this session's real A1
          output as a regression check -- existing 12 rules unaffected.

  0.7.2 - Same class of bug as A1 v0.13.1, found in the same debugging
          session: `a6 = _import_a6()` and `cache.get_scans(...)` both
          sat outside real exception handling. _import_a6() can raise
          (ImportError if 'cryptography' isn't installed -- A6's own
          module-level import fails the instant it's loaded) and so
          can get_scans() (CacheError on a wrong key or a tampered
          database). Either one crashed A2 with a raw traceback instead
          of the clean "--cache: ..." message this was supposed to
          show.

          Rewrote the --cache branch so _import_a6(), A6Cache(), and
          get_scans() are all inside one try -- cache is deliberately
          left open (not closed) on the success path so write_findings()
          can still use it further down, and only gets closed on each
          early-failure return.

          Reproduced the original bug first (shadowing 'cryptography'
          with a stub module that raises ImportError, then running
          --cache as a real subprocess) to confirm the crash before the
          fix, and the clean message after. Re-confirmed the full
          --cache pipeline (A1 write -> A2 read+evaluate+write-back),
          --input/--json, piped stdin, and the v0.7.1 no-args-on-a-tty
          fix all still work unchanged.

  0.7.1 - Fixed a real bug Ammar hit testing v0.13.0/v0.7.0's new --cache
          wiring: running A2 with no --input, no --cache, and nothing
          piped into it looked like a dead, black cmd window -- no
          crash, no message, just silence. The cause: `_load_input()`
          falls back to `sys.stdin.read()` when --input isn't given,
          and on a real interactive terminal with nothing piped in,
          that call blocks forever waiting for input that's never
          coming (Ctrl+Z/Ctrl+D on Windows/Unix). That's not a hang
          bug so much as a silent-failure bug wearing a hang's
          clothes -- the exact shape of bug this codebase has fixed
          everywhere else (A1's Wi-Fi scan in v0.2.0, DNS/interface
          detection in v0.4.0): something goes wrong with zero
          indication anything is happening at all.

          `_load_input()` now checks `sys.stdin.isatty()` before
          reading: if stdin is a live terminal (not a pipe or
          redirect) and neither --input nor --cache was given, it
          raises a new NoInputError with a plain-language message
          telling you what to pass instead of blocking silently.
          Piping a real scan into stdin (`cat scan.json | a2 ...`) is
          unaffected -- isatty() is false in that case, so the normal
          read still happens.

          Verified in this sandbox with a real pty (a plain subprocess
          pipe doesn't reproduce isatty()==True, needed pty.spawn() to
          actually simulate an interactive terminal with nothing
          piped in): confirmed the old behavior hung with zero output,
          confirmed this version prints the message and exits
          immediately instead. Re-confirmed --input, --cache, and
          piped stdin (cat scan.json | ...) all still work unchanged.

  0.7.0 - Wires A2 into A6 (Encrypted Local Cache) directly -- the other
          half of the "small plumbing change" CLAUDE.md flagged once A6
          existed (A1 v0.13.0 got its half first). New `--cache` flag:
          instead of `--input scan.json`, reads the most recent scan
          straight out of A6 (or a specific one via `--cache-scan-id`),
          runs the same `evaluate()` unchanged, and writes findings back
          into A6 via `write_findings()` linked to that scan's id,
          instead of only a JSON file. `--input`/`--json` still work
          exactly as before and are unaffected when `--cache` isn't
          passed -- this is additive, not a replacement.

          Same dynamic-import trick A1 v0.13.0 uses for the same reason:
          `_import_a6()` globs for `a6_encrypted_cache_v*.py` next to
          this file rather than hardcoding a version, so A6 can keep
          bumping its own filename with zero changes needed here --
          matching the existing reasoning A2 already applies to *not*
          importing A1 directly. `cryptography` (A6's dependency) is
          only imported lazily inside `_import_a6()`, only when
          `--cache` is used, so A2 itself stays standard-library-only
          otherwise.

          Verified: ran A1 v0.13.0 --cache against this sandbox's
          network, then A2 --cache with no --input at all, confirmed it
          picked up that exact scan from A6, evaluated it, and wrote the
          resulting finding back into A6 linked to the right scan id.

  0.6.0 - A1 v0.12.0 added a new "ALL" service to check_firewall_rules()
          for a rule that blocks everything (no protocol/port
          restriction, a chain/profile default-deny, or on Windows a
          rule with Protocol=Any/RemotePort=Any -- Ammar's specific
          example). check_firewall_blocking() gets a matching branch:
          fires if *any* of the four existing broken conditions is
          true, not just its one specific symptom like the other
          services -- a blanket rule is consistent with all of them at
          once, so it shouldn't need to match one narrowly. Whichever
          symptom is actually present is what the finding names.
          Tested against a real bare `-j DROP` rule and a real chain
          default policy of DROP in this sandbox (both now produce a
          critical finding); confirmed the five prior per-service
          detections are unaffected.
  0.5.0 - A1 v0.11.0 widened check_firewall_rules() from DNS/ICMP-only to
          a small named set of connectivity-relevant ports (DNS, HTTP,
          HTTPS, DHCP client/server). check_firewall_blocking() rewritten
          to match: instead of one "DNS broken OR internet broken" gate
          for every rule, each service now correlates against the
          specific symptom it would actually cause -- DNS against
          check_dns_not_resolving's own trigger, HTTPS against
          check_internet_reachability's (its test is a TCP connect to
          port 443 specifically, a direct match), ICMP against
          check_gateway_latency's 100%-loss trigger (ICMP is what ping
          uses -- a blocked ICMP rule shows up as an unreachable gateway,
          not a generic "no internet"), DHCP against
          check_gateway_missing's (no DHCP means no IP/gateway/DNS server
          in the first place). HTTP (port 80) is gathered by A1 but
          deliberately never correlated -- no existing A1 check tests
          port 80, so there's no symptom to attach it to; a known,
          stated gap rather than a guessed-at one.

          This replaces the old blanket gate specifically because it was
          imprecise: the original design would have credited an ICMP
          block for "the internet is unreachable" even though A1's own
          reachability test doesn't use ICMP at all (TCP connect only,
          see check_internet_reachability()) -- a real rule blocking
          ping could sit there unconnected to the actual cause of an
          outage. Tested against all four now-correlated services (DNS,
          HTTPS, ICMP, DHCP) with matching and non-matching connectivity
          contexts, confirming each only fires against its real symptom.
  0.4.0 - A1 v0.10.0 added check_firewall_rules() -- the actual local
          firewall ruleset, filtered down to rules that block DNS (port
          53) or ICMP. Added check_firewall_blocking(): correlates that
          against the connectivity findings other rules already compute
          (DNS not resolving, internet unreachable) and, when a matching
          rule exists, produces a specific "this firewall rule is likely
          why" finding instead of leaving the customer with just a bare
          "DNS isn't resolving." This is exactly the A1-gathers/A2-
          decides split CLAUDE.md already draws for every module: A1's
          check_firewall_rules() reports facts with no verdict attached,
          A2 is what turns "a matching rule exists" + "DNS is actually
          broken" into an actual diagnosis. Severity matches whatever
          it's explaining (critical if the internet itself is
          unreachable, warning if only DNS is) rather than introducing a
          third severity scale. One finding per matching rule, using the
          rule's own name/description as the finding's target, so
          finding_id stays stable and distinct per rule across scans.
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
    python3 network_discovery_v0.15.0.py --json scan.json
    python3 a2_rule_engine_v0.9.0.py --input scan.json

Note: this has to be a two-step, file-based handoff, not a direct pipe.
A1's `--json` with no path still prints its normal plain-language output
to stdout first and *then* appends the JSON -- piping that straight into
A2 hands it a mix of prose and JSON, not valid JSON on its own. Always
give A1 a real path (`--json scan.json`) when the output is meant for A2.

Dump findings as JSON instead of/alongside the plain-language printout:
    python3 a2_rule_engine_v0.9.0.py --input scan.json --json findings.json

Or skip the JSON file entirely and read/write straight through A6:
    python3 network_discovery_v0.15.0.py --cache
    python3 a2_rule_engine_v0.9.0.py --cache
"""

import argparse
import hashlib
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone


def _import_a6():
    """
    Dynamically loads whichever a6_encrypted_cache_v*.py sits next to this
    file, picking the highest (major, minor, patch) version present --
    same reasoning A2 already uses to avoid hardcoding A1's version: A6
    can keep bumping its own filename with zero changes needed here.
    Returns None if no A6 file is found (--cache then reports that
    clearly instead of crashing).
    """
    import glob
    import importlib.util
    import re as _re

    here = os.path.dirname(os.path.abspath(__file__))
    candidates = glob.glob(os.path.join(here, "a6_encrypted_cache_v*.py"))
    if not candidates:
        return None

    def _version_key(path):
        m = _re.search(r"_v(\d+)\.(\d+)\.(\d+)\.py$", path)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    path = max(candidates, key=_version_key)
    spec = importlib.util.spec_from_file_location("a6_encrypted_cache", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

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


def check_interface_dns_missing(data):
    """
    Per-interface version of check_dns_missing(), using A1 v0.14.0's
    interface_network_config (not the old flat dns_servers) so the finding
    can name which interface needs fixing -- A4's _set_interface_dns() acts
    per-interface and needs that target.

    Only fires for interfaces in static IP mode. DHCP-mode interfaces are
    deliberately skipped: on macOS, networksetup -getdnsservers only shows
    manually-set DNS overrides, never DHCP-provided ones (a real, flagged
    A1 limitation) -- an empty reading there doesn't mean DNS is actually
    missing, it means the tool can't see it. Static-mode interfaces don't
    have that ambiguity anywhere: DNS is never auto-provided for a static
    config, so an empty list is unambiguous evidence on all 3 platforms.

    Only checks interfaces that are actually up (admin_enabled and
    connected both True) -- same "up interface" criteria check_interfaces()
    already uses, since a down interface's DNS config isn't relevant to
    anything right now.
    """
    findings = []
    net_config = data.get("interface_network_config") or {}
    by_name = {i.get("name"): i for i in (data.get("interfaces") or [])}
    for name, cfg in net_config.items():
        iface = by_name.get(name) or {}
        if iface.get("admin_enabled") is not True or iface.get("connected") is not True:
            continue
        if cfg.get("ip_assignment_mode") != "static":
            continue
        if cfg.get("dns_servers"):
            continue
        findings.append(make_finding(
            rule_id="interface_dns_missing", category="dhcp", severity=SEV_WARNING,
            target=name,
            summary=f"Network adapter '{name}' is set to a static IP but has no DNS server configured.",
            detail=str(cfg), fix_classification=FIX_GUIDED,
            evidence={"interface_network_config": cfg, "interface": iface},
        ))
    return findings


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

    fix_classification is FIX_AUTO as of v0.9.0 (was FIX_GUIDED) -- see
    that version's changelog entry for the reasoning (A4 v0.4.0's
    flush_dns_cache() backs this up; a cache flush is judged safe and
    reversible, unlike this file's other guided fixes). The trigger
    condition itself is unchanged from v0.3.0.
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
            detail=str(dns_res), fix_classification=FIX_AUTO,
            evidence={"dns_resolution": dns_res, "internet": internet},
        )]
    return []


# ---------------------------------------------------------------------
# v0.9.0 rules -- wired up to the ~21 new A1 v0.15.0 discovery fields.
# See this version's CHANGELOG entry above for the full per-rule
# reasoning; each docstring below covers just what's specific to that
# rule.
# ---------------------------------------------------------------------

def check_rogue_dhcp(data):
    """
    Fires when A1's detect_rogue_dhcp_servers() (needs root to bind UDP
    port 68) saw more than one distinct DHCP server answer a broadcast
    DHCPDISCOVER -- a second/unexpected DHCP server on the LAN, a classic
    hard-to-diagnose fault (a misconfigured switch bridging two networks,
    a consumer router plugged in downstream with its own DHCP still on,
    or genuine rogue DHCP). target="network" -- this is a network-wide
    fact, not attributable to one interface.
    """
    rogue = data.get("rogue_dhcp_servers") or {}
    count = rogue.get("count", 0)
    if count is not None and count > 1:
        servers = ", ".join(rogue.get("responding_servers") or []) or "unknown addresses"
        return [make_finding(
            rule_id="rogue_dhcp_servers", category="dhcp", severity=SEV_CRITICAL,
            target="network",
            summary=(f"More than one device on your network is trying to hand out IP addresses "
                     f"({count} DHCP servers responded: {servers}) -- this usually means a second "
                     "router or a misconfigured device is plugged in, and can cause random, "
                     "intermittent connection problems."),
            detail=str(rogue), fix_classification=FIX_GUIDED,
            evidence={"rogue_dhcp_servers": rogue},
        )]
    return []


def check_duplicate_ip(data):
    """
    One finding per conflicting IP in A1's best-effort duplicate_ip.
    conflicts (a MAC address change on the same IP between two ARP-table
    reads a few seconds apart -- A1's own docstring is explicit this is
    best-effort, not a guarantee, and this rule doesn't overstate it
    either). target is the conflicting IP itself, since that's the
    stable identity a later scan would re-detect against -- neither MAC
    alone identifies "the same problem" the way the IP does here.
    """
    findings = []
    dup = data.get("duplicate_ip") or {}
    for conflict in dup.get("conflicts") or []:
        ip = conflict.get("ip", "unknown")
        findings.append(make_finding(
            rule_id="duplicate_ip", category="lan", severity=SEV_WARNING,
            target=ip,
            summary=(f"{ip} appears to have been used by more than one device on your network "
                     "recently -- this can cause one or both devices to drop off the network "
                     "intermittently."),
            detail=str(conflict), fix_classification=FIX_GUIDED,
            evidence={"conflict": conflict, "note": dup.get("note")},
        ))
    return findings


def check_multiple_default_routes(data):
    """
    Fires when more than one family="ipv4" route in A1's routing_table
    matches a default-route destination (Linux/macOS "default", Windows
    "0.0.0.0" -- see the confirmed field shapes this version was built
    against). severity is warning, not critical, and
    fix_classification is FIX_NONE: editing a routing table blind is too
    risky for this app to guide a non-technical customer through, but
    "something set up two default routes" is still a real, worth-
    surfacing fact.
    """
    routes = data.get("routing_table") or []
    defaults = [
        r for r in routes
        if r.get("family") == "ipv4" and r.get("destination") in ("default", "0.0.0.0", "0.0.0.0/0")
    ]
    if len(defaults) > 1:
        return [make_finding(
            rule_id="multiple_default_routes", category="lan", severity=SEV_WARNING,
            target="network",
            summary=(f"This machine has {len(defaults)} default routes configured at once -- "
                     "usually caused by more than one active network connection (e.g. Wi-Fi and "
                     "Ethernet both configured with a gateway), which can cause unpredictable "
                     "routing."),
            detail=str(defaults), fix_classification=FIX_NONE,
            evidence={"routing_table": defaults},
        )]
    return []


# Hostnames this app's own other checks already depend on and can name
# with certainty -- see check_hosts_file_hijack() below for why the
# watchlist is kept this narrow rather than a general "known good
# sites" list.
_HOSTS_HIJACK_WATCHLIST = {
    "example.com",                     # A1's _DNS_TEST_HOSTNAME, confirmed by reading A1's source
    "connectivitycheck.gstatic.com",   # A1's captive-portal check host
    "speed.cloudflare.com",            # A1's throughput check host
}


def _is_loopback_or_unspecified(ip_str):
    """True for 127.0.0.1/::1 (loopback) or 0.0.0.0/:: (unspecified) --
    both are the common, legitimate shape of a customer's own ad-block
    hosts file entry, not a hijack redirect."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_unspecified


def check_hosts_file_hijack(data):
    """
    Deliberately narrow, on purpose: this does NOT flag "any suspicious
    hosts entry." It only checks active (not commented-out) hosts-file
    entries against a small, fixed watchlist of hostnames this app's own
    other checks already depend on and can name with certainty (see
    _HOSTS_HIJACK_WATCHLIST) -- example.com (A1's DNS-resolution test
    hostname), connectivitycheck.gstatic.com (the captive-portal check's
    host), and speed.cloudflare.com (the throughput check's host).

    A matching entry only fires if its redirect target is a real,
    non-loopback, non-unspecified IP. 127.0.0.1/0.0.0.0/::1/:: targets
    are excluded on purpose -- that's the standard, legitimate shape of
    a customer's own ad-blocking hosts file (or a leftover from a
    previous fix), not hijacking, and this app has no internet-connected
    reputation service to distinguish a real hijack from a legitimate
    block list any more precisely than that. A broader "any suspicious
    hosts entry" rule was considered and declined for the same reason
    v0.8.0 declined a guessing MTU rule: there's no safe way to draw
    that line without a connectivity-dependent lookup this offline app
    doesn't have.
    """
    findings = []
    for entry in data.get("hosts_file") or []:
        if entry.get("active") is not True:
            continue
        ip = entry.get("ip")
        if not ip or _is_loopback_or_unspecified(ip):
            continue
        for hostname in entry.get("hostnames") or []:
            if hostname not in _HOSTS_HIJACK_WATCHLIST:
                continue
            findings.append(make_finding(
                rule_id="hosts_file_hijack", category="security", severity=SEV_CRITICAL,
                target=hostname,
                summary=(f"Your computer's hosts file redirects '{hostname}' (a site this app "
                         f"uses to test your connection) to {ip} instead of its real address -- "
                         "this can be a sign of malware or a hijacked network configuration."),
                detail=str(entry), fix_classification=FIX_GUIDED,
                evidence={"hosts_file_entry": entry},
            ))
    return findings


def _proxy_active(data):
    """
    Returns True/False when A1's system_proxy_config confidently tells
    us whether a proxy is active, or None when it doesn't. Windows:
    proxy_enabled is a real, A1-normalized bool. Linux: http_proxy or
    https_proxy being set is a real, normalized signal. macOS: A1
    doesn't normalize scutil --proxy's raw key-value dump at all, and
    nothing in A1's source confirms an exact key name for "is a proxy
    on" there (the likely candidate, HTTPEnable, isn't something this
    file's reading of A1 could confirm without real Mac hardware to
    check against) -- so macOS is deliberately treated as insufficient
    data rather than guessed at, returning None. A real, stated gap: a
    Mac with an active proxy won't get this finding until A1 normalizes
    that field the way it already does for Windows and Linux.
    """
    proxy = data.get("system_proxy_config") or {}
    if not proxy:
        return None
    if "proxy_enabled" in proxy:
        return proxy.get("proxy_enabled") is True
    if "http_proxy" in proxy or "https_proxy" in proxy:
        return bool(proxy.get("http_proxy")) or bool(proxy.get("https_proxy"))
    return None


def check_proxy_configured(data):
    """
    Fires when _proxy_active() confidently detects an active system
    proxy (Windows/Linux only -- see _proxy_active()'s docstring for why
    macOS isn't attempted). Severity scales with _connectivity_context(),
    same pattern as check_wifi_radio_off(): a configured proxy isn't
    inherently a problem (plenty of legitimate reasons to run one), so
    it's info when the internet works fine or the check was skipped --
    unlike the interface/radio rules, "unknown" is deliberately treated
    the same as "ok" here, not left at a louder default, because an
    active proxy alone was never alarming in the first place. It's
    upgraded to warning only when the internet is confirmed down, where
    a broken or stale proxy config is a plausible contributing cause
    worth surfacing more clearly.
    """
    if _proxy_active(data) is not True:
        return []
    context = _connectivity_context(data)
    severity = SEV_WARNING if context == "broken" else SEV_INFO
    proxy = data.get("system_proxy_config") or {}
    return [make_finding(
        rule_id="proxy_configured", category="lan", severity=severity,
        target="system_proxy",
        summary=("A system-wide proxy is configured on this machine." +
                  (" Your internet isn't working right now -- if this proxy is stale or "
                   "misconfigured, that could be why." if context == "broken" else "")),
        detail=str(proxy), fix_classification=FIX_GUIDED,
        evidence={"system_proxy_config": proxy, "internet": data.get("internet")},
    )]


def check_vpn_active(data):
    """
    Fires when A1's vpn_interfaces (name-pattern matched against
    get_interface_status()'s output) is non-empty. Same
    _connectivity_context() severity scaling as check_proxy_configured(),
    same reasoning -- a VPN being up isn't itself a problem.
    fix_classification is FIX_NONE: this app has no business touching
    VPN configuration under any circumstance.
    """
    vpns = data.get("vpn_interfaces") or []
    if not vpns:
        return []
    context = _connectivity_context(data)
    severity = SEV_WARNING if context == "broken" else SEV_INFO
    names = ", ".join(v.get("name", "unknown") for v in vpns)
    return [make_finding(
        rule_id="vpn_active", category="lan", severity=severity,
        target="vpn",
        summary=(f"A VPN/tunnel interface is active ({names})." +
                  (" Your internet isn't working right now -- if the VPN is stuck or "
                   "misconfigured, that could be why." if context == "broken" else "")),
        detail=str(vpns), fix_classification=FIX_NONE,
        evidence={"vpn_interfaces": vpns, "internet": data.get("internet")},
    )]


def check_pmtu_blackhole_finding(data):
    """
    Fires when A1's pmtu_check.blackhole_suspected is True. Summary
    explicitly suggests lowering the interface's MTU as a workaround --
    this routes straight to A4's existing _set_interface_mtu() fix from
    v0.3.0, so no new A4 fix category is needed for this rule.
    """
    pmtu = data.get("pmtu_check") or {}
    if pmtu.get("blackhole_suspected") is True:
        return [make_finding(
            rule_id="pmtu_blackhole", category="wan", severity=SEV_WARNING,
            target="pmtu",
            summary=("A network path problem (a 'PMTU blackhole') may be silently dropping some "
                     "of your traffic -- lowering this connection's MTU is usually the workaround."),
            detail=str(pmtu), fix_classification=FIX_GUIDED,
            evidence={"pmtu_check": pmtu},
        )]
    return []


def check_captive_portal_finding(data):
    """
    Fires when A1's captive_portal.portal_detected is True. Severity is
    critical, deliberately higher than most FIX_GUIDED findings in this
    file: a captive portal fully blocks real internet use even though
    internet.reachable can still show True (A1's TCP-connect
    reachability test isn't itself interceptable the way an HTTP request
    is) -- "internet works" and "internet is actually usable" diverge
    here, and a customer stuck behind a login page needs a clear signal,
    not an info note. Summary is plain-language guidance only; there's
    nothing here for A3 to automate.
    """
    portal = data.get("captive_portal") or {}
    if portal.get("portal_detected") is True:
        return [make_finding(
            rule_id="captive_portal", category="wan", severity=SEV_CRITICAL,
            target="captive_portal",
            summary=("This network is showing a login/sign-in page before it will let you "
                     "online -- open a web browser and look for a login page (common on hotel, "
                     "cafe, and guest Wi-Fi networks)."),
            detail=str(portal), fix_classification=FIX_GUIDED,
            evidence={"captive_portal": portal},
        )]
    return []


def check_wifi_weak_signal(data):
    """
    Fires when wifi_connection has both signal_dbm and noise_dbm and
    their difference (signal-to-noise ratio) is under 15dB. 15dB is a
    conservative, commonly-cited "poor" SNR boundary in Wi-Fi
    site-survey guidance (roughly: 25dB+ good, 15-25dB workable, under
    15dB unreliable) -- picked deliberately conservative so this doesn't
    flag a merely mediocre signal as a problem. Purely physical/
    positional and advisory -- nothing in software to fix, hence
    severity=info and fix_classification=FIX_NONE.
    """
    wifi = data.get("wifi_connection") or {}
    signal = wifi.get("signal_dbm")
    noise = wifi.get("noise_dbm")
    if signal is not None and noise is not None:
        snr = signal - noise
        if snr < 15:
            target = wifi.get("ssid") or "wifi"
            return [make_finding(
                rule_id="wifi_weak_signal", category="wifi", severity=SEV_INFO,
                target=target,
                summary=(f"Wi-Fi signal quality is poor ({signal}dBm signal vs {noise}dBm noise, "
                         f"a {snr}dB signal-to-noise ratio) -- try moving closer to the router or "
                         "reducing interference."),
                detail=str(wifi), fix_classification=FIX_NONE,
                evidence={"wifi_connection": wifi},
            )]
    return []


def check_wifi_power_saving_enabled(data):
    """
    Built on check_firewall_blocking()'s "precompute symptom booleans,
    then a targeted dispatch that declines to fire without
    corroboration" pattern. wifi_power_save == "on" (Linux-only field)
    is normal and common by itself -- NOT flagged on its own. This only
    fires when it's paired with an actual symptom: gateway ping loss
    >= 20%, or jitter > 50ms -- the kind of intermittent drops/latency
    power-saving mode is a plausible (not certain) cause of.
    """
    if data.get("wifi_power_save") != "on":
        return []
    lat = data.get("gateway_latency") or {}
    loss = lat.get("loss_percent")
    jitter = lat.get("jitter_ms")
    loss_bad = loss is not None and loss >= 20
    jitter_bad = jitter is not None and jitter > 50
    if not (loss_bad or jitter_bad):
        return []
    if loss_bad and jitter_bad:
        symptom = f"{loss}% packet loss and {jitter}ms of jitter to the router"
    elif loss_bad:
        symptom = f"{loss}% packet loss to the router"
    else:
        symptom = f"{jitter}ms of jitter to the router"
    return [make_finding(
        rule_id="wifi_power_saving_enabled", category="wifi", severity=SEV_WARNING,
        target="wifi_power_save",
        summary=(f"Wi-Fi power-saving mode is on, and this machine is also seeing {symptom} -- "
                 "power saving can cause exactly this kind of intermittent drop/latency, "
                 "especially on older or budget Wi-Fi adapters."),
        detail=str({"wifi_power_save": data.get("wifi_power_save"), "gateway_latency": lat}),
        fix_classification=FIX_GUIDED,
        evidence={"gateway_latency": lat},
    )]


def check_wps_enabled(data):
    """
    Fires per wifi_networks entry with wps_enabled is True (Linux-only
    field from A1's `iw scan` parser -- absent entirely on Windows/
    macOS, read via .get() so it degrades to "no finding" there rather
    than guessing from absence).

    Scoping judgment call: scoped to the network matching
    wifi_connection["ssid"] (the customer's own, currently-connected AP)
    rather than firing for every nearby scanned network. Reasoning:
    fix_classification is FIX_NONE either way (this app has no router
    credentials to act on any of them, consumer or otherwise -- same
    territory as CLAUDE.md's flagged web-UI-scraping decision), so
    flagging a neighbor's router's WPS setting isn't actionable or even
    relevant to this customer -- it would just be noise about hardware
    they don't own. Stated honestly: this means a customer connected via
    Ethernet (wifi_connection["ssid"] is None) whose own Wi-Fi AP is
    still broadcasting WPS won't get this finding today, since there's
    no connected SSID to cross-reference against -- judged an acceptable
    gap against the noisier alternative of flagging every visible
    network's WPS state regardless of whose it is.
    """
    findings = []
    own_ssid = (data.get("wifi_connection") or {}).get("ssid")
    if not own_ssid:
        return findings
    for net in data.get("wifi_networks") or []:
        if net.get("wps_enabled") is not True:
            continue
        ssid = net.get("ssid")
        if ssid != own_ssid:
            continue
        findings.append(make_finding(
            rule_id="wps_enabled", category="security", severity=SEV_WARNING,
            target=ssid,
            summary=(f"Your Wi-Fi network ('{ssid}') has WPS (Wi-Fi Protected Setup) turned on -- "
                     "a known weaker way to connect to a router. Fixing this means logging into "
                     "the router directly and turning WPS off; this app can't do it for you."),
            detail=str(net), fix_classification=FIX_NONE,
            evidence={"wifi_network": net},
        ))
    return findings


def check_clock_not_synced(data):
    """
    Fires when A1's clock_drift.synchronized is explicitly False -- never
    on None, which means the OS-level check itself couldn't determine
    sync status (e.g. macOS needing root for systemsetup), and guessing
    "not synced" from that would be exactly the confidently-wrong shape
    this codebase keeps catching and fixing elsewhere.

    fix_classification is FIX_AUTO -- the first use of FIX_AUTO in this
    codebase, alongside check_dns_not_resolving()'s v0.9.0 upgrade (see
    this version's CHANGELOG entry for the full reasoning). An NTP
    resync is judged safe and reversible with no real user tradeoff,
    unlike every FIX_GUIDED rule in this file. A3 (Fix Engine) doesn't
    exist yet, so today this only labels the data -- nothing actually
    auto-executes from it.
    """
    clock = data.get("clock_drift") or {}
    if clock.get("synchronized") is False:
        return [make_finding(
            rule_id="clock_not_synced", category="lan", severity=SEV_WARNING,
            target="system_clock",
            summary=("This computer's clock is not synchronized with an internet time server -- "
                     "a wrong system clock can cause secure website connections, banking apps, "
                     "and other services to fail in confusing ways."),
            detail=str(clock), fix_classification=FIX_AUTO,
            evidence={"clock_drift": clock},
        )]
    return []


def check_high_jitter(data):
    """
    Fires when gateway_latency.jitter_ms is not None and > 30ms. 30ms
    clears the same bar v0.8.0's MTU rule was rejected on, but in the
    other direction: it's a genuinely standard, widely-cited "noticeable
    for real-time traffic" jitter threshold (VoIP/video-call quality
    guidance consistently puts acceptable jitter well under this), not a
    customer/context-specific value the way MTU is. Purely diagnostic --
    severity=info, fix_classification=FIX_NONE.
    """
    lat = data.get("gateway_latency") or {}
    jitter = lat.get("jitter_ms")
    if jitter is not None and jitter > 30:
        return [make_finding(
            rule_id="gateway_high_jitter", category="lan", severity=SEV_INFO,
            target="gateway_jitter",
            summary=(f"Latency to your router is inconsistent (jitter of {jitter}ms) -- this can "
                     "cause choppy voice/video calls even when your overall connection speed "
                     "looks fine."),
            detail=str(lat), fix_classification=FIX_NONE,
            evidence={"gateway_latency": lat},
        )]
    return []


def check_throughput_critically_low(data):
    """
    Fires when throughput.mbps is not None and < 1.0. Deliberately a
    conservative absolute floor -- "basically not working" regardless of
    what plan the customer is paying for, not a judgment about being
    "slow" relative to an unknown ISP speed tier this app has no way to
    know. fix_classification is FIX_NONE for the same reason: no basis
    to suggest a specific fix beyond "your connection is basically not
    working right now."
    """
    throughput = data.get("throughput") or {}
    mbps = throughput.get("mbps")
    if mbps is not None and mbps < 1.0:
        return [make_finding(
            rule_id="throughput_critically_low", category="wan", severity=SEV_WARNING,
            target="throughput",
            summary=(f"Download speed measured at only {mbps} Mbps -- your internet connection "
                     "is barely working right now, regardless of what speed you're paying for."),
            detail=str(throughput), fix_classification=FIX_NONE,
            evidence={"throughput": throughput},
        )]
    return []


def check_firewall_blocking(data):
    """
    Correlates A1's firewall rule scan against whichever connectivity
    symptom the blocked service would actually explain -- not one
    blanket "something's broken" gate for every service, since a rule
    blocking ICMP shouldn't get blamed for "no internet" when the real
    cause was something else (or vice versa):

      - DNS blocked   -> only fires if DNS itself isn't resolving
        (check_dns_not_resolving's own trigger).
      - HTTPS blocked -> only fires if the internet is confirmed
        unreachable. check_internet_reachability()'s own test is a TCP
        connect to port 443 specifically, so this is a direct match, not
        an inferred one.
      - ICMP blocked  -> only fires if the gateway itself is unreachable
        by ping (check_gateway_latency's 100%-loss trigger) -- ICMP is
        what ping uses, so that's the actual symptom a blocked ICMP rule
        would cause, not a generic "internet unreachable."
      - DHCP blocked  -> only fires if no gateway was found at all
        (check_gateway_missing's own trigger) -- without DHCP a device
        never gets an IP, gateway, or DNS server in the first place, so
        "no gateway" is the real symptom, not "DNS broken" or "internet
        unreachable" downstream of it.
      - HTTP blocked  -> never correlated today. A1 doesn't test port 80
        anywhere, so there's no symptom to attach this to yet -- a known
        gap, not a bug. A1 still gathers it in case a future check needs
        it.
      - ALL blocked   -> fires if *any* of the four conditions above is
        true, not just one. A blanket rule (no protocol/port
        restriction, or a chain/profile default-deny) isn't evidence
        for one specific service -- it's consistent with every symptom
        at once, so it shouldn't need to match a specific one to be
        worth surfacing. Whichever symptom is actually present is what
        the summary names.

    One finding per matching rule; severity matches whatever it's
    explaining rather than a scale of its own.
    """
    suspects = data.get("firewall_rules") or []
    if not suspects:
        return []

    internet = data.get("internet") or {}
    dns_res = data.get("dns_resolution") or {}
    gateway_latency = data.get("gateway_latency") or {}

    dns_broken = internet.get("reachable") is True and dns_res.get("any_working") is False
    internet_broken = internet.get("reachable") is False
    gateway_unreachable = gateway_latency.get("loss_percent") == 100
    gateway_missing = not data.get("gateway")

    findings = []
    for rule in suspects:
        service = rule.get("service", "")
        if service == "DNS":
            if not dns_broken:
                continue
            severity, context = SEV_WARNING, "DNS isn't resolving"
        elif service == "HTTPS":
            if not internet_broken:
                continue
            severity, context = SEV_CRITICAL, "the internet is unreachable"
        elif service == "ICMP":
            if not gateway_unreachable:
                continue
            severity, context = SEV_CRITICAL, "the router isn't responding to pings"
        elif service in ("DHCP (server)", "DHCP (client)"):
            if not gateway_missing:
                continue
            severity, context = SEV_CRITICAL, "no gateway/router could be found"
        elif service == "ALL":
            if gateway_missing:
                context = "no gateway/router could be found"
            elif internet_broken:
                context = "the internet is unreachable"
            elif gateway_unreachable:
                context = "the router isn't responding to pings"
            elif dns_broken:
                context = "DNS isn't resolving"
            else:
                continue
            severity = SEV_CRITICAL
        else:
            # HTTP and anything else A1 gathers but has no correlated
            # symptom for yet -- not flagged, to avoid false attribution.
            continue

        summary_service = "all outbound traffic" if service == "ALL" else service
        findings.append(make_finding(
            rule_id="firewall_blocking_connectivity", category="security", severity=severity,
            target=rule.get("name", "firewall rule"),
            summary=(f"A local firewall rule ({rule.get('name', 'unnamed')}) blocks {summary_service} "
                     f"-- likely why {context}."),
            detail=str(rule), fix_classification=FIX_GUIDED,
            evidence={"firewall_rule": rule, "internet": internet, "dns_resolution": dns_res,
                      "gateway_latency": gateway_latency, "gateway": data.get("gateway")},
        ))
    return findings


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
    check_interface_dns_missing,
    check_dns_not_resolving,
    check_firewall_blocking,
    # -- v0.9.0 additions below --
    check_rogue_dhcp,
    check_duplicate_ip,
    check_multiple_default_routes,
    check_hosts_file_hijack,
    check_proxy_configured,
    check_vpn_active,
    check_pmtu_blackhole_finding,
    check_captive_portal_finding,
    check_wifi_weak_signal,
    check_wifi_power_saving_enabled,
    check_wps_enabled,
    check_clock_not_synced,
    check_high_jitter,
    check_throughput_critically_low,
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


class NoInputError(Exception):
    """Raised when neither --input, --cache, nor piped stdin was given."""


def _load_input(path):
    if path in (None, "-"):
        if path is None and sys.stdin.isatty():
            # Reading stdin here would just block forever with zero output on
            # screen -- indistinguishable from a hang/black screen to anyone
            # running this without piping something in. Report it instead.
            raise NoInputError(
                "No --input file given, --cache not used, and nothing is piped in. "
                "Run with --input scan.json, --cache (to read from A6 instead), or "
                "pipe a scan's JSON into stdin."
            )
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
                         help="Path to A1's --json output. Omit to read from stdin. Ignored if --cache is given.")
    parser.add_argument("--json", nargs="?", const="-", default=None,
                         help="Export findings as JSON. Give a path to write to a file, "
                              "or omit the path to print JSON to stdout.")
    parser.add_argument("--cache", action="store_true",
                         help="Read the scan straight from A6 (Encrypted Local Cache) instead of --input, and "
                              "write findings back into A6 linked to that scan. Needs a6_encrypted_cache_v*.py "
                              "next to this file and the 'cryptography' package.")
    parser.add_argument("--cache-db", default=None,
                         help="A6 database path (default: A6's own default, network_cache.db)")
    parser.add_argument("--cache-key", default=None,
                         help="A6 key file path (default: A6's own default, network_cache.key)")
    parser.add_argument("--cache-scan-id", type=int, default=None,
                         help="With --cache, evaluate this specific A6 scan id instead of the most recent one")
    args = parser.parse_args()

    cache = None
    scan_id = None
    if args.cache:
        # _import_a6() and get_scans() can both raise (ImportError if
        # 'cryptography' isn't installed -- A6's own module-level import
        # fails the instant we try to load it; CacheError on a wrong key or
        # a tampered database). Both have to be inside this try, not just
        # A6Cache(**kwargs) -- otherwise either one is unhandled and crashes
        # with a raw traceback instead of the clean message this is meant to
        # give. cache is deliberately NOT closed here on the success path --
        # it stays open so write_findings() can use it further down, and
        # gets closed there (or right here, on any early failure exit).
        cache = None
        try:
            a6 = _import_a6()
            if a6 is None:
                print("--cache: no a6_encrypted_cache_v*.py found next to this file -- nothing to read.",
                      file=sys.stderr)
                return 1

            kwargs = {}
            if args.cache_db:
                kwargs["db_path"] = args.cache_db
            if args.cache_key:
                kwargs["key_path"] = args.cache_key
            cache = a6.A6Cache(**kwargs)

            # A6 v0.1.0 has no get-scan-by-id lookup, only get_scans(limit=N)
            # sorted newest-first -- fine for a local single-user cache,
            # flagged as a known gap to revisit if scan volume ever makes
            # this worth adding to A6 itself.
            scans = cache.get_scans(limit=10_000 if args.cache_scan_id is not None else 1)
            if args.cache_scan_id is not None:
                scans = [s for s in scans if s["id"] == args.cache_scan_id]
            if not scans:
                what = f"scan id {args.cache_scan_id}" if args.cache_scan_id is not None else "any scans"
                print(f"--cache: A6 has no {what} -- run A1 with --cache first.", file=sys.stderr)
                cache.close()
                return 1
            scan = scans[0]
            scan_id = scan["id"]
            data = scan["discovery"]
        except ImportError as e:
            print(f"--cache: {e}", file=sys.stderr)
            if cache is not None:
                cache.close()
            return 1
        except Exception as e:
            print(f"--cache: {e}", file=sys.stderr)
            if cache is not None:
                cache.close()
            return 1
    else:
        try:
            data = _load_input(args.input)
        except NoInputError as e:
            print(f"{e}", file=sys.stderr)
            return 1
        except FileNotFoundError:
            print(f"Input file not found: {args.input}", file=sys.stderr)
            return 1
        except json.JSONDecodeError as e:
            print(f"Input was not valid JSON: {e}", file=sys.stderr)
            return 1

    findings, errors = evaluate(data)
    _print_findings(findings, errors)

    if cache is not None:
        try:
            n = cache.write_findings(findings, scan_id=scan_id)
            print(f"\nCached {n} finding(s) into A6, linked to scan id {scan_id}")
        except Exception as e:
            print(f"\n! --cache: failed to write findings back to A6: {e}", file=sys.stderr)
        finally:
            cache.close()

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
