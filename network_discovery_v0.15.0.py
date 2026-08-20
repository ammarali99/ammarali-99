#!/usr/bin/env python3
"""
network_discovery.py -- Module A1 (Discovery) of the offline network
diagnostic app.

VERSION: 0.15.0
CHANGELOG:
  0.15.0 - A large batch of new discovery functions, grouped by area.
          This is the biggest single version bump in A1 so far --
          summarized by group below, with per-platform notes and what's
          actually been run for real in this sandbox versus reviewed
          logic/command-construction only.

          Layer 2 / topology: get_interface_link_info() (per-interface
          speed/duplex -- Linux reads /sys/class/net/<iface>/speed and
          .../duplex directly, same "prefer a stable file read over a
          CLI tool" precedent get_arp_table() already set with
          /proc/net/arp, falling back to `ethtool` on a /sys read
          failure; macOS parses `ifconfig`'s media: line; Windows uses
          `wmic nic ... get Name,Speed` for speed only -- wmic is
          deprecated and being phased out of newer Windows, flagged the
          same way every other fragile-tool choice in this file is
          flagged, and duplex is deliberately NOT attempted on Windows
          at all, matching this file's existing precedent of declining
          to guess at the real Airplane Mode flag rather than ship a
          confidently-wrong reading). get_windows_ipconfig_extra()
          (Windows-only, one ipconfig /all pass shared by
          get_dhcp_lease_info(), get_dns_suffix_search_list(), and
          get_ipv6_status() -- same "one pass over ipconfig /all"
          principle get_interface_network_config() established in
          v0.14.0, applied to a different slice of the same output so
          those three functions don't each shell out separately;
          returns empty data with no error on non-Windows, since each
          of those three has its own real per-platform implementation
          there instead). get_dhcp_lease_info() (dhcp_server plus
          lease_obtained/lease_expires on Windows/macOS, or
          lease_time_seconds on Linux -- nmcli's DHCP4.OPTION only
          exposes a lease *duration*, not absolute timestamps, a real
          difference in what the tool reports rather than a parsing
          gap; Linux returns "unknown" per interface when nmcli doesn't
          manage it, same convention get_ip_assignment_mode() already
          uses). detect_rogue_dhcp_servers() (hand-built DHCPDISCOVER
          per RFC 2131 -- a UDP payload via SOCK_DGRAM, not a raw
          socket -- broadcast to 255.255.255.255:67 from a socket bound
          to port 68, collecting DHCPOFFER replies for a short window;
          needs root/admin to bind port 68 on Linux/macOS, caught and
          explained the same way check_firewall_rules() already
          explains its own root requirement; Windows' behavior here is
          untested, not confirmed either way). detect_duplicate_ip()
          (best-effort only, stated explicitly in its own docstring and
          returned "note" -- compares an ARP-table read taken right
          before the ping sweep against one taken right after, flagging
          any IP whose MAC changed in between, plus a best-effort Linux
          dmesg grep for "duplicate address detected"). The ARP table
          get_arp_table() already computed internally is now also
          surfaced directly as "arp_table" in run_discovery()'s output
          -- it was only ever used for cross-referencing before.
          discover_upnp_devices() generalizes the existing
          _ssdp_discover()/_fetch_igd_xml() (the latter renamed
          _fetch_device_description_xml() to reflect that it was
          already generic) to collect every SSDP responder on the LAN,
          not just the gateway's IGD service -- _ssdp_discover() gained
          a search_target parameter (default unchanged) so
          query_upnp_gateway()'s existing behavior is untouched.
          discover_mdns_devices() sends an mDNS PTR query for
          _services._dns-sd._udp.local to 224.0.0.251:5353 and parses
          real resource records out of the replies (_decode_dns_name()/
          _parse_mdns_answers() -- a full RR walk with DNS name
          decompression, well beyond _parse_dns_response()'s 12-byte
          header-only check, since mDNS responses actually carry PTR/
          TXT/A/SRV records worth reading); a response that can't be
          parsed still reports its raw IP with a note in errors, rather
          than being dropped or guessed at.

          Routing: get_routing_table() (`netsh interface ipv4/ipv6 show
          route` / `ip route show` / `netstat -rn -f inet` -- each
          platform's own route dict shape, not forced into one uniform
          schema none of the three naturally produce).
          traceroute_to_gateway() and traceroute_to_internet() both
          shell out to the OS tracert/traceroute binary and regex hop
          lines, the same template check_gateway_latency() already uses
          for `ping` -- no raw ICMP built anywhere. Linux falls back to
          `tracepath` if `traceroute` itself isn't installed (not every
          minimal distro ships it). traceroute_to_gateway() is LAN-only
          and always runs, unguarded by any flag, same precedent as
          check_gateway_latency(); traceroute_to_internet() is A1's
          THIRD deliberate exception to "only A7 touches the internet"
          (after check_internet_reachability() and
          check_dns_resolution() -- see CLAUDE.md's Architecture
          section), with its own --no-traceroute flag.

          DNS (deeper): read_hosts_file() (plain open()/parse of the OS
          hosts file, zero subprocess calls -- runs unconditionally
          every scan, not gated by any flag, since A4 needs it as a
          diff baseline; a commented-out but otherwise hosts-shaped line
          is captured with active=False rather than dropped, since a
          customer's commented-out entry is itself diagnostic
          information). dump_dns_cache() (Windows: `ipconfig
          /displaydns`, a real per-entry dump; Linux: `resolvectl
          statistics` -- explicitly flagged as aggregate hit/miss/
          cache-size counters, NOT a real per-name dump, so it can't be
          mistaken for one; macOS: no clean non-root method exists at
          all, stated as a flat gap -- same class of decision as this
          file's already-documented removal of macOS Wi-Fi nearby-scan
          support). get_dns_suffix_search_list() (Windows via
          get_windows_ipconfig_extra(); Linux reads /etc/resolv.conf's
          search/domain line directly; macOS reuses `scutil --dns` --
          the same tool get_dns_servers() already uses as its macOS
          fallback -- rather than enumerating every service via
          `networksetup -getsearchdomains`). Per-DNS-server latency was
          NOT added as a new function -- check_dns_resolution() already
          returns per-server latency_ms in servers_tested, so this item
          from the spec was already satisfied by existing data.

          Proxy / VPN / interception: get_system_proxy_config() (runs
          unconditionally every scan, same reasoning as
          read_hosts_file(); Windows reads the registry directly via
          the stdlib `winreg` module -- imported lazily inside `if
          SYSTEM == "Windows":` so the module still loads cleanly on
          Linux/macOS -- a deliberate departure from this file's usual
          shell-out-and-regex style, flagged in-line as the right tool
          for a direct registry read, not a style violation; Linux
          reads http_proxy/https_proxy/no_proxy env vars in both
          casings plus a best-effort `gsettings` read; macOS parses
          `scutil --proxy`). detect_vpn_adapters() classifies
          get_interface_status()'s existing interface list by name
          pattern (tap/tun/vpn/wintun/wireguard on Windows; tun/tap/wg\\d
          on Linux; utun\\d on macOS) -- not a new OS query at all.
          check_pmtu_blackhole() (A1's FOURTH internet exception, own
          --no-pmtu flag) pings a size ladder (1400/1450/1472/1500
          bytes, straddling the standard ~1500-byte Ethernet MTU
          boundary) with the DF bit set via the OS ping binary's native
          flags, looking for a smaller size succeeding while a larger
          one times out with no explicit ICMP Fragmentation-Needed
          message -- that silence is the blackhole signature, versus an
          explicit rejection. check_captive_portal() (A1's FIFTH
          internet exception, own --no-captive-portal flag) does a
          plain HTTP GET (deliberately HTTP, not HTTPS -- that's what
          captive portals actually intercept) to
          http://connectivitycheck.gstatic.com/generate_204, Android's
          own captive-portal-detection endpoint -- anything other than
          an empty HTTP 204 means something intercepted the request.

          Wi-Fi (deeper): get_wifi_connection_details() -- link rate/
          signal/noise/802.11 standard for the CURRENTLY ASSOCIATED
          network only, deliberately separate from scan_wifi_networks()
          (which describes every nearby SSID a scan found, none of
          which carry live link-quality data for networks we're not
          connected to). Windows reuses the existing `netsh wlan show
          interfaces` call via a new shared
          _windows_wlan_show_interfaces_raw() helper instead of
          shelling out a second time for data get_wifi_radio_state()
          already fetches -- get_wifi_radio_state() itself was updated
          to use the same helper, no behavior change. Linux uses `iw
          dev <iface> link` plus `iw dev <iface> survey dump` for noise
          (driver-dependent -- many mac80211 drivers don't report it at
          all, in which case noise_dbm just stays None, not an error).
          macOS uses `system_profiler SPAirPortDataType`, the richest of
          the three platforms here. WPS-enabled detection was added to
          _scan_wifi_iw()'s per-network dicts ONLY (via the WPS
          information element in `iw scan` output) -- the other four
          _scan_wifi_* parsers (_scan_wifi_windows, _scan_wifi_nmcli,
          _scan_wifi_iwlist, _scan_wifi_macos) deliberately leave
          wps_enabled absent rather than guess, each with a one-line
          comment explaining why: none of those scan tools expose WPS
          status cleanly. get_wifi_power_management() is Linux-only by
          explicit product decision (`iw dev <iface> get power_save`,
          clean and root-free) -- Windows/macOS both return an explicit
          error explaining the platform gap instead of a guess (same
          class of decision as the declined Windows Airplane Mode read
          and the declined Windows link duplex read above). Runs
          unconditionally when SYSTEM == "Linux", not gated by a flag,
          since A4's new Linux-only diff category needs a baseline
          every scan.

          IPv6: get_ipv6_status() -- per-interface address(es), a
          default gateway if present, DNS servers, and a pure-logic
          stack_type classification ("dual_stack"/"ipv4_only"/
          "ipv6_only") computed from what this function gathered plus
          an ipv4_present flag the caller already knows by the time
          this runs, rather than a second independent IPv4 check.
          Windows via get_windows_ipconfig_extra(); Linux via `ip -6
          addr show` / `ip -6 route show default` / `nmcli -t -f
          IP6.DNS device show`; macOS via `ifconfig`'s inet6 lines plus
          `networksetup -getinfo` for the configuration mode.

          Time: check_clock_drift() reads each OS's own already-
          computed sync status (`w32tm /query /status` / `timedatectl
          show` + optional `chronyc tracking` / `systemsetup
          -getusingnetworktime`) -- deliberately NOT an independent live
          NTP query, which would have been an unapproved SIXTH internet
          exception beyond the five actually approved for this batch.
          The returned "note" states plainly that this can't detect
          real drift if the machine's own NTP client is itself stopped
          or broken.

          Quality: check_gateway_latency() now also returns jitter_ms
          (RFC 3550-style mean absolute difference between consecutive
          RTT samples) -- a pure enhancement to data it was already
          collecting internally and discarding, zero new subprocess
          calls, not a new function. measure_throughput() (A1's SIXTH
          internet exception, own --no-throughput flag) downloads a
          fixed 2,000,000-byte (2 MB) payload from
          https://speed.cloudflare.com/__down?bytes=2000000 -- a real
          public Cloudflare endpoint built for exactly this -- via
          stdlib urllib, timing it with time.monotonic() to compute
          Mbps, with a 15-second timeout so a genuinely broken
          connection can't hang the whole scan. check_nat_type() (A1's
          SEVENTH internet exception, own --no-nat-type flag) hand-
          builds a minimal RFC 5389 STUN Binding Request (same hand-
          built-packet-over-UDP pattern as check_dns_resolution()'s DNS
          query) against the public stun.l.google.com:19302, parsing
          XOR-MAPPED-ADDRESS (falling back to MAPPED-ADDRESS) to learn
          this machine's own public IP:port. Also queries a second
          public STUN server (stun1.l.google.com:19302) and compares
          the returned external port for a COARSE nat_type_guess (same
          port from both suggests Cone-type NAT; a different port
          suggests Symmetric) -- explicitly flagged in the docstring as
          a heuristic, not the full RFC 3489 NAT-type classification
          algorithm, which needs more servers/ports than this attempts.

          Host-level: get_driver_info() -- Linux via `ethtool -i
          <iface>` (clean, direct) plus a best-effort `modinfo` follow-
          up for a vermagic field; Windows via `wmic path
          win32_pnpsigneddriver ...` (wmic deprecation flagged the same
          way get_interface_link_info() flags its own wmic use); macOS
          via `system_profiler SPNetworkDataType`, genuinely thinner
          than the other two platforms since macOS has no equivalent to
          ethtool/wmic for this, stated as such rather than padded out.

          CLI: seven new flags, one per LAN-broadcast/multicast
          function and one per new internet exception, each
          independently skippable rather than folded into --no-internet
          or --no-upnp: --no-dhcp-probe, --no-mdns, --no-traceroute
          (gates traceroute_to_internet() only -- traceroute_to_gateway()
          is LAN-only and always runs), --no-pmtu, --no-captive-portal,
          --no-throughput, --no-nat-type. discover_upnp_devices() reuses
          the existing --no-upnp flag (same SSDP/LAN-multicast class as
          query_upnp_gateway()) rather than getting its own.
          read_hosts_file(), get_system_proxy_config(), and (on Linux)
          get_wifi_power_management() run unconditionally every scan,
          matching the spec's explicit call that A4 needs these as an
          always-present baseline, not an optional extra.

          run_discovery(): all new data keys are appended after the
          existing "upnp_errors" key, before the closing brace, per this
          file's established convention -- the original keys are
          untouched and in their original order.

          Deviations from the spec, with reasoning: (1)
          get_dhcp_lease_info() returns lease_time_seconds on Linux
          instead of lease_obtained/lease_expires, since nmcli's
          DHCP4.OPTION genuinely doesn't expose absolute timestamps --
          faking them from "now + duration" would be worse than
          reporting what the tool actually gives. (2) stack_type in
          get_ipv6_status() is computed inside the function from an
          ipv4_present parameter the caller passes in, rather than
          computed separately in run_discovery() after the fact -- both
          were allowed by the spec, this was the cleaner wiring. (3)
          get_windows_ipconfig_extra() is called once per scan in
          run_discovery() and its result threaded into
          get_dhcp_lease_info(), get_dns_suffix_search_list(), and
          get_ipv6_status() as an optional parameter (each also still
          calls it internally if not passed one, so each function is
          independently correct standalone) -- avoids three redundant
          `ipconfig /all` subprocess calls on every Windows scan.

          Verification, stated honestly: this sandbox is Linux
          (Ubuntu 24.04, running as root), with iputils-ping and
          traceroute installed specifically to exercise this batch (this
          sandbox's ICMP ping to the internet is filtered -- 100% loss --
          while TCP connect and traceroute both work normally; this was
          already true before this version and is unrelated to it).
          Actually run end-to-end against this sandbox's real network:
          get_interface_link_info() (real /sys reads and the ethtool
          fallback both exercised -- note /sys/class/net/eth0/speed
          returned -1 on this container's virtio_net interface, handled
          as "unknown" rather than an error, a real edge case caught by
          testing, not anticipated blind), get_routing_table() (real `ip
          route show` output), traceroute_to_gateway() and
          traceroute_to_internet() (real traceroute output, including a
          run beyond this container's own edge that correctly showed
          "* * *" unresolved hops), read_hosts_file() (real /etc/hosts),
          get_dns_suffix_search_list() (real /etc/resolv.conf, which has
          no search line here -- correctly reported as an error, not a
          false empty success), get_system_proxy_config() (real env-var
          read, gsettings correctly absent-and-skipped in this
          container), get_ipv6_status() (real `ip -6 addr show`; no
          nmcli daemon running here so IP6.DNS lookups correctly no-op),
          check_clock_drift() (ran against this container's real absent
          D-Bus/timedatectl, correctly reported as a failure rather than
          a silent false reading), dump_dns_cache() (Linux path: no
          resolvectl in this container, correctly reported as the tool
          being absent), check_captive_portal() (a real HTTP GET against
          the live endpoint through this sandbox's proxy returned a
          genuine 204 with an empty body -- confirms plain HTTP is NOT
          intercepted here, so this sandbox can validate the true-
          negative path; there was no real captive portal available to
          validate the true-positive path against), measure_throughput()
          (a real 2 MB download completed successfully, ~24 Mbps
          measured in this sandbox -- a real number, not a placeholder,
          though it reflects this sandbox's own proxy path, not a
          customer's real link), get_driver_info() (real ethtool -i
          output on this container's virtio_net driver),
          detect_rogue_dhcp_servers() (real UDP port 68 bind succeeded
          running as root; the broadcast send/listen ran cleanly and
          correctly reported zero offers, since there's no real DHCP
          server on this container's network to answer), and
          discover_mdns_devices()/discover_upnp_devices() (both ran
          their real socket setup/multicast-join/send/receive path
          cleanly, correctly reporting zero devices since this container
          has no mDNS/SSDP responders on its network -- the negative
          path is real, the positive path with an actual responding
          device is not verified here).

          Real bug, caught by running discover_mdns_devices() for real
          in this sandbox (not anticipated blind): the first run showed
          this container's own machine as a "responding device" with
          empty names/services -- not a real Bonjour/Avahi responder,
          but IP multicast loopback delivering our own outgoing query
          straight back into the same socket, since any host joined to
          a multicast group receives its own sends to that group by
          default. Fixed by disabling IP_MULTICAST_LOOP on the socket
          right after joining the group. Re-ran after the fix: zero
          devices reported, correctly, since this container has no real
          mDNS responders on its network.

          check_nat_type()'s STUN query specifically timed out in this
          sandbox -- confirmed separately that this environment's
          outbound network only cooperates with TCP (HTTP/HTTPS/DNS
          through the proxy); a bare UDP packet to an external STUN
          server on port 19302 got no response at all. The STUN
          request/response build-and-parse logic itself was verified
          independently of the network round-trip (packet construction
          checked by hand against the RFC 5389 layout), but the actual
          send/receive path is unverified here -- a genuine sandbox
          network limitation, not a bug being papered over.

          Windows-specific paths (get_windows_ipconfig_extra() and
          everything built on it -- get_dhcp_lease_info(),
          get_dns_suffix_search_list(), get_ipv6_status()'s Windows
          branch; get_interface_link_info()'s and get_driver_info()'s
          wmic branches; get_wifi_connection_details()'s and
          get_wifi_radio_state()'s shared netsh helper;
          _scan_wifi_windows()'s unchanged-but-adjacent wps_enabled
          comment) and macOS-specific paths (get_interface_link_info(),
          get_dhcp_lease_info(), get_dns_suffix_search_list(),
          get_ipv6_status(), get_wifi_connection_details(),
          get_driver_info(), check_clock_drift()'s systemsetup branch)
          are command-construction-reviewed only, same honesty standard
          v0.14.0 already set for its own Windows/macOS work -- no
          Windows or macOS machine is available in this sandbox to run
          them against. detect_duplicate_ip()'s dmesg-grep path and
          check_pmtu_blackhole()'s blackhole-vs-filtered-ICMP
          distinction are logic-reviewed only: this sandbox has no real
          duplicate-IP condition or real PMTU-blackholed path to
          trigger either one against, stated plainly in both functions'
          own docstrings/notes rather than claimed as verified.

  0.14.0 - New get_interface_network_config(): per-interface DNS
          servers, IP assignment mode, and (when static) the actual
          static IP/subnet/gateway -- one dict per interface, keyed by
          the same interface names get_interface_status() already
          uses. Needed for A4's expanded diff-and-rollback work:
          get_dns_servers() reads DNS as one flat list across the whole
          machine, and get_ip_assignment_mode() only returns a mode
          label for one IP, neither of which is enough to know *which*
          interface's DNS to restore, or what static values to restore
          it to. Both existing functions are unchanged and still used
          exactly as before -- this is a new, additive function, not a
          replacement, so nothing that already depended on the old
          shape breaks.

          On Windows this is one pass over `ipconfig /all`: each
          adapter's block already has DNS servers, DHCP Enabled, IPv4
          Address, Subnet Mask, and Default Gateway together, so it's
          captured in a single parse instead of three separate ones.
          On Linux, per-device via `nmcli device show` (IP4.DNS,
          IP4.ADDRESS, IP4.GATEWAY) plus the connection's ipv4.method
          for the mode -- same NetworkManager-only limitation
          get_ip_assignment_mode() already has; an interface nmcli
          doesn't manage just doesn't appear, rather than guessing
          wrong. Also captures `connection_name` (the nmcli connection
          id, e.g. "Wired connection 1") on Linux, and the networksetup
          service name on macOS -- A4's DNS/static-mode set commands
          need to address the *connection*, not just the device, on
          both platforms. On macOS, `networksetup -getinfo <service>`
          for IP/mask/gateway/mode plus `-getdnsservers <service>` for
          DNS -- flagged as not yet verified on real macOS hardware,
          and `-getdnsservers` specifically only shows manually-set DNS
          overrides, not DHCP-provided ones (a real limitation of that
          command, not a parsing gap).

          Verification, stated honestly: this sandbox's NetworkManager
          wouldn't cooperate (container-specific `managed=false` default
          fighting a live managed test interface -- fixable in principle,
          not worth the fight for this), so the Linux/Windows/macOS
          parsers were each verified by feeding them realistic captured
          command output (real `nmcli -t` terse format, real `ipconfig
          /all` block structure, real `networksetup -getinfo` layout)
          and checking the parsed result field-by-field, rather than
          against a live managed interface. That's weaker than this
          codebase's usual real-hardware bar and is flagged as such --
          not claimed as more than it is.

  0.13.1 - Real bug, found while chasing down why --cache "kept not
          working" for Ammar: `a6 = _import_a6()` sat *outside* the
          try/except that was supposed to catch A6-related failures.
          _import_a6() can itself raise -- most likely an ImportError,
          since A6's own module-level code does
          `from cryptography.fernet import Fernet` and re-raises if
          that package isn't installed/working. With the call outside
          the try, that exception was completely unhandled: instead of
          the clean "--cache: ... -- scan not cached" message this was
          supposed to show, A1 crashed with a raw Python traceback,
          even though the scan itself had already finished
          successfully. On Windows this likely showed as the console
          window flashing a wall of text and closing before it could
          be read.

          Fixed by moving _import_a6() inside the same try block as
          the rest of the --cache logic. Reproduced the original bug
          first (in this sandbox, by shadowing the real `cryptography`
          package with a stub module that raises ImportError, then
          running --cache for real as a subprocess) to confirm it
          really did crash with a traceback before the fix, and prints
          the clean message and exits normally after. Re-confirmed the
          full --cache pipeline, --input/--json, and no-args-on-a-tty
          (v0.7.1's fix) all still work unchanged.

  0.13.0 - Wires A1 into A6 (Encrypted Local Cache) directly, the "small
          plumbing change" CLAUDE.md flagged once A6 existed. New
          `--cache` flag: after a scan, writes the discovery dict
          straight into A6 via write_scan() instead of only a JSON
          file. `--json` still works exactly as before and is
          unaffected -- `--cache` is additive, not a replacement, so
          existing scripts/workflows don't break.

          A1 still doesn't hardcode an import of a specific A6 file
          version, for the same reason it already avoids importing A2
          directly (see A2's own changelog): a hardcoded
          `import a6_encrypted_cache_v0_1_0` would break the moment A6
          bumps its version and gets renamed, same fragility problem.
          `_import_a6()` instead globs for `a6_encrypted_cache_v*.py`
          next to this file and loads whichever one has the highest
          (major, minor, patch) version number, so A6 can keep bumping
          its own filename with zero changes needed here -- exactly the
          same reasoning, just applied one hop further down the chain.

          `cryptography` (A6's dependency) is only ever imported lazily,
          inside `_import_a6()`, and only when `--cache` is actually
          used -- A1 itself stays standard-library-only and runs fine
          with zero pip installs if you never pass `--cache`. If A6
          can't be found or `cryptography` isn't installed, `--cache`
          reports the actual error and the scan still completes and
          prints/exports normally -- caching is a secondary feature,
          not something that should take down a scan.

          Verified: ran with --cache against this sandbox's network,
          confirmed a new row appeared in A6 with get_scans(), and that
          --json export still worked unchanged in the same run.

  0.12.0 - check_firewall_rules() only ever recognized rules scoped to
          one of the five named ports -- a rule that blocks everything
          (no protocol/port restriction at all) matched none of those
          checks and was silently invisible, even though it's the
          single most consequential kind of rule there is: it explains
          every connectivity symptom at once, not just one. Ammar's
          specific example: a Windows rule blocking all remote ports
          (Protocol=Any or RemotePort=Any) -- the parser's own first
          gate, `protocol in ("tcp", "udp")`, rejected it before ever
          looking at the port field.

          Every platform parser now also recognizes a blanket rule and
          labels it service "ALL" instead of one of the five named
          services, since it isn't really the same category as "blocks
          one specific service" -- it's evidence against every symptom
          A2 tracks simultaneously:
            - Windows: an enabled, outbound Block rule with
              Protocol=Any or RemotePort=Any.
            - Linux (iptables): a rule with protocol "all" (no -p given),
              AND separately, a chain's own default policy (`Chain
              OUTPUT (policy DROP)`) -- a genuinely different mechanism
              from an individual rule, previously invisible for a
              second, unrelated reason: the chain-header regex only
              extracted the chain name, never the policy verdict sitting
              right next to it.
            - Linux (nft): a bare `drop`/`reject` statement mentioning
              neither `dport` nor `icmp`, and separately a chain's
              `policy drop;`/`policy reject;` line.
            - macOS (pfctl): a `block` line naming neither `udp` nor
              `tcp` -- correct pf semantics, not a heuristic guess: pf
              rules apply to all protocols by default when `proto` is
              omitted.

          New _windows_firewall_profile_policy(): reads whether the
          active Windows Firewall profile's default outbound action is
          Block (`netsh advfirewall show currentprofile`) -- a
          policy-level setting, not a rule, so _firewall_windows()'s
          per-rule parsing could never have seen it regardless of the
          fix above. Surfaced as the same synthetic "ALL" suspect rule
          if the currently active profile is outbound-block-by-default.

          A2's check_firewall_blocking() (a2_rule_engine v0.6.0) gets a
          matching "ALL" branch: fires if *any* of the four existing
          broken conditions is true (not just one), since a blanket
          block is consistent with all of them regardless of which
          symptom happens to be visible right now.

          Re-verified against a real iptables ruleset in this sandbox: a
          bare `-j DROP` rule (no -p) and a chain default policy of DROP
          are both now caught; the previous five-service detections
          (udp/53, tcp/80, tcp/443, udp/67, icmp) are unaffected.
          Windows/macOS paths remain unverified against real hardware.
  0.11.0 - check_firewall_rules() only ever checked DNS (port 53) and
          ICMP -- too narrow. A firewall rule silently dropping HTTP or
          HTTPS looks identical to "internet is down" but never got
          flagged, and a rule blocking DHCP is arguably the single most
          foundational way to break connectivity (no IP, no gateway, no
          DNS server -- nothing works), also never flagged. Replaced the
          single hardcoded DNS-port check with a small, named table,
          _CONNECTIVITY_PORTS: DNS (53, tcp/udp), HTTP (80, tcp), HTTPS
          (443, tcp/udp -- udp for HTTP/3-QUIC, increasingly common),
          DHCP server (67, udp), DHCP client (68, udp). Each suspect rule
          now carries a "service" label (e.g. "HTTPS") instead of just a
          bare port number, for plain-language findings later.

          Deliberately still a small, curated set, not "every port" --
          the whole point of only returning DNS/ICMP-matching rules in
          v0.10.0 was to avoid dumping the full ruleset on A2/downstream;
          widening that to every possible port would mean flagging a
          customer's legitimate custom rule (blocking some unrelated
          app's port) as if it explains a connectivity problem it has
          nothing to do with. Every port in this table maps to a symptom
          A1/A2 can already detect and correlate against: DNS -> DNS not
          resolving, HTTP/HTTPS -> internet unreachable (A1's own
          reachability check tests port 443 specifically), DHCP -> no
          gateway found at all. That correlation logic lives in A2's
          check_firewall_blocking() (a2_rule_engine v0.5.0) -- A1 still
          only gathers, it doesn't decide anything matters.

          Re-verified against this sandbox's real iptables (rules for
          udp/53, tcp/80, tcp/443, and icmp all correctly caught; an
          unrelated tcp/8080 rule still correctly ignored).
  0.10.0 - check_firewall_rules(): reads the actual local firewall
          ruleset (netsh advfirewall on Windows, iptables/nft on Linux,
          pfctl on macOS) for any rule that blocks DNS (port 53) or ICMP
          specifically. Pure data gathering, same as every other A1
          function -- this reports what rules exist, it doesn't decide
          whether they explain anything. A2's check_firewall_blocking()
          (new in a2_rule_engine v0.4.0) is what correlates a matching
          rule against an actual DNS/internet failure and calls it a
          likely cause -- that split (A1 gathers, A2 decides) is the
          same one CLAUDE.md already draws for every other module.
          Only returns the small subset of rules that block DNS/ICMP,
          not a full ruleset dump -- nobody downstream needs the rest.
          Known limitation, flagged rather than hidden: reading the full
          ruleset needs root on Linux (iptables/nft) and macOS (pfctl);
          without it, the errors list explains why instead of silently
          returning "no blocking rules found" -- an empty result has to
          be distinguishable from "couldn't check," same reasoning as
          every other error-surfacing fix in this file. Windows' netsh
          advfirewall doesn't need elevation to read rules. Verified
          against this sandbox's real iptables output (both a genuine
          DNS-block rule and a clean ruleset); Windows/macOS parsing is
          unverified against real hardware, same caveat as the UPnP
          traffic counters and Wi-Fi radio state parsing before it.
          Skippable with --no-firewall.
  0.9.0 - check_dns_resolution(): tests whether each *configured* DNS
          server actually resolves names, instead of just reading the
          config and assuming it works. This is the "internet is
          reachable but DNS is broken" case -- ISP DNS server down, DNS
          hijacked/misconfigured, captive portal -- which looks
          identical to "internet is down" to a non-technical user but
          has a completely different fix. Sends a raw DNS query directly
          to each server (not through the OS resolver, which can't be
          pointed at one specific server) for example.com -- IANA-
          reserved for documentation/testing, about as stable a target
          as exists. This is A1's second deliberate exception to "only
          A7 touches the internet" (see check_internet_reachability());
          gated under the same --no-internet flag since both are the
          same category of operation.
  0.8.0 - query_upnp_gateway() was printing whatever the router's UPnP
          stack returned as if it were trustworthy, and on Ammar's real
          Tenda router it wasn't: external_ip came back as a *private*
          address (192.168.100.2 -- a real WAN IP can't be private,
          this means the router is itself behind another router/NAT,
          common with FTTH ONT/modem combos), uptime_seconds came back
          as ~26.6 years (impossible, a firmware counter bug), and
          total_bytes_received came back as exactly 2^32-1 (the classic
          signature of an overflowed/wrapped 32-bit counter, or a
          "not really supported" sentinel value). None of these were
          flagged -- they just got printed next to the genuinely good
          data (external IP format, connection status) as if all of it
          were equally trustworthy. Added _upnp_sanity_notes(), which
          checks for exactly these three patterns and surfaces them as
          plain-language notes instead of silently trusting whatever
          the router's firmware says.
  0.7.0 - query_upnp_gateway(): talks to the router itself via UPnP IGD
          (Internet Gateway Device) -- a real, standardized protocol
          most consumer routers (Tenda/TP-Link included) support, and
          one that's normally unauthenticated on the LAN by design (it
          exists so any app can request port-forwarding without a login
          prompt). No router credentials needed, unlike the admin panel.
          SSDP-discovers the device, fetches its description XML, finds
          the WANIPConnection/WANPPPConnection service, and calls
          GetExternalIPAddress / GetStatusInfo over SOAP; also tries
          WANCommonInterfaceConfig for traffic byte counters if present
          (best-effort -- not verified against real hardware, wrapped so
          a failure there doesn't affect the rest). Skippable with
          --no-upnp.
          This does NOT get the DHCP client list or the router's actual
          configured DHCP range -- UPnP doesn't expose that. Getting it
          would need logging into the router's own web admin panel and
          scraping undocumented, per-model endpoints -- flagged, not
          built, see CLAUDE.md's "Flagged / open decisions."
  0.6.0 - Three additions Claude suggested and Ammar approved:
            - check_gateway_latency(): pings the gateway a handful of
              times (not just once) for real signal on connection
              quality -- packet loss and average round-trip time, not
              just alive/dead. Deliberately separate from the one-shot
              _ping_once() used for the subnet sweep; running 4-5 pings
              against every host in the subnet would be far too slow, so
              this only ever targets the single gateway IP.
            - MTU per interface, folded into get_interface_status()'s
              existing per-interface dict (`ip link show` / `ifconfig`
              already report it; Windows needed a second netsh command,
              `netsh interface ipv4 show subinterfaces`, merged in by
              interface name).
            - check_internet_reachability(): a lightweight TCP-connect
              test (not ICMP) to a couple of well-known IPs on port 443.
              This is A1's one deliberate, documented exception to "only
              A7 touches the internet" -- see CLAUDE.md's Architecture
              section for the reasoning. It's a reachability TEST, not a
              dependency: nothing else in A1 needs it to succeed, and the
              whole rest of the file still works fully offline. Skippable
              with --no-internet.
  0.5.0 - Two more items from Ammar's list:
            - get_interface_status() now reports admin_enabled and
              connected as two separate fields instead of one collapsed
              "up" bool -- an adapter can be enabled but not connected
              (cable unplugged, nothing in range), which is a different
              situation from being disabled outright, and worth telling
              apart. This is also what answers "were the adapters set to
              on or off in Windows" directly, using data this file was
              already fetching.
            - get_wifi_radio_state(): hardware/software Wi-Fi radio kill
              state (netsh on Windows, rfkill on Linux). Deliberately
              does NOT claim to read Windows' actual system-wide
              "Airplane Mode" flag -- see the function's docstring for
              why (no reliable stdlib-only way to do that without either
              fragile PowerShell/WinRT interop or an unverified registry
              key). Software-off is the mechanism Airplane Mode and
              Fn-key Wi-Fi toggles both actually use, so this answers the
              practical question even without reading the OS flag
              directly. Not applicable on macOS -- no OS-level Airplane
              Mode exists there.
  0.4.0 - Fixed the same silent-failure bug from v0.2.0, this time in the
          v0.3.0 additions: Ammar tested on real Windows hardware and
          get_interface_status() came back completely empty (no Ethernet,
          no Wi-Fi, nothing) with zero explanation. Root cause was the
          same pattern -- exceptions caught and swallowed with `pass`, so
          a command failure looked identical to "no interfaces found."
          get_dns_servers(), get_interface_status(), and
          get_ip_assignment_mode() now all return (result, errors) same
          as scan_wifi_networks(), and each one also flags it when the
          command *succeeds* but nothing matches the expected output
          format (including a short raw-output snippet), since that's a
          second, quieter way to end up with an empty list that isn't an
          exception at all.
          Also: the Wi-Fi scan error Ammar hit --
          "The wireless local area network interface is powered down and
          doesn't support the requested operation" -- is netsh's real
          answer, not a bug, but it reads like an error dump, not a
          diagnosis. Added a plain-language hint underneath it, and
          get_interface_status() now reports the same "Wi-Fi: DOWN"
          finding directly, so it doesn't only show up buried in a scan
          error.
  0.3.0 - Added five discovery items from Ammar's list:
            - get_dns_servers(): configured DNS server(s), offline (reads
              local config, doesn't query DNS itself)
            - calculate_pool_usage(): rough IP pool usage for the scanned
              subnet (used/free/percent) -- known gap, see docstring: this
              is usage across the whole subnet, not the router's actual
              configured DHCP range, which we have no way to know without
              asking the router
            - get_interface_status(): which network interfaces exist and
              whether each is up or down, with a best-effort ethernet/wifi
              guess (exact on macOS via hardware-port lookup, name-based
              guess elsewhere)
            - get_ip_assignment_mode(): whether this machine's IP looks
              like DHCP or static -- known gap: Linux detection needs
              NetworkManager (nmcli); returns "unknown" rather than
              guessing wrong if it's not present
            - get_arp_table() was already built (v0.1.0)
          CDP and LLDP (from the same list) are deliberately NOT here --
          see CLAUDE.md's "Flagged / open decisions" section for why
          (raw Layer-2 capture needs root/admin everywhere, and has no
          viable path at all on iOS, or on a non-rooted Android phone).
  0.2.0 - Wi-Fi scanning was silently failing: every error inside
          scan_wifi_networks() was caught and swallowed with `pass`, so a
          failed scan looked identical to "zero networks found" -- you'd
          just see the "Scanning Wi-Fi networks..." line and nothing
          after it. Fixed by making every command report its actual error
          instead of hiding it. Also added `iw` as a Linux fallback
          between nmcli and iwlist, since `iwlist` (wireless-tools) is
          missing by default on a lot of current distros -- `iw`
          (iproute2) is the modern replacement and more likely to exist.
          New: channel/signal values are now parsed into real numbers
          during scanning (not left as raw strings), and a new
          suggest_best_channel() looks at every network we saw and
          recommends the least congested 2.4GHz and 5GHz channel.
  0.1.0 - First version in this repo. Implements everything listed under
          "Current state" in CLAUDE.md: local IP/subnet + gateway
          detection, threaded ping sweep, ARP cross-reference (catches
          devices with ICMP disabled), seed MAC vendor lookup, offline
          hostname resolution, common-port probing with role guessing,
          Wi-Fi network scanning, and JSON export.

Standard-library only. No pip installs, on purpose -- see CLAUDE.md for why.

Run it directly:  python3 network_discovery_v0.15.0.py
Skip the slow steps while testing:  python3 network_discovery_v0.15.0.py --no-ports --no-wifi
Stay fully offline, no exceptions: python3 network_discovery_v0.15.0.py --no-internet --no-traceroute \
    --no-pmtu --no-captive-portal --no-throughput --no-nat-type
Dump machine-readable output:       python3 network_discovery_v0.15.0.py --json out.json

Note on Wi-Fi scanning permissions: on Linux, actually triggering a scan
(as opposed to reading a cached list) usually needs root. If you see a
"not permitted" style error in the output, try running with sudo.

Note on firewall rule reading: on Linux and macOS, reading the full
firewall ruleset (iptables/nft, pfctl) needs root -- run with sudo if
you see a permission error under the firewall section. Skip it entirely
with --no-firewall.

Note on the rogue DHCP probe: on Linux and macOS it needs root/admin to
bind UDP port 68 (a privileged port). Run with sudo, or skip it entirely
with --no-dhcp-probe.
"""

import argparse
import ipaddress
import json
import os
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor


def _import_a6():
    """
    Dynamically loads whichever a6_encrypted_cache_v*.py sits next to this
    file, picking the highest (major, minor, patch) version present --
    same reasoning A2 already uses to avoid hardcoding A1's version: A6
    can keep bumping its own filename with zero changes needed here.
    Returns None if no A6 file is found (--cache then reports that
    clearly instead of crashing the scan).
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

# The three 2.4GHz channels that don't overlap each other at all (each
# channel is 20MHz wide but channels are spaced 5MHz apart, so anything
# closer than 5 channels away bleeds into its neighbour). Every router and
# regulatory region supports these three, which is why professional Wi-Fi
# installers only ever recommend picking among them.
NONOVERLAPPING_24GHZ = [1, 6, 11]

# 5GHz channels that don't require DFS (radar detection) -- safe to
# recommend without worrying about a router refusing or delaying on them.
COMMON_5GHZ = [36, 40, 44, 48, 149, 153, 157, 161]

# Used only by check_internet_reachability() -- Cloudflare and Google's
# anycast IPs, picked purely for extremely high uptime/ubiquity as
# reachability-check targets (this is standard practice, e.g. router
# firmware "internet check" features use the same pattern). We do a bare
# TCP connect to port 443 and nothing else -- no data sent beyond the
# handshake, no DNS lookups performed against them.
INTERNET_CHECK_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 443)]

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


def _get_interface_for_ip(ip):
    """Finds which network interface has this IP assigned. Used by
    get_ip_assignment_mode() to know which connection/interface to ask
    about. Returns None if not found (e.g. on Windows, which looks up
    DHCP status by IP directly instead and doesn't need this)."""
    try:
        if SYSTEM == "Linux":
            out = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show"], text=True)
            for line in out.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        elif SYSTEM == "Darwin":
            out = subprocess.check_output(["ifconfig"], text=True)
            for block in out.split("\n\n"):
                if ip in block:
                    m = re.match(r"^(\w+):", block)
                    if m:
                        return m.group(1)
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return None


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


def get_dns_servers():
    """
    Finds the DNS server(s) this machine is configured to use. Fully
    offline -- reads local config/OS state, never queries a DNS server
    itself.

    Returns (servers, errors). Every failure -- including the command
    succeeding but nothing matching the format we expect -- is reported
    instead of silently coming back as an empty list.
    """
    servers = []
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("ipconfig not found (unexpected on Windows)")
                return servers, errors
            if result.returncode != 0:
                errors.append(f"ipconfig /all failed: {(result.stderr or result.stdout).strip()}")
                return servers, errors

            in_dns_block = False
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("DNS Servers"):
                    m = re.search(r":\s*([\d.]+)\s*$", stripped)
                    if m:
                        servers.append(m.group(1))
                    in_dns_block = True
                    continue
                if in_dns_block and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", stripped):
                    servers.append(stripped)
                    continue
                in_dns_block = False

            if not servers:
                errors.append("ipconfig /all ran but no \"DNS Servers\" line was found for any adapter")

        else:
            # Linux and macOS both maintain /etc/resolv.conf.
            try:
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                servers.append(parts[1])
            except FileNotFoundError:
                errors.append("/etc/resolv.conf not found")

            if not servers and SYSTEM == "Darwin":
                try:
                    result = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, errors="ignore", timeout=10)
                except FileNotFoundError:
                    errors.append("scutil not found")
                    result = None
                if result is not None:
                    if result.returncode != 0:
                        errors.append(f"scutil --dns failed: {(result.stderr or result.stdout).strip()}")
                    else:
                        for line in result.stdout.splitlines():
                            m = re.search(r"nameserver\[\d+\]\s*:\s*([\d.]+)", line)
                            if m:
                                servers.append(m.group(1))
                        if not servers:
                            errors.append("scutil --dns ran but no nameserver entries were found")
    except Exception as e:
        errors.append(f"unexpected error finding DNS servers: {e}")

    seen = set()
    unique = []
    for s in servers:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique, errors


def calculate_pool_usage(network_str, device_count):
    """
    Rough IP pool usage for the subnet we scanned: how many addresses are
    in use out of how many are usable.

    Known gap: this is usage across the *whole subnet*, not the router's
    actual configured DHCP range -- a router might only hand out
    .100-.200 while the subnet is a full /24. We have no way to know the
    real DHCP range without asking the router directly (that's an A3-era
    problem, once we have router credentials/access).
    """
    network = ipaddress.ip_network(network_str, strict=False)
    total_usable = max(network.num_addresses - 2, 1)
    used = min(device_count, total_usable)
    return {
        "subnet": str(network),
        "total_usable": total_usable,
        "used": used,
        "free": total_usable - used,
        "percent_used": round(used / total_usable * 100, 1),
    }


def _macos_interface_types():
    """Maps macOS interface names (en0, en1, ...) to wifi/ethernet using
    the hardware-port list, since macOS names alone don't tell you which
    is which (en0 is Wi-Fi on some Macs, Ethernet on others)."""
    types = {}
    try:
        out = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
        for block in out.split("\n\n"):
            port_m = re.search(r"Hardware Port: (.+)", block)
            dev_m = re.search(r"Device: (\w+)", block)
            if port_m and dev_m:
                if "Wi-Fi" in port_m.group(1) or "AirPort" in port_m.group(1):
                    types[dev_m.group(1)] = "wifi"
                elif "Ethernet" in port_m.group(1):
                    types[dev_m.group(1)] = "ethernet"
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return types


def _guess_interface_type(name):
    """Best-effort ethernet/wifi guess from interface naming conventions.
    Known gap: unreliable on macOS by name alone -- get_interface_status()
    uses _macos_interface_types() instead there."""
    lname = name.lower()
    if "wi-fi" in lname or "wifi" in lname or "wlan" in lname or lname.startswith("wl"):
        return "wifi"
    if "ethernet" in lname or lname.startswith("eth") or lname.startswith("en"):
        return "ethernet"
    return "other"


def _windows_mtu_by_interface():
    """Maps interface name -> MTU on Windows via a second, separate netsh
    command from the one get_interface_status() uses for up/down state."""
    mtu = {}
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "subinterfaces"],
            capture_output=True, text=True, errors="ignore", timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0].isdigit():
                    mtu[" ".join(parts[4:])] = int(parts[0])
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return mtu


def get_interface_status():
    """
    Lists network interfaces with two separate signals per interface,
    not one collapsed "up" bool, plus MTU:
      - admin_enabled: was the adapter itself turned on/off (Windows
        adapter settings "Enable"/"Disable", Linux/macOS admin UP flag)
      - connected: is it actually carrying a link right now (Windows
        "Connected"/"Disconnected", Linux LOWER_UP flag, macOS
        "status: active/inactive")
    An adapter can be enabled but not connected (cable unplugged, no
    network in range) -- that's a different situation from the adapter
    being disabled outright, and worth telling apart.

    Returns (interfaces, errors) -- same pattern as scan_wifi_networks().
    An earlier version of this function had the exact silent-failure bug
    that v0.2.0 fixed for Wi-Fi scanning, just not fixed here yet: caught
    on Ammar's real Windows machine, where it came back completely empty
    with no explanation at all.
    """
    interfaces = []
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("netsh not found (unexpected on Windows)")
                return interfaces, errors
            if result.returncode != 0:
                errors.append(f"netsh interface show interface failed: {(result.stderr or result.stdout).strip()}")
                return interfaces, errors

            mtu_by_name = _windows_mtu_by_interface()
            for line in result.stdout.splitlines():
                parts = line.split(None, 3)
                if len(parts) == 4 and parts[0] in ("Enabled", "Disabled"):
                    admin_state, conn_state, _if_type, name = parts
                    name = name.strip()
                    interfaces.append({
                        "name": name,
                        "type": _guess_interface_type(name),
                        "admin_enabled": admin_state == "Enabled",
                        "connected": conn_state == "Connected",
                        "mtu": mtu_by_name.get(name),
                    })
            if not interfaces:
                snippet = "\n".join(result.stdout.splitlines()[:6])
                errors.append(
                    "netsh ran but no interface rows were recognized -- output may not "
                    f"match the expected format. First lines:\n{snippet}"
                )

        elif SYSTEM == "Linux":
            try:
                result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("`ip` command not found")
                return interfaces, errors
            if result.returncode != 0:
                errors.append(f"ip link show failed: {(result.stderr or result.stdout).strip()}")
                return interfaces, errors

            for line in result.stdout.splitlines():
                m = re.match(r"\d+:\s+([^:@]+)[:@].*?<([^>]*)>", line)
                if not m:
                    continue
                name, flags = m.group(1), m.group(2).split(",")
                if name == "lo":
                    continue
                mtu_m = re.search(r"\bmtu\s+(\d+)", line)
                interfaces.append({
                    "name": name,
                    "type": _guess_interface_type(name),
                    "admin_enabled": "UP" in flags,
                    "connected": "LOWER_UP" in flags,
                    "mtu": int(mtu_m.group(1)) if mtu_m else None,
                })
            if not interfaces:
                errors.append("ip link show ran but found no non-loopback interfaces")

        elif SYSTEM == "Darwin":
            mac_types = _macos_interface_types()
            try:
                result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("ifconfig not found")
                return interfaces, errors
            if result.returncode != 0:
                errors.append(f"ifconfig failed: {(result.stderr or result.stdout).strip()}")
                return interfaces, errors

            for block in result.stdout.split("\n\n"):
                m = re.match(r"^(\w+):\s*flags=\d+<([^>]*)>", block)
                if not m:
                    continue
                name, flags = m.group(1), m.group(2).split(",")
                if name == "lo0":
                    continue
                status_m = re.search(r"status:\s*(\w+)", block)
                mtu_m = re.search(r"\bmtu\s+(\d+)", block)
                interfaces.append({
                    "name": name,
                    "type": mac_types.get(name, _guess_interface_type(name)),
                    "admin_enabled": "UP" in flags,
                    "connected": (status_m.group(1) == "active") if status_m else None,
                    "mtu": int(mtu_m.group(1)) if mtu_m else None,
                })
            if not interfaces:
                errors.append("ifconfig ran but found no non-loopback interfaces")
    except Exception as e:
        errors.append(f"unexpected error checking interfaces: {e}")

    return interfaces, errors


def get_wifi_radio_state():
    """
    Reports the Wi-Fi radio's hardware/software on-off state --
    "hardware" is a physical switch/killswitch, "software" is a radio
    kill done in software, which is the actual mechanism both Airplane
    Mode and Fn-key Wi-Fi toggles use.

    This deliberately does NOT claim to read Windows' system-wide
    "Airplane Mode" setting directly. The documented way to do that needs
    WinRT interop through PowerShell, which is fragile to write blind
    without a Windows machine to test against; the alternative is an
    undocumented registry key whose exact on/off value mapping isn't
    something that could be verified without hardware either, and
    shipping a confidently-wrong on/off reading is worse than not having
    the feature. Hardware/software radio state is the practical
    diagnostic that actually matters here, and it's readable through
    netsh/rfkill, tools this file already trusts.

    Not applicable on macOS -- there's no OS-level Airplane Mode there,
    Wi-Fi power is a per-adapter toggle only (see scan_wifi_networks()).

    Known gap: the Windows netsh output parsing hasn't been confirmed
    against real hardware. If it comes back with a parse error, that's
    expected until tested -- the error includes a snippet of the raw
    output so the parsing can be corrected in one pass.

    Returns ({"hardware": "on"/"off"/None, "software": "on"/"off"/None}, errors).
    """
    state = {"hardware": None, "software": None}
    errors = []
    try:
        if SYSTEM == "Windows":
            # Shares one `netsh wlan show interfaces` call with
            # get_wifi_connection_details() via this helper, instead of
            # each function shelling out separately for data that
            # command already reports together.
            stdout, err = _windows_wlan_show_interfaces_raw()
            if err:
                errors.append(err)
                return state, errors

            hw_m = re.search(r"Hardware\s+(On|Off)", stdout)
            sw_m = re.search(r"Software\s+(On|Off)", stdout)
            if hw_m:
                state["hardware"] = hw_m.group(1).lower()
            if sw_m:
                state["software"] = sw_m.group(1).lower()
            if not hw_m and not sw_m:
                snippet = "\n".join(stdout.splitlines()[:12])
                errors.append(
                    "netsh wlan show interfaces ran but no \"Radio status\" was found -- "
                    f"output format may not match what this code expects. First lines:\n{snippet}"
                )

        elif SYSTEM == "Linux":
            try:
                result = subprocess.run(["rfkill", "list"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("rfkill not installed (install util-linux's rfkill, or try `nmcli radio wifi`)")
                return state, errors
            if result.returncode != 0:
                errors.append(f"rfkill list failed: {(result.stderr or result.stdout).strip()}")
                return state, errors

            in_wifi = False
            for line in result.stdout.splitlines():
                if re.match(r"^\d+:\s", line):
                    in_wifi = any(w in line.lower() for w in ("wlan", "wireless", "wifi"))
                elif in_wifi and "Soft blocked" in line:
                    state["software"] = "off" if "yes" in line.lower() else "on"
                elif in_wifi and "Hard blocked" in line:
                    state["hardware"] = "off" if "yes" in line.lower() else "on"
            if state["hardware"] is None and state["software"] is None:
                errors.append("rfkill list ran but found no Wi-Fi radio entry")
        # SYSTEM == "Darwin": intentionally left as (None, None) with no
        # errors -- not a failure, just not a thing macOS has.
    except Exception as e:
        errors.append(f"unexpected error checking Wi-Fi radio state: {e}")

    return state, errors


def get_ip_assignment_mode(local_ip):
    """
    Best-effort check for whether this machine's IP came from DHCP or was
    set statically.

    Known gap: Linux detection depends on NetworkManager (nmcli) managing
    the interface -- returns "unknown" rather than guessing wrong if
    nmcli isn't present or the interface isn't NetworkManager-managed
    (common on servers using netplan/systemd-networkd directly).

    Returns (mode, errors) -- mode is "dhcp" / "static" / "unknown".
    """
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("ipconfig not found (unexpected on Windows)")
                return "unknown", errors
            if result.returncode != 0:
                errors.append(f"ipconfig /all failed: {(result.stderr or result.stdout).strip()}")
                return "unknown", errors

            for block in result.stdout.split("\r\n\r\n"):
                if local_ip in block:
                    m = re.search(r"DHCP Enabled[.\s]*:\s*(Yes|No)", block)
                    if m:
                        return ("dhcp" if m.group(1) == "Yes" else "static"), errors
            errors.append(f"ipconfig /all ran but no adapter block contained {local_ip}")

        elif SYSTEM == "Linux":
            iface = _get_interface_for_ip(local_ip)
            if not iface:
                errors.append(f"could not find a network interface for {local_ip}")
                return "unknown", errors
            try:
                active = subprocess.run(
                    ["nmcli", "-t", "-f", "NAME,DEVICE", "con", "show", "--active"],
                    capture_output=True, text=True, errors="ignore", timeout=10,
                )
            except FileNotFoundError:
                errors.append("nmcli not installed")
                return "unknown", errors
            if active.returncode != 0:
                errors.append(f"nmcli con show failed: {(active.stderr or active.stdout).strip()}")
                return "unknown", errors

            found_conn = False
            for line in active.stdout.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[1] == iface:
                    found_conn = True
                    method_out = subprocess.run(
                        ["nmcli", "-t", "-f", "ipv4.method", "con", "show", parts[0]],
                        capture_output=True, text=True, errors="ignore", timeout=10,
                    )
                    method = method_out.stdout.strip().split(":")[-1]
                    if method == "auto":
                        return "dhcp", errors
                    if method == "manual":
                        return "static", errors
                    errors.append(f"nmcli reported ipv4.method={method!r} for {iface}, not auto/manual")
                    break
            if not found_conn:
                errors.append(f"no active nmcli connection found for interface {iface}")

        elif SYSTEM == "Darwin":
            iface = _get_interface_for_ip(local_ip)
            if not iface:
                errors.append(f"could not find a network interface for {local_ip}")
                return "unknown", errors
            out = subprocess.run(
                ["ipconfig", "getpacket", iface],
                capture_output=True, text=True, errors="ignore", timeout=5,
            )
            if out.returncode == 0 and out.stdout.strip():
                return "dhcp", errors
            return "static", errors
    except Exception as e:
        errors.append(f"unexpected error checking dhcp/static: {e}")

    return "unknown", errors


def _macos_hardware_ports():
    """
    All (device, hardware-port-name) pairs from `networksetup
    -listallhardwareports`, e.g. [("en0", "Wi-Fi"), ("en1", "Thunderbolt
    Ethernet")]. Unlike _macos_interface_types() (which keeps only a
    normalized wifi/ethernet type), this keeps the actual port name --
    the exact string networksetup's other commands (-getinfo,
    -getdnsservers, -setdnsservers, -setnetworkserviceenabled) need as
    an argument.
    """
    pairs = []
    try:
        out = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
        for block in out.split("\n\n"):
            port_m = re.search(r"Hardware Port: (.+)", block)
            dev_m = re.search(r"Device: (\w+)", block)
            if port_m and dev_m:
                pairs.append((dev_m.group(1), port_m.group(1).strip()))
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return pairs


def get_interface_network_config():
    """
    Per-interface DNS servers, IP assignment mode, and (when static) the
    actual static IP/subnet/gateway -- everything A4 needs to later
    detect and revert a DNS or static/DHCP change on a specific
    interface. Deliberately separate from get_dns_servers() and
    get_ip_assignment_mode() (both stay unchanged, machine-wide/single-IP
    as before) rather than replacing them -- existing A2 rules and
    existing scans keep working exactly as before; this is additive.

    Returns ({interface_name: {"dns_servers": [...], "ip_assignment_mode":
    "dhcp"/"static"/"unknown", "ip_address": str|None, "subnet_mask":
    str|None, "gateway": str|None}}, errors).

    Known gap, same shape as get_ip_assignment_mode()'s existing one:
    on Linux, an interface not managed by NetworkManager just doesn't
    appear in the result, rather than guessing wrong.
    """
    config = {}
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("ipconfig not found (unexpected on Windows)")
                return config, errors
            if result.returncode != 0:
                errors.append(f"ipconfig /all failed: {(result.stderr or result.stdout).strip()}")
                return config, errors

            # One pass over ipconfig /all: each adapter's block has DNS
            # servers, DHCP Enabled, IPv4 Address, Subnet Mask, and
            # Default Gateway all together, so this captures everything
            # per interface in a single parse instead of three.
            current = None
            in_dns_block = False
            for line in result.stdout.splitlines():
                header_m = re.match(
                    r"^(?:Ethernet adapter|Wireless LAN adapter|Tunnel adapter|Unknown adapter) (.+):\s*$",
                    line,
                )
                if header_m:
                    current = header_m.group(1).strip()
                    config[current] = {
                        "dns_servers": [], "ip_assignment_mode": "unknown",
                        "ip_address": None, "subnet_mask": None, "gateway": None,
                        "connection_name": None,
                    }
                    in_dns_block = False
                    continue
                if current is None:
                    continue
                stripped = line.strip()

                if stripped.startswith("DNS Servers"):
                    m = re.search(r":\s*([\d.]+)\s*$", stripped)
                    if m:
                        config[current]["dns_servers"].append(m.group(1))
                    in_dns_block = True
                    continue
                if in_dns_block and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", stripped):
                    config[current]["dns_servers"].append(stripped)
                    continue
                in_dns_block = False

                m = re.search(r"DHCP Enabled[.\s]*:\s*(Yes|No)", stripped)
                if m:
                    config[current]["ip_assignment_mode"] = "dhcp" if m.group(1) == "Yes" else "static"
                    continue
                m = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", stripped)
                if m:
                    config[current]["ip_address"] = m.group(1)
                    continue
                m = re.search(r"Subnet Mask[.\s]*:\s*([\d.]+)", stripped)
                if m:
                    config[current]["subnet_mask"] = m.group(1)
                    continue
                m = re.search(r"Default Gateway[.\s]*:\s*([\d.]+)", stripped)
                if m:
                    config[current]["gateway"] = m.group(1)
                    continue

            if not config:
                errors.append("ipconfig /all ran but no adapter blocks were recognized")

        elif SYSTEM == "Linux":
            try:
                devices = subprocess.run(
                    ["nmcli", "-t", "-f", "DEVICE,STATE", "device"],
                    capture_output=True, text=True, errors="ignore", timeout=10,
                )
            except FileNotFoundError:
                errors.append("nmcli not installed -- per-interface network config needs NetworkManager")
                return config, errors
            if devices.returncode != 0:
                errors.append(f"nmcli device failed: {(devices.stderr or devices.stdout).strip()}")
                return config, errors

            for line in devices.stdout.splitlines():
                parts = line.split(":")
                if len(parts) != 2 or parts[1] != "connected":
                    continue
                iface = parts[0]
                show = subprocess.run(
                    ["nmcli", "-t", "-f",
                     "IP4.DNS,IP4.ADDRESS,IP4.GATEWAY,GENERAL.CONNECTION",
                     "device", "show", iface],
                    capture_output=True, text=True, errors="ignore", timeout=10,
                )
                if show.returncode != 0:
                    errors.append(f"nmcli device show {iface} failed: {(show.stderr or show.stdout).strip()}")
                    continue

                entry = {"dns_servers": [], "ip_assignment_mode": "unknown",
                         "ip_address": None, "subnet_mask": None, "gateway": None,
                         "connection_name": None}
                conn_name = None
                for dline in show.stdout.splitlines():
                    m = re.match(r"IP4\.DNS\[\d+\]:(.+)", dline)
                    if m:
                        entry["dns_servers"].append(m.group(1).strip())
                        continue
                    m = re.match(r"IP4\.ADDRESS\[\d+\]:([\d.]+)/(\d+)", dline)
                    if m:
                        entry["ip_address"] = m.group(1)
                        entry["subnet_mask"] = _cidr_to_netmask(int(m.group(2)))
                        continue
                    m = re.match(r"IP4\.GATEWAY:(.+)", dline)
                    if m and m.group(1).strip():
                        entry["gateway"] = m.group(1).strip()
                        continue
                    m = re.match(r"GENERAL\.CONNECTION:(.+)", dline)
                    if m:
                        conn_name = m.group(1).strip()

                entry["connection_name"] = conn_name
                if conn_name:
                    method_out = subprocess.run(
                        ["nmcli", "-t", "-f", "ipv4.method", "con", "show", conn_name],
                        capture_output=True, text=True, errors="ignore", timeout=10,
                    )
                    method = method_out.stdout.strip().split(":")[-1]
                    if method == "auto":
                        entry["ip_assignment_mode"] = "dhcp"
                    elif method == "manual":
                        entry["ip_assignment_mode"] = "static"
                    else:
                        errors.append(f"nmcli reported ipv4.method={method!r} for {iface}, not auto/manual")

                config[iface] = entry

            if not config:
                errors.append("nmcli ran but reported no connected devices")

        elif SYSTEM == "Darwin":
            for device, service in _macos_hardware_ports():
                entry = {"dns_servers": [], "ip_assignment_mode": "unknown",
                         "ip_address": None, "subnet_mask": None, "gateway": None,
                         "connection_name": service}

                dns_out = subprocess.run(
                    ["networksetup", "-getdnsservers", service],
                    capture_output=True, text=True, errors="ignore", timeout=10,
                )
                # -getdnsservers only ever shows manually-set DNS overrides,
                # not DHCP-provided ones -- "There aren't any..." means
                # either no override or the interface is inactive, not
                # necessarily "no DNS at all". Not yet verified on real
                # macOS hardware.
                entry["dns_servers"] = [
                    l.strip() for l in dns_out.stdout.splitlines()
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", l.strip())
                ]

                info_out = subprocess.run(
                    ["networksetup", "-getinfo", service],
                    capture_output=True, text=True, errors="ignore", timeout=10,
                )
                info = info_out.stdout
                if "DHCP Configuration" in info:
                    entry["ip_assignment_mode"] = "dhcp"
                elif "Manually" in info:
                    entry["ip_assignment_mode"] = "static"
                m = re.search(r"IP address:\s*([\d.]+)", info)
                if m:
                    entry["ip_address"] = m.group(1)
                m = re.search(r"Subnet mask:\s*([\d.]+)", info)
                if m:
                    entry["subnet_mask"] = m.group(1)
                m = re.search(r"Router:\s*([\d.]+)", info)
                if m:
                    entry["gateway"] = m.group(1)

                if entry["ip_address"]:
                    config[device] = entry

            if not config:
                errors.append("networksetup ran but no active hardware ports were found")
    except Exception as e:
        errors.append(f"unexpected error reading per-interface network config: {e}")

    return config, errors


def _cidr_to_netmask(prefix_len):
    """25 -> '255.255.255.128', etc. Used to turn nmcli's CIDR-style
    IP4.ADDRESS (e.g. 192.168.1.100/24) into a plain dotted subnet mask,
    matching the shape Windows/macOS report it in."""
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return ".".join(str((mask >> shift) & 0xFF) for shift in (24, 16, 8, 0))


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


def check_gateway_latency(gateway_ip, count=4, timeout_ms=1000):
    """
    Pings the gateway a handful of times -- not just once -- for real
    signal on connection quality: packet loss and average round-trip
    time, not just alive/dead. Deliberately separate from the one-shot
    _ping_once() the subnet sweep uses; running several pings against
    every host in the subnet would be far too slow, so this only ever
    targets the single gateway IP.

    v0.15.0: also returns jitter_ms -- the RFC 3550-style mean absolute
    difference between consecutive RTT samples, computed from the same
    per-ping RTT list this function was already collecting internally
    (just not returning before). Zero new subprocess calls, a pure
    enhancement to data already gathered here.
    """
    if not gateway_ip:
        return {"target": None, "sent": 0, "received": 0, "loss_percent": None, "avg_ms": None, "jitter_ms": None}

    rtts = []
    received = 0
    for _ in range(count):
        if SYSTEM == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), gateway_ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), gateway_ip]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 2)
        except (subprocess.SubprocessError, OSError):
            continue
        if result.returncode == 0:
            received += 1
            m = re.search(r"time[=<]\s*([\d.]+)\s*ms", result.stdout, re.IGNORECASE)
            if m:
                rtts.append(float(m.group(1)))

    jitter_ms = None
    if len(rtts) >= 2:
        diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
        jitter_ms = round(sum(diffs) / len(diffs), 1)

    return {
        "target": gateway_ip,
        "sent": count,
        "received": received,
        "loss_percent": round((count - received) / count * 100, 1) if count else None,
        "avg_ms": round(sum(rtts) / len(rtts), 1) if rtts else None,
        "jitter_ms": jitter_ms,
    }


def check_internet_reachability(targets=INTERNET_CHECK_TARGETS, timeout=2.0):
    """
    A1's one deliberate exception to "only A7 touches the internet" (see
    CLAUDE.md's Architecture section) -- a lightweight reachability TEST,
    not a dependency. Nothing else in this file needs this to succeed;
    everything else works fully offline. This exists because the
    product's whole vision is diagnosing network issues *including* when
    the internet connection itself is the problem, which needs an actual
    check of whether the WAN path is up.

    Uses a plain TCP connect (not ICMP) to a couple of well-known IPs on
    port 443 -- no admin/root needed, and it reflects real usage (a
    browser doing HTTPS) better than a ping would. Skippable with
    --no-internet.
    """
    checks = []
    reachable = False
    for ip, port in targets:
        start = time.monotonic()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            elapsed_ms = round((time.monotonic() - start) * 1000, 1)
            checks.append({"target": f"{ip}:{port}", "reachable": True, "latency_ms": elapsed_ms})
            reachable = True
        except OSError:
            checks.append({"target": f"{ip}:{port}", "reachable": False, "latency_ms": None})
        finally:
            s.close()
    return {"reachable": reachable, "checks": checks}


# IANA-reserved for documentation/testing (RFC 2606) -- guaranteed to
# exist and never used for anything real, so it's about as stable a
# target as a DNS resolution test can have.
_DNS_TEST_HOSTNAME = "example.com"


def _encode_dns_name(hostname):
    """Encodes a hostname into DNS wire format: length-prefixed labels
    ending in a zero byte, e.g. "example.com" -> b'\\x07example\\x03com\\x00'."""
    parts = hostname.strip(".").split(".")
    return b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"


def _build_dns_query(hostname, query_id, qtype=1):
    """Builds a minimal DNS query packet (header + one question) by
    hand -- there's no stdlib DNS client, and we specifically need to
    query one exact server rather than however the OS resolver decides
    to pick among configured servers. `qtype` defaults to 1 (A, what
    check_dns_resolution() uses); discover_mdns_devices() passes 12
    (PTR) for its mDNS service-discovery query."""
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(hostname) + struct.pack(">HH", qtype, 1)  # class IN
    return header + question


def _parse_dns_response(data, expected_id):
    """Reads just the DNS response header -- enough to know whether the
    server answered our exact query successfully, without needing a full
    resource-record parser."""
    if len(data) < 12:
        return None
    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    if resp_id != expected_id:
        return None
    return {
        "is_response": bool(flags & 0x8000),
        "rcode": flags & 0x000F,
        "answer_count": ancount,
    }


def check_dns_resolution(dns_servers=None, timeout=2.0):
    """
    Tests whether each *configured* DNS server actually resolves names,
    instead of just reading the config and assuming it works. This is
    the "internet is reachable but DNS is broken" case -- ISP DNS server
    down, DNS hijacked/misconfigured, a captive portal -- which looks
    identical to "internet is down" to a non-technical user, but has a
    completely different fix.

    A1's second deliberate exception to "only A7 touches the internet"
    (see check_internet_reachability() and CLAUDE.md's Architecture
    section): most configured DNS servers live off-LAN, so testing one
    means an outbound query. Same as the reachability check, this is a
    diagnostic TEST, not a dependency -- gated under the same
    --no-internet flag since both are the same category of operation.

    Sends a raw DNS query directly to each server (not through the OS
    resolver, which can't be pointed at one specific server) for
    example.com. Returns {"servers_tested": [...], "any_working": bool}.
    """
    if dns_servers is None:
        dns_servers, _ = get_dns_servers()

    results = []
    for server in dns_servers:
        query_id = random.randint(0, 65535)
        query = _build_dns_query(_DNS_TEST_HOSTNAME, query_id)
        start = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (server, 53))
            data, _addr = sock.recvfrom(512)
            elapsed_ms = round((time.monotonic() - start) * 1000, 1)
            parsed = _parse_dns_response(data, query_id)
            if parsed and parsed["is_response"] and parsed["rcode"] == 0 and parsed["answer_count"] > 0:
                results.append({"server": server, "working": True, "latency_ms": elapsed_ms, "error": None})
            elif parsed:
                results.append({
                    "server": server, "working": False, "latency_ms": elapsed_ms,
                    "error": f"responded but rcode={parsed['rcode']} answers={parsed['answer_count']}",
                })
            else:
                results.append({"server": server, "working": False, "latency_ms": None, "error": "malformed or mismatched response"})
        except socket.timeout:
            results.append({"server": server, "working": False, "latency_ms": None, "error": "timed out"})
        except OSError as e:
            results.append({"server": server, "working": False, "latency_ms": None, "error": str(e)})
        finally:
            sock.close()

    return {"servers_tested": results, "any_working": any(r["working"] for r in results)}


# Firewall rule scanning -- see check_firewall_rules() below. Deliberately
# a small, named table, not "every port": each one maps to a symptom
# A1/A2 can already detect and correlate against (see A2's
# check_firewall_blocking()) -- DNS -> DNS not resolving, HTTP/HTTPS ->
# internet unreachable (check_internet_reachability() itself tests port
# 443), DHCP -> no gateway found at all. Widening this to every possible
# port would mean flagging a customer's legitimate custom rule (blocking
# some unrelated app's port) as if it explains a connectivity problem it
# has nothing to do with.
_CONNECTIVITY_PORTS = {
    53: ("DNS", {"tcp", "udp"}),
    80: ("HTTP", {"tcp"}),
    443: ("HTTPS", {"tcp", "udp"}),  # udp covers HTTP/3 (QUIC)
    67: ("DHCP (server)", {"udp"}),
    68: ("DHCP (client)", {"udp"}),
}


def _port_matches(port_field, port):
    """
    Best-effort check for whether a rule's port field includes the given
    port number. Handles the formats netsh/iptables/pfctl all use in some
    form: a single port ("53"), a comma list ("53,80"), or a range
    ("50-60"). Returns False for anything unparseable rather than
    guessing.
    """
    if not port_field:
        return False
    for part in str(port_field).split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                if int(lo) <= port <= int(hi):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == port:
                    return True
            except ValueError:
                continue
    return False


def _matched_connectivity_service(port_field, protocol):
    """
    Checks a rule's port field against every port in _CONNECTIVITY_PORTS
    for the given protocol, returning (port, service_name) for the first
    match, or (None, None). A rule's port field can be a single port, a
    comma list, or a range -- _port_matches() already handles all three.
    """
    for port, (service, protocols) in _CONNECTIVITY_PORTS.items():
        if protocol in protocols and _port_matches(port_field, port):
            return port, service
    return None, None


def _firewall_windows(errors):
    """
    Parses `netsh advfirewall firewall show rule name=all` into per-rule
    blocks, then keeps only the enabled Block rules whose protocol/port
    match one of _CONNECTIVITY_PORTS, ICMP, or a blanket "blocks all
    remote ports" rule (Protocol=Any or RemotePort=Any, outbound --
    service "ALL"). A blanket rule doesn't map to one connectivity
    service; it's evidence against all of them at once, so it's kept in
    a separate category rather than forced into the five-service table.
    Reading rules this way doesn't need elevation on Windows, unlike the
    Linux/macOS paths.
    """
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, errors="ignore", timeout=20,
        )
    except FileNotFoundError:
        errors.append("netsh not found (unexpected on Windows)")
        return []
    except subprocess.TimeoutExpired:
        errors.append("netsh advfirewall show rule timed out")
        return []
    if result.returncode != 0:
        errors.append(f"netsh advfirewall firewall show rule failed: {(result.stderr or result.stdout).strip()}")
        return []

    rules = []
    current = {}
    for line in result.stdout.splitlines():
        line = line.rstrip()
        if line.startswith("Rule Name:"):
            if current:
                rules.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif ":" in line and current:
            key, _, val = line.partition(":")
            current[key.strip()] = val.strip()
    if current:
        rules.append(current)

    if not rules:
        errors.append("netsh advfirewall ran but no rules were parsed -- output may not match the expected format")
        return []

    suspects = []
    for r in rules:
        if r.get("Enabled") != "Yes" or r.get("Action") != "Block":
            continue
        protocol = (r.get("Protocol") or "").lower()
        direction = (r.get("Direction") or "").lower()
        is_icmp = protocol.startswith("icmpv4") or protocol.startswith("icmpv6") or protocol == "icmp"
        is_blanket = direction == "out" and (
            protocol == "any" or (r.get("RemotePort") or "").strip().lower() == "any"
        )
        port, service = (None, None)
        if is_blanket:
            service = "ALL"
        elif protocol in ("tcp", "udp"):
            port, service = _matched_connectivity_service(r.get("LocalPort"), protocol)
        if service or is_icmp:
            suspects.append({
                "name": r.get("name", "unnamed rule"),
                "direction": direction or None,
                "protocol": "icmp" if is_icmp else protocol,
                "port": port,
                "service": "ICMP" if is_icmp else service,
                "action": "block",
            })
    return suspects


def _windows_firewall_profile_policy(errors):
    """
    Reads whether the currently active Windows Firewall profile blocks
    outbound connections by default -- a policy-level setting, not an
    individual rule, so it's invisible to _firewall_windows()'s per-rule
    parsing no matter how that's extended. `netsh advfirewall show
    currentprofile` reports it directly. Returns True/False, or None if
    it couldn't be read (with the reason in errors).
    """
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "currentprofile"],
            capture_output=True, text=True, errors="ignore", timeout=10,
        )
    except FileNotFoundError:
        errors.append("netsh not found (unexpected on Windows)")
        return None
    except subprocess.TimeoutExpired:
        errors.append("netsh advfirewall show currentprofile timed out")
        return None
    if result.returncode != 0:
        errors.append(f"netsh advfirewall show currentprofile failed: {(result.stderr or result.stdout).strip()}")
        return None

    m = re.search(r"Outbound connections\s*:\s*(\w+)", result.stdout, re.IGNORECASE)
    if not m:
        errors.append(
            "netsh advfirewall show currentprofile ran but no \"Outbound connections\" "
            "setting was found -- output may not match the expected format"
        )
        return None
    return m.group(1).strip().lower() == "block"


# iptables normally prints protocol names (udp/tcp/icmp/all), but on at
# least one real system tested against (a minimal container, despite a
# populated /etc/protocols) it printed raw protocol numbers instead --
# caught by testing against a real ruleset, not assumed. Mapped here so
# parsing doesn't silently miss rules just because of that difference.
# "0" is the kernel's IPPROTO_IP sentinel, which is what a rule with no
# -p at all shows as here -- caught the same way, by testing a real
# unrestricted rule and seeing "0" instead of the expected "all".
_IPTABLES_PROTO_NUMBERS = {"0": "all", "1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}


def _firewall_linux_iptables(errors):
    """
    Parses `iptables -L -n` for DROP/REJECT rules matching a port in
    _CONNECTIVITY_PORTS, ICMP, or a blanket rule (no -p given, shows as
    protocol "all") -- service "ALL", same reasoning as the Windows
    blanket case: it isn't one connectivity service, it's evidence
    against all of them. Also recognizes a chain's own default policy
    (`Chain OUTPUT (policy DROP)`) as its own "ALL" suspect -- a
    genuinely different mechanism from an individual rule, previously
    invisible because the chain-header regex only ever captured the
    chain name, never the policy verdict next to it.

    Returns None (not []) on any failure to read the ruleset at all, so
    the caller can fall back to nft -- an empty list means "read the
    ruleset successfully, found nothing matching," a real and useful
    result that shouldn't trigger a fallback.
    """
    try:
        result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("iptables not installed")
        return None
    except subprocess.TimeoutExpired:
        errors.append("iptables -L timed out")
        return None
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"iptables -L failed: {msg}")
        if "permission denied" in msg.lower() or "not running" in msg.lower():
            errors.append("Reading iptables rules usually needs root -- try running with sudo.")
        return None

    suspects = []
    chain = None
    for line in result.stdout.splitlines():
        chain_m = re.match(r"^Chain (\S+)(?:\s*\(policy (\w+)\))?", line)
        if chain_m:
            chain = chain_m.group(1)
            policy = chain_m.group(2)
            if policy in ("DROP", "REJECT") and chain in ("INPUT", "OUTPUT"):
                suspects.append({
                    "name": f"{chain} chain default policy: {policy}",
                    "direction": {"INPUT": "in", "OUTPUT": "out"}.get(chain),
                    "protocol": "all",
                    "port": None,
                    "service": "ALL",
                    "action": policy.lower(),
                })
            continue
        parts = line.split()
        if len(parts) < 2 or parts[0] not in ("DROP", "REJECT"):
            continue
        target, raw_proto = parts[0], parts[1]
        proto = _IPTABLES_PROTO_NUMBERS.get(raw_proto, raw_proto)
        is_icmp = proto in ("icmp", "icmpv6")
        is_blanket = proto == "all"
        port, service = (None, None)
        if is_blanket:
            service = "ALL"
        elif proto in ("tcp", "udp"):
            port_m = re.search(r"dpt:(\d+)", line)
            if port_m:
                candidate = int(port_m.group(1))
                entry = _CONNECTIVITY_PORTS.get(candidate)
                if entry and proto in entry[1]:
                    port, service = candidate, entry[0]
        if service or is_icmp:
            suspects.append({
                "name": f"{chain or '?'} chain: {target} {proto}",
                "direction": {"INPUT": "in", "OUTPUT": "out", "FORWARD": "forward"}.get(chain, chain),
                "protocol": "icmp" if is_icmp else proto,
                "port": port,
                "service": "ICMP" if is_icmp else service,
                "action": target.lower(),
            })
    return suspects


def _firewall_linux_nft(errors):
    """
    Fallback for nftables-only systems (no iptables shim installed).
    Coarse line-based parsing, not a full nft grammar parser -- looks for
    drop/reject lines that also mention ICMP or a _CONNECTIVITY_PORTS
    match, same "good enough, report clearly when it isn't" approach as
    the rest of this file's OS-tool parsing.

    Also recognizes two blanket-block shapes as service "ALL": a chain's
    own `policy drop;`/`policy reject;` line (nft's default-policy
    syntax), and a drop/reject statement that names neither a port nor
    ICMP at all -- most likely an unrestricted rule. This is a looser
    heuristic than the other nft matches, flagged as such: nft can drop
    a single non-tcp/udp/icmp protocol this same way, which would look
    identical here. Kept anyway because missing an actual blanket rule
    is worse than an occasional over-broad flag on this fallback path.
    """
    try:
        result = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("nft not installed")
        return None
    except subprocess.TimeoutExpired:
        errors.append("nft list ruleset timed out")
        return None
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"nft list ruleset failed: {msg}")
        if "permission denied" in msg.lower():
            errors.append("Reading nftables rules usually needs root -- try running with sudo.")
        return None

    suspects = []
    for line in result.stdout.splitlines():
        stripped = line.strip()

        policy_m = re.match(r"^policy\s+(drop|reject)\s*;?", stripped, re.IGNORECASE)
        if policy_m:
            suspects.append({
                "name": stripped, "direction": None, "protocol": "all",
                "port": None, "service": "ALL", "action": policy_m.group(1).lower(),
            })
            continue

        if not re.search(r"\b(drop|reject)\b", stripped, re.IGNORECASE):
            continue
        is_icmp = re.search(r"\bicmpx?(v6)?\b", stripped, re.IGNORECASE) is not None
        proto = "udp" if "udp" in stripped.lower() else "tcp" if "tcp" in stripped.lower() else None
        port, service = (None, None)
        if proto:
            port_m = re.search(r"dport\s+(\d+)", stripped)
            if port_m:
                candidate = int(port_m.group(1))
                entry = _CONNECTIVITY_PORTS.get(candidate)
                if entry and proto in entry[1]:
                    port, service = candidate, entry[0]
        is_blanket = not is_icmp and not service and proto is None
        if is_blanket:
            service = "ALL"
        if service or is_icmp:
            suspects.append({
                "name": stripped,
                "direction": None,
                "protocol": "icmp" if is_icmp else (proto or "all"),
                "port": port,
                "service": "ICMP" if is_icmp else service,
                "action": "drop" if re.search(r"\bdrop\b", stripped, re.IGNORECASE) else "reject",
            })
    return suspects


def _firewall_macos(errors):
    """
    Parses `pfctl -sr` for block rules matching a port in
    _CONNECTIVITY_PORTS, ICMP, or a blanket rule -- a `block` line naming
    neither `udp` nor `tcp`. That's correct pf semantics, not a guess:
    pf rules apply to all protocols by default when `proto` is omitted,
    so the absence of either keyword genuinely means "blocks everything,"
    same reasoning as iptables' protocol "all" rows. Needs root -- pfctl's
    own error message says so plainly, so that's passed through rather
    than guessed at.
    """
    try:
        result = subprocess.run(["pfctl", "-sr"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("pfctl not found (unexpected on macOS)")
        return []
    except subprocess.TimeoutExpired:
        errors.append("pfctl -sr timed out")
        return []
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"pfctl -sr failed: {msg}")
        if "must be root" in msg.lower() or "permission" in msg.lower():
            errors.append("Reading pf rules needs root -- try running with sudo.")
        return []

    suspects = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not re.match(r"^block\b", stripped, re.IGNORECASE):
            continue
        lower = stripped.lower()
        is_icmp = "icmp" in lower
        proto = "udp" if "udp" in lower else "tcp" if "tcp" in lower else None
        port, service = (None, None)
        if proto:
            port_m = re.search(r"port\s*=?\s*(\d+)", lower)
            if port_m:
                candidate = int(port_m.group(1))
                entry = _CONNECTIVITY_PORTS.get(candidate)
                if entry and proto in entry[1]:
                    port, service = candidate, entry[0]
        is_blanket = not is_icmp and not service and proto is None
        if is_blanket:
            service = "ALL"
        if service or is_icmp:
            direction = "in" if re.search(r"\bin\b", lower) else "out" if re.search(r"\bout\b", lower) else None
            suspects.append({
                "name": stripped,
                "direction": direction,
                "protocol": "icmp" if is_icmp else (proto or "all"),
                "port": port,
                "service": "ICMP" if is_icmp else service,
                "action": "block",
            })
    return suspects


def check_firewall_rules():
    """
    Reads the actual local firewall ruleset for any rule that blocks one
    of _CONNECTIVITY_PORTS (DNS, HTTP, HTTPS, DHCP), ICMP, or blocks
    everything (service "ALL" -- see _firewall_windows()/
    _firewall_linux_iptables()/etc. for what that covers per platform,
    including Windows' profile-level default outbound policy, which is
    a separate check since it isn't a rule at all). Pure data gathering,
    same as every other function in this file -- this reports what
    rules exist, it doesn't decide whether one of them explains a
    connectivity problem. A2's check_firewall_blocking() is what
    correlates a matching rule against an actual failure and calls it a
    likely cause.

    Only returns that small, curated subset of rules, not a full ruleset
    dump -- nothing downstream needs the rest, and a wider net would mean
    flagging a customer's legitimate custom rule as if it were the cause
    of a problem it has nothing to do with. "ALL" is the one deliberate
    exception to "curated by specific service" -- a blanket rule isn't
    a legitimate custom rule for something unrelated, it's evidence
    against every connectivity symptom at once.

    Known limitation: reading the full ruleset needs root on Linux
    (iptables/nft) and macOS (pfctl). Without it, the errors list
    explains why instead of silently returning "no blocking rules found"
    -- an empty result has to be distinguishable from "couldn't check,"
    same reasoning behind every other error-surfacing fix in this file.
    Windows' netsh advfirewall doesn't need elevation to read rules.

    Returns (suspect_rules, errors).
    """
    errors = []
    suspects = []
    try:
        if SYSTEM == "Windows":
            suspects = _firewall_windows(errors)
            outbound_blocked = _windows_firewall_profile_policy(errors)
            if outbound_blocked:
                suspects.append({
                    "name": "Windows Firewall profile default (Outbound connections: Block)",
                    "direction": "out", "protocol": "all", "port": None,
                    "service": "ALL", "action": "block",
                })
        elif SYSTEM == "Linux":
            result = _firewall_linux_iptables(errors)
            if result is None:
                result = _firewall_linux_nft(errors)
            if result is None:
                errors.append("could not read firewall rules via iptables or nft")
                suspects = []
            else:
                suspects = result
        elif SYSTEM == "Darwin":
            suspects = _firewall_macos(errors)
        else:
            errors.append(f"unrecognized platform: {SYSTEM}")
    except Exception as e:
        errors.append(f"unexpected error checking firewall rules: {e}")
    return suspects, errors


# UPnP IGD (Internet Gateway Device) -- see query_upnp_gateway() below for
# what this is and why it needs no router credentials.
_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_UPNP_DEVICE_NS = "urn:schemas-upnp-org:device-1-0"


def _ssdp_discover(timeout=3.0, search_target="urn:schemas-upnp-org:device:InternetGatewayDevice:1"):
    """
    Sends a UPnP SSDP M-SEARCH multicast request and collects LOCATION
    URLs from any device that answers. This is the standard way UPnP
    devices are found on a LAN -- no credentials, no prior knowledge of
    a device's IP needed, just a multicast question on the local
    network.

    `search_target` defaults to InternetGatewayDevice (query_upnp_gateway()'s
    original, narrower use); discover_upnp_devices() passes "ssdp:all"
    to widen this to every SSDP-speaking device on the LAN, not just the
    router.
    """
    request = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}",
        'MAN: "ssdp:discover"',
        "MX: 2",
        f"ST: {search_target}",
        "", "",
    ]).encode()

    locations = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)
    deadline = time.monotonic() + timeout
    try:
        sock.sendto(request, (_SSDP_ADDR, _SSDP_PORT))
        while time.monotonic() < deadline:
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode(errors="ignore")
            m = re.search(r"^LOCATION:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)
            if m and m.group(1) not in locations:
                locations.append(m.group(1))
    except OSError:
        pass
    finally:
        sock.close()
    return locations


def _fetch_device_description_xml(location_url, timeout=3.0):
    """Downloads and parses a UPnP device's description XML (a plain,
    unauthenticated HTTP GET) into an ElementTree. Returns None on any
    failure -- fetching, timing out, or malformed XML. Used by both
    query_upnp_gateway() (IGD-specific) and discover_upnp_devices() (any
    SSDP-speaking device) -- this was already generic, just renamed to
    reflect that it's not IGD-specific."""
    try:
        with urllib.request.urlopen(location_url, timeout=timeout) as resp:
            xml_bytes = resp.read()
        return ET.fromstring(xml_bytes)
    except (urllib.error.URLError, OSError, ValueError, ET.ParseError):
        return None


def _find_igd_service(root, base_url, wanted_substrings):
    """
    Searches a parsed IGD description tree for the first service whose
    serviceType contains any of `wanted_substrings` (e.g.
    "WANIPConnection"), at any nesting depth -- IGD services are
    typically nested a few devices deep (root -> WANDevice ->
    WANConnectionDevice -> the actual service), and ElementTree's
    .iter() searches all descendants regardless of depth. Returns
    (control_url, service_type), or (None, None) if nothing matched.
    """
    def tag(name):
        return f"{{{_UPNP_DEVICE_NS}}}{name}"

    for service in root.iter(tag("service")):
        service_type = service.findtext(tag("serviceType")) or ""
        if any(w in service_type for w in wanted_substrings):
            control = service.findtext(tag("controlURL"))
            if control:
                if not control.startswith("http"):
                    control = base_url + (control if control.startswith("/") else "/" + control)
                return control, service_type
    return None, None


def _soap_call(control_url, service_type, action, timeout=3.0):
    """
    Sends a UPnP SOAP action call (a plain HTTP POST with an XML body --
    no auth) and returns every leaf element's text from the response,
    keyed by tag name (e.g. {"NewExternalIPAddress": "41.x.x.x"}).
    Returns None on any failure.
    """
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:{action} xmlns:u="{service_type}"></u:{action}>'
        "</s:Body></s:Envelope>"
    ).encode()

    req = urllib.request.Request(
        control_url,
        data=body,
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service_type}#{action}"',
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_bytes = resp.read()
    except (urllib.error.URLError, OSError, ValueError):
        return None

    try:
        root = ET.fromstring(resp_bytes)
    except ET.ParseError:
        return None

    result = {}
    for elem in root.iter():
        tag_name = elem.tag.split("}")[-1]
        if elem.text and elem.text.strip() and not list(elem):
            result[tag_name] = elem.text.strip()
    return result


# Cheap consumer routers' UPnP stacks are frequently buggy -- these are
# the specific, recognizable ways that shows up in practice (see
# _upnp_sanity_notes()), not an exhaustive validity check.
_UPNP_MAX_UINT32 = 2**32 - 1
_UPNP_IMPLAUSIBLE_UPTIME_SECONDS = 5 * 365 * 24 * 3600  # ~5 years


def _upnp_sanity_notes(info):
    """
    UPnP IGD implementations on cheap consumer routers are frequently
    buggy. A response can be well-formed and still be nonsense -- this
    checks for the specific ways that showed up on Ammar's real Tenda
    router (a "external" IP that's actually private, an uptime of
    decades, a traffic counter sitting at exactly 2^32-1) and returns
    plain-language notes about them, instead of silently printing
    whatever the firmware said as if it were trustworthy.
    """
    notes = []

    ext_ip = info.get("external_ip")
    if ext_ip:
        try:
            if ipaddress.ip_address(ext_ip).is_private:
                notes.append(
                    f"external_ip ({ext_ip}) is itself a private address -- a real WAN IP "
                    "can't be private. This router is behind another router/NAT (double-NAT), "
                    "common with some FTTH ONT/modem setups. Port forwarding may need to "
                    "happen on the upstream device instead."
                )
        except ValueError:
            pass

    uptime = info.get("uptime_seconds")
    if uptime is not None:
        try:
            uptime_int = int(uptime)
            if uptime_int > _UPNP_IMPLAUSIBLE_UPTIME_SECONDS:
                years = round(uptime_int / (365 * 24 * 3600), 1)
                notes.append(
                    f"uptime_seconds ({uptime_int}, about {years} years) is implausible for a "
                    "home router -- almost certainly a bug in this router's UPnP firmware, not "
                    "a real reading."
                )
        except (TypeError, ValueError):
            pass

    for key in ("total_bytes_sent", "total_bytes_received"):
        val = info.get(key)
        if val is not None:
            try:
                if int(val) == _UPNP_MAX_UINT32:
                    notes.append(
                        f"{key} is exactly 2^32-1 -- the signature of either an overflowed/"
                        "wrapped 32-bit counter or a \"not really supported\" sentinel value. "
                        "Not a reliable measurement."
                    )
            except (TypeError, ValueError):
                pass

    return notes


def query_upnp_gateway(timeout=3.0):
    """
    Talks to the router via UPnP IGD (Internet Gateway Device) -- a real,
    standardized protocol most consumer routers (Tenda/TP-Link included)
    support, and one that's normally unauthenticated on the LAN by
    design (it exists so any app can request port-forwarding without a
    login prompt). No router credentials needed, unlike the web admin
    panel.

    This only ever covers what the standard exposes: WAN/external IP,
    connection status, uptime, and (best-effort) traffic byte counters.
    It does NOT get the DHCP client list or the router's actual
    configured DHCP range -- that data only lives behind the router's
    own web admin login, which UPnP doesn't expose. See CLAUDE.md's
    "Flagged / open decisions" for that piece.

    Known gap: the WANCommonInterfaceConfig traffic-counter lookup is
    unverified against real hardware -- not every router implements it,
    and a missing/failed result there is treated as "not available,"
    not an error, since it's a bonus on top of the core WAN info.

    A successful response isn't necessarily a *trustworthy* one -- see
    _upnp_sanity_notes(), which info["notes"] holds the output of.

    Returns (info, errors). info is {} if no IGD was found at all.
    """
    errors = []
    info = {}

    locations = _ssdp_discover(timeout=timeout)
    if not locations:
        errors.append(
            "No UPnP Internet Gateway Device responded to SSDP discovery "
            "(some routers have UPnP turned off by default)"
        )
        return info, errors

    root = None
    base_url = None
    for location in locations:
        candidate_root = _fetch_device_description_xml(location, timeout=timeout)
        if candidate_root is not None:
            parsed = urllib.parse.urlparse(location)
            root = candidate_root
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            break
    if root is None:
        errors.append(f"Found {len(locations)} UPnP device(s) but couldn't fetch/parse their description XML")
        return info, errors

    control_url, service_type = _find_igd_service(root, base_url, ("WANIPConnection", "WANPPPConnection"))
    if not control_url:
        errors.append("No WANIPConnection/WANPPPConnection service found in the UPnP device description")
        return info, errors
    info["control_url"] = control_url
    info["service_type"] = service_type

    ext_ip = _soap_call(control_url, service_type, "GetExternalIPAddress", timeout=timeout)
    if ext_ip and "NewExternalIPAddress" in ext_ip:
        info["external_ip"] = ext_ip["NewExternalIPAddress"]
    else:
        errors.append("GetExternalIPAddress did not return a usable response")

    status = _soap_call(control_url, service_type, "GetStatusInfo", timeout=timeout)
    if status:
        info["connection_status"] = status.get("NewConnectionStatus")
        info["uptime_seconds"] = status.get("NewUptime")
        info["last_connection_error"] = status.get("NewLastConnectionError")
    else:
        errors.append("GetStatusInfo did not return a usable response")

    # Traffic counters live on a different service (WANCommonInterfaceConfig,
    # a sibling of WANIPConnection) that not every router implements --
    # best-effort, missing is normal, not an error.
    traffic_control_url, traffic_service_type = _find_igd_service(root, base_url, ("WANCommonInterfaceConfig",))
    if traffic_control_url:
        sent = _soap_call(traffic_control_url, traffic_service_type, "GetTotalBytesSent", timeout=timeout)
        received = _soap_call(traffic_control_url, traffic_service_type, "GetTotalBytesReceived", timeout=timeout)
        if sent and "NewTotalBytesSent" in sent:
            info["total_bytes_sent"] = sent["NewTotalBytesSent"]
        if received and "NewTotalBytesReceived" in received:
            info["total_bytes_received"] = received["NewTotalBytesReceived"]

    info["notes"] = _upnp_sanity_notes(info)
    return info, errors


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


def _to_int(value):
    """Best-effort int conversion; returns None instead of raising."""
    if value is None:
        return None
    try:
        return int(float(str(value).strip().rstrip("%")))
    except (TypeError, ValueError):
        return None


def _freq_to_channel(freq_mhz):
    """Converts a Wi-Fi frequency in MHz (what `iw` reports) to a channel
    number. Covers 2.4GHz, 5GHz, and 6GHz (Wi-Fi 6E)."""
    try:
        freq = int(float(freq_mhz))
    except (TypeError, ValueError):
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if 5000 <= freq <= 5895:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return None


def _scan_wifi_windows(errors):
    networks = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, errors="ignore", timeout=20,
        )
    except FileNotFoundError:
        errors.append("netsh not found (unexpected on Windows)")
        return networks
    except subprocess.TimeoutExpired:
        errors.append("netsh timed out")
        return networks

    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"netsh failed: {msg}")
        if "powered down" in msg.lower():
            errors.append(
                "The Wi-Fi adapter is turned off -- check the physical Wi-Fi switch/"
                "function key, Airplane mode, or enable the adapter in Windows network "
                "adapter settings. (See the interface status list above -- Wi-Fi should "
                "show as DOWN there too.)"
            )
        return networks

    current = {}
    # wps_enabled deliberately not attempted here -- `netsh wlan show
    # networks` doesn't expose WPS status cleanly, so it's left absent
    # rather than guessed (see _scan_wifi_iw()'s Linux-only WPS parsing).
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("SSID") and " BSSID" not in line:
            if current:
                networks.append(current)
            current = {"ssid": line.split(":", 1)[1].strip(), "channel": None, "signal": None}
        elif line.startswith("Signal"):
            current["signal"] = _to_int(line.split(":", 1)[1])
        elif line.startswith("Authentication"):
            current["security"] = line.split(":", 1)[1].strip()
        elif line.startswith("Channel"):
            current["channel"] = _to_int(line.split(":", 1)[1])
    if current:
        networks.append(current)

    if not networks and not result.stdout.strip():
        errors.append("netsh returned no output -- is Wi-Fi turned on?")
    return networks


def _scan_wifi_nmcli(errors):
    networks = []
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, errors="ignore", timeout=20,
        )
    except FileNotFoundError:
        errors.append("nmcli not installed")
        return None
    except subprocess.TimeoutExpired:
        errors.append("nmcli timed out")
        return None

    if result.returncode != 0:
        errors.append(f"nmcli failed: {(result.stderr or result.stdout).strip()}")
        return None

    # wps_enabled deliberately not attempted here -- nmcli's terse wifi
    # list output doesn't expose WPS status cleanly, so it's left absent
    # rather than guessed (see _scan_wifi_iw()'s Linux-only WPS parsing).
    for line in result.stdout.splitlines():
        # nmcli terse output backslash-escapes literal colons inside a
        # field, so split on unescaped colons only.
        parts = re.split(r"(?<!\\):", line)
        parts = [p.replace("\\:", ":") for p in parts]
        if len(parts) >= 4 and parts[0]:
            networks.append({
                "ssid": parts[0],
                "signal": _to_int(parts[1]),
                "channel": _to_int(parts[2]),
                "security": parts[3] or "Open",
            })
    return networks


def _scan_wifi_iw(errors):
    try:
        dev_out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("iw not installed")
        return None
    except subprocess.TimeoutExpired:
        errors.append("iw dev timed out")
        return None
    if dev_out.returncode != 0:
        errors.append(f"iw dev failed: {(dev_out.stderr or dev_out.stdout).strip()}")
        return None

    iface_m = re.search(r"Interface (\S+)", dev_out.stdout)
    if not iface_m:
        errors.append("iw dev found no wireless interface")
        return None
    iface = iface_m.group(1)

    try:
        scan_out = subprocess.run(["iw", "dev", iface, "scan"], capture_output=True, text=True, timeout=25)
    except subprocess.TimeoutExpired:
        errors.append(f"iw dev {iface} scan timed out")
        return None

    if scan_out.returncode != 0:
        msg = (scan_out.stderr or scan_out.stdout).strip()
        errors.append(f"iw dev {iface} scan failed: {msg}")
        if "not permitted" in msg.lower() or "denied" in msg.lower():
            errors.append("Wi-Fi scanning on Linux usually needs root -- try running with sudo.")
        return None

    networks = []
    current = None
    for line in scan_out.stdout.splitlines():
        stripped = line.strip()
        if line.startswith("BSS "):
            if current:
                networks.append(current)
            # wps_enabled: only attempted here (Linux/iw) -- `iw scan`
            # dumps a WPS information element when the AP advertises one.
            # Windows/macOS scan tools don't expose WPS status cleanly,
            # so it's not attempted there rather than guessed (see the
            # other four _scan_wifi_* parsers).
            current = {"ssid": None, "channel": None, "signal": None, "security": "Open", "wps_enabled": False}
        elif current is None:
            continue
        elif stripped.startswith("freq:"):
            current["channel"] = _freq_to_channel(stripped.split(":", 1)[1].strip())
        elif stripped.startswith("signal:"):
            current["signal"] = _to_int(stripped.split(":", 1)[1].replace("dBm", ""))
        elif stripped.startswith("SSID:"):
            current["ssid"] = stripped.split(":", 1)[1].strip() or "(hidden)"
        elif stripped.startswith("RSN:") or stripped.startswith("WPA:"):
            current["security"] = "WPA/WPA2"
        elif stripped.startswith("WPS:"):
            current["wps_enabled"] = True
    if current:
        networks.append(current)

    if not networks and not scan_out.stdout.strip():
        errors.append(f"iw dev {iface} scan returned no output")
    return networks


def _scan_wifi_iwlist(errors):
    try:
        result = subprocess.run(["iwlist", "scan"], capture_output=True, text=True, errors="ignore", timeout=25)
    except FileNotFoundError:
        errors.append("iwlist not installed (install wireless-tools, or use NetworkManager for nmcli)")
        return None
    except subprocess.TimeoutExpired:
        errors.append("iwlist scan timed out")
        return None

    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        errors.append(f"iwlist scan failed: {msg}")
        if "not permitted" in msg.lower():
            errors.append("Wi-Fi scanning on Linux usually needs root -- try running with sudo.")
        return None

    networks = []
    current = None
    # wps_enabled deliberately not attempted here -- iwlist's scan output
    # doesn't expose WPS status cleanly, so it's left absent rather than
    # guessed (see _scan_wifi_iw()'s Linux-only WPS parsing).
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Cell"):
            if current:
                networks.append(current)
            current = {"ssid": None, "channel": None, "signal": None, "security": "Open"}
        elif current is None:
            continue
        elif line.startswith("ESSID"):
            current["ssid"] = line.split(":", 1)[1].strip('"') or "(hidden)"
        elif "Signal level" in line:
            m = re.search(r"Signal level[=:](-?\d+)", line)
            if m:
                current["signal"] = int(m.group(1))
        elif line.startswith("Channel:"):
            current["channel"] = _to_int(line.split(":", 1)[1])
        elif "Encryption key:on" in line:
            current["security"] = "WEP/WPA"
    if current:
        networks.append(current)
    return networks


def _scan_wifi_macos(errors):
    networks = []
    try:
        iface_out = subprocess.run(["networksetup", "-listallhardwareports"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        errors.append(f"networksetup -listallhardwareports failed: {e}")
        return networks

    iface_m = re.search(r"Hardware Port: Wi-Fi\nDevice: (\w+)", iface_out.stdout)
    iface = iface_m.group(1) if iface_m else "en0"

    try:
        result = subprocess.run(["networksetup", "-getairportnetwork", iface], capture_output=True, text=True, errors="ignore", timeout=10)
    except subprocess.TimeoutExpired:
        errors.append("networksetup -getairportnetwork timed out")
        return networks

    if result.returncode != 0:
        errors.append(f"networksetup failed: {(result.stderr or result.stdout).strip()}")
        return networks

    m = re.search(r"Current Wi-Fi Network:\s*(.+)", result.stdout)
    if m:
        # wps_enabled deliberately not attempted here -- networksetup
        # doesn't expose WPS status cleanly, so it's left absent rather
        # than guessed (see _scan_wifi_iw()'s Linux-only WPS parsing).
        networks.append({
            "ssid": m.group(1).strip(),
            "channel": None,
            "signal": None,
            "note": "current network only -- Apple removed the nearby-scan tool "
                    "(airport) from recent macOS versions, this is a platform limit",
        })
    else:
        errors.append("Not currently connected to Wi-Fi (macOS can only report the connected network)")
    return networks


def scan_wifi_networks():
    """
    Scans for nearby Wi-Fi networks using OS-native tools (no libraries).
    On macOS this can only report the currently connected network -- see
    _scan_wifi_macos().

    Returns (networks, errors). Every failure is reported in `errors`
    instead of being silently swallowed -- an earlier version of this
    function caught every exception and did nothing with it, so a failed
    scan looked identical to "no networks found."
    """
    errors = []
    networks = []
    try:
        if SYSTEM == "Windows":
            networks = _scan_wifi_windows(errors)
        elif SYSTEM == "Linux":
            # Try nmcli first (no root needed if NetworkManager owns the
            # interface), then iw, then the older iwlist -- in roughly
            # newest-and-most-likely-to-work to oldest order.
            networks = _scan_wifi_nmcli(errors)
            if not networks:
                networks = _scan_wifi_iw(errors)
            if not networks:
                networks = _scan_wifi_iwlist(errors)
            networks = networks or []
        elif SYSTEM == "Darwin":
            networks = _scan_wifi_macos(errors)
        else:
            errors.append(f"unrecognized platform: {SYSTEM}")
    except Exception as e:  # belt-and-braces -- every path above handles
        # its own errors, so reaching here means something unexpected.
        errors.append(f"unexpected error during Wi-Fi scan: {e}")

    return networks, errors


def _signal_weight(signal):
    """
    Turns a signal reading into a rough 0..1 "how disruptive is this to a
    neighbouring channel" weight. Signal comes in two scales depending on
    which tool found it: dBm (negative, e.g. -42, from iw/iwlist) or a
    0-100 percentage (nmcli, netsh). Unknown/missing readings get a
    neutral 0.5 so one bad reading doesn't zero out a whole channel.
    """
    if signal is None:
        return 0.5
    if signal < 0:
        return max(0.0, min(1.0, (signal + 90) / 60))
    return max(0.0, min(1.0, signal / 100))


def suggest_best_channel(networks):
    """
    Looks at every Wi-Fi network we saw and recommends the least congested
    channel, separately for 2.4GHz and 5GHz. Only networks with a
    parseable numeric channel count towards this -- one with no channel
    info just gets skipped.

    2.4GHz channels overlap their neighbours (each channel is 20MHz wide
    but they're spaced 5MHz apart), so a network on channel 3 partially
    congests channels 1 and 6 too. We only ever recommend among 1/6/11 --
    the three channels that don't overlap anything -- same as any
    professional Wi-Fi installer would.

    5GHz channels don't overlap each other the same way, so it's just
    "which channel has the fewest/weakest networks on it already."
    """
    band24 = [n for n in networks if n.get("channel") is not None and 1 <= n["channel"] <= 14]
    band5 = [n for n in networks if n.get("channel") is not None and n["channel"] >= 36]

    recommendation = {}

    if band24:
        scores = {}
        for ch in NONOVERLAPPING_24GHZ:
            score = 0.0
            for n in band24:
                distance = abs(n["channel"] - ch)
                if distance == 0:
                    weight = 1.0
                elif distance <= 4:
                    weight = (5 - distance) / 5
                else:
                    weight = 0.0
                score += weight * _signal_weight(n.get("signal"))
            scores[ch] = round(score, 2)
        best = min(scores, key=scores.get)
        recommendation["2.4ghz"] = {"recommended_channel": best, "congestion_by_channel": scores}

    if band5:
        scores = {ch: 0.0 for ch in COMMON_5GHZ}
        for n in band5:
            ch = n["channel"]
            scores[ch] = round(scores.get(ch, 0.0) + _signal_weight(n.get("signal")), 2)
        best = min(scores, key=scores.get)
        recommendation["5ghz"] = {"recommended_channel": best, "congestion_by_channel": scores}

    return recommendation


def get_interface_link_info():
    """
    Per-interface link speed (Mbps) and duplex. Linux reads
    /sys/class/net/<iface>/speed and /sys/class/net/<iface>/duplex
    directly -- plain file reads, no subprocess -- same "prefer a stable
    file read over parsing a CLI tool's output where one exists"
    precedent get_arp_table() already set with /proc/net/arp vs `arp -a`.
    Falls back to `ethtool <iface>` for whichever field the /sys read
    didn't give (a down interface, or certain virtual ones, report -1
    or raise PermissionError/OSError here -- not a bug, just "unknown",
    same as any other best-effort reading in this file).

    macOS shells out to `ifconfig <iface>` and regexes the `media:` line.
    Windows shells out to `wmic nic ... get Name,Speed` for speed only --
    wmic is a deprecated tool Microsoft is phasing out of newer Windows
    versions, flagged the same way this file flags every other
    known-fragile-tool choice. Duplex is deliberately NOT attempted on
    Windows -- there's no reliable non-PowerShell source, matching this
    file's existing precedent of declining to guess at the real Airplane
    Mode flag rather than ship a confidently-wrong reading (see
    get_wifi_radio_state()'s docstring).

    Returns ({interface_name: {"speed_mbps": int|None, "duplex":
    "full"/"half"/None}}, errors).
    """
    data = {}
    errors = []
    try:
        if SYSTEM == "Linux":
            interfaces, _ = get_interface_status()
            for iface in interfaces:
                name = iface["name"]
                entry = {"speed_mbps": None, "duplex": None}
                try:
                    with open(f"/sys/class/net/{name}/speed") as f:
                        speed = int(f.read().strip())
                    if speed > 0:
                        entry["speed_mbps"] = speed
                except (PermissionError, FileNotFoundError, OSError, ValueError):
                    # A down interface (or some virtual ones) reports -1
                    # here rather than raising -- not a bug, "unknown"
                    # either way.
                    pass
                try:
                    with open(f"/sys/class/net/{name}/duplex") as f:
                        raw = f.read().strip()
                    if raw in ("full", "half"):
                        entry["duplex"] = raw
                except (PermissionError, FileNotFoundError, OSError):
                    pass
                if entry["speed_mbps"] is None or entry["duplex"] is None:
                    try:
                        result = subprocess.run(["ethtool", name], capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            if entry["speed_mbps"] is None:
                                sm = re.search(r"Speed:\s*(\d+)Mb/s", result.stdout)
                                if sm:
                                    entry["speed_mbps"] = int(sm.group(1))
                            if entry["duplex"] is None:
                                dm = re.search(r"Duplex:\s*(Full|Half)", result.stdout)
                                if dm:
                                    entry["duplex"] = dm.group(1).lower()
                    except FileNotFoundError:
                        pass
                data[name] = entry
            if not data:
                errors.append("no interfaces found to read link speed/duplex for")

        elif SYSTEM == "Darwin":
            interfaces, _ = get_interface_status()
            for iface in interfaces:
                name = iface["name"]
                try:
                    result = subprocess.run(["ifconfig", name], capture_output=True, text=True, timeout=10)
                except FileNotFoundError:
                    errors.append("ifconfig not found")
                    break
                entry = {"speed_mbps": None, "duplex": None}
                if result.returncode == 0:
                    m = re.search(r"media:\s*\S+\s*\(([^)]*)\)", result.stdout)
                    if m:
                        media = m.group(1)
                        sm = re.search(r"(\d+)base", media)
                        if sm:
                            entry["speed_mbps"] = int(sm.group(1))
                        if "full-duplex" in media:
                            entry["duplex"] = "full"
                        elif "half-duplex" in media:
                            entry["duplex"] = "half"
                data[name] = entry
            if not data:
                errors.append("ifconfig ran but no interfaces returned media info")

        elif SYSTEM == "Windows":
            try:
                result = subprocess.run(
                    ["wmic", "nic", "where", "NetEnabled=true", "get", "Name,Speed", "/format:csv"],
                    capture_output=True, text=True, errors="ignore", timeout=20,
                )
            except FileNotFoundError:
                errors.append("wmic not found -- it's a deprecated tool Microsoft is phasing out of "
                               "newer Windows versions, this machine may not have it")
                return data, errors
            if result.returncode != 0:
                errors.append(f"wmic nic failed: {(result.stderr or result.stdout).strip()}")
                return data, errors
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            if len(lines) >= 2:
                header = lines[0].split(",")
                for line in lines[1:]:
                    parts = line.split(",")
                    if len(parts) != len(header):
                        continue
                    row = dict(zip(header, parts))
                    name = row.get("Name", "").strip()
                    speed_raw = row.get("Speed", "").strip()
                    if name:
                        speed_mbps = int(speed_raw) // 1_000_000 if speed_raw.isdigit() else None
                        # Duplex deliberately left None on Windows -- no
                        # reliable non-PowerShell source exists, and a
                        # confidently-wrong reading is worse than none
                        # (same precedent get_wifi_radio_state() sets for
                        # the real Airplane Mode flag).
                        data[name] = {"speed_mbps": speed_mbps, "duplex": None}
            if not data:
                errors.append("wmic ran but no enabled NICs were parsed -- output may not match the expected format")
    except Exception as e:
        errors.append(f"unexpected error reading interface link info: {e}")
    return data, errors


def get_windows_ipconfig_extra():
    """
    Windows-only consolidation function: one `ipconfig /all` pass,
    parsed once, for DHCP lease fields (dhcp_server/lease_obtained/
    lease_expires per interface), the top-level DNS suffix search list,
    and per-interface IPv6 addresses/gateway -- the same "one Windows
    pass over ipconfig /all" principle get_interface_network_config()
    already established for DNS/DHCP-mode/static-IP data, applied to a
    different slice of the same command's output rather than shelling
    out three more times for get_dhcp_lease_info(),
    get_dns_suffix_search_list(), and get_ipv6_status().

    On non-Windows platforms this simply isn't applicable -- returns
    empty data with no error (each of those three functions has its own
    separate, real implementation per platform instead).

    Returns ({"dns_suffix_search_list": [...], "interfaces": {name:
    {"dhcp_server", "lease_obtained", "lease_expires", "ipv6_addresses",
    "ipv6_gateway"}}}, errors).
    """
    data = {"dns_suffix_search_list": [], "interfaces": {}}
    errors = []
    if SYSTEM != "Windows":
        return data, errors
    try:
        try:
            result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors="ignore", timeout=10)
        except FileNotFoundError:
            errors.append("ipconfig not found (unexpected on Windows)")
            return data, errors
        if result.returncode != 0:
            errors.append(f"ipconfig /all failed: {(result.stderr or result.stdout).strip()}")
            return data, errors

        current = None
        in_suffix_block = False
        for line in result.stdout.splitlines():
            header_m = re.match(
                r"^(?:Ethernet adapter|Wireless LAN adapter|Tunnel adapter|Unknown adapter) (.+):\s*$",
                line,
            )
            if header_m:
                current = header_m.group(1).strip()
                data["interfaces"][current] = {
                    "dhcp_server": None, "lease_obtained": None, "lease_expires": None,
                    "ipv6_addresses": [], "ipv6_gateway": None,
                }
                in_suffix_block = False
                continue
            stripped = line.strip()

            if current is None:
                # Top "Windows IP Configuration" section, before any
                # adapter block -- this is where DNS Suffix Search List
                # lives, and (like DNS Servers elsewhere in this same
                # command's output) it can continue on following
                # unlabeled indented lines when there's more than one
                # suffix.
                if in_suffix_block:
                    if stripped and re.match(r"^[\w.\-]+$", stripped):
                        data["dns_suffix_search_list"].append(stripped)
                        continue
                    in_suffix_block = False
                m = re.search(r"DNS Suffix Search List[.\s]*:\s*(.*)$", stripped)
                if m:
                    val = m.group(1).strip()
                    if val:
                        data["dns_suffix_search_list"].append(val)
                    in_suffix_block = True
                continue

            m = re.search(r"DHCP Server[.\s]*:\s*([\d.]+)", stripped)
            if m:
                data["interfaces"][current]["dhcp_server"] = m.group(1)
                continue
            m = re.search(r"Lease Obtained[.\s]*:\s*(.+)", stripped)
            if m:
                data["interfaces"][current]["lease_obtained"] = m.group(1).strip()
                continue
            m = re.search(r"Lease Expires[.\s]*:\s*(.+)", stripped)
            if m:
                data["interfaces"][current]["lease_expires"] = m.group(1).strip()
                continue
            m = re.search(r"IPv6 Address[.\s()a-zA-Z]*:\s*([0-9a-fA-F:]+)", stripped)
            if m:
                data["interfaces"][current]["ipv6_addresses"].append(m.group(1))
                continue
            m = re.search(r"Link-local IPv6 Address[.\s()a-zA-Z]*:\s*([0-9a-fA-F:%\w]+)", stripped)
            if m:
                data["interfaces"][current]["ipv6_addresses"].append(m.group(1).split("%")[0])
                continue
            m = re.search(r"Default Gateway[.\s]*:\s*([0-9a-fA-F:]+:[0-9a-fA-F:]*:[0-9a-fA-F:]*)", stripped)
            if m:
                data["interfaces"][current]["ipv6_gateway"] = m.group(1)
                continue

        if not data["interfaces"]:
            errors.append("ipconfig /all ran but no adapter blocks were recognized")
    except Exception as e:
        errors.append(f"unexpected error reading extended ipconfig /all data: {e}")
    return data, errors


def get_dhcp_lease_info(ipconfig_extra=None):
    """
    Per-interface DHCP lease info: which server handed out the lease,
    and when it was obtained/expires (Windows/macOS) or its lease
    duration (Linux -- see below for why that's a different field, not
    a parsing shortfall).

    Windows pulls straight from get_windows_ipconfig_extra() (called
    internally if not already fetched by the caller). Linux uses `nmcli
    -t -f DHCP4.OPTION device show <iface>` and greps
    dhcp_server_identifier / dhcp_lease_time out of its terse
    colon-separated sub-fields -- same NetworkManager-only limitation
    get_ip_assignment_mode() already has: an interface nmcli doesn't
    manage returns "unknown" rather than a guess, not silence. Note:
    nmcli's DHCP4.OPTION only exposes a lease *duration*
    (dhcp_lease_time, in seconds), not absolute obtained/expires
    timestamps the way Windows/macOS report them -- a real difference
    in what the tool exposes, not something worth faking by adding
    "now" and "now + duration" as if they were real values. macOS uses
    `ipconfig getpacket <iface>` (Apple's own ipconfig tool -- unrelated
    to Windows' command of the same name) and regexes
    server_identifier/lease_time out of its output.

    Returns ({interface_name: {"dhcp_server", "lease_obtained"/
    "lease_expires" (Windows/macOS) or "lease_time_seconds" (Linux)} |
    "unknown"}, errors).
    """
    data = {}
    errors = []
    try:
        if SYSTEM == "Windows":
            if ipconfig_extra is None:
                ipconfig_extra, ie_errors = get_windows_ipconfig_extra()
                errors.extend(ie_errors)
            for name, info in ipconfig_extra.get("interfaces", {}).items():
                data[name] = {
                    "dhcp_server": info.get("dhcp_server"),
                    "lease_obtained": info.get("lease_obtained"),
                    "lease_expires": info.get("lease_expires"),
                }
            if not data and not errors:
                errors.append("no DHCP lease info found in ipconfig /all output")

        elif SYSTEM == "Linux":
            interfaces, _ = get_interface_status()
            try:
                devices = subprocess.run(
                    ["nmcli", "-t", "-f", "DEVICE,STATE", "device"],
                    capture_output=True, text=True, errors="ignore", timeout=10,
                )
            except FileNotFoundError:
                errors.append("nmcli not installed -- DHCP lease info needs NetworkManager")
                return data, errors
            if devices.returncode != 0:
                errors.append(f"nmcli device failed: {(devices.stderr or devices.stdout).strip()}")
                return data, errors
            connected = set()
            for line in devices.stdout.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[1] == "connected":
                    connected.add(parts[0])
            for iface in interfaces:
                name = iface["name"]
                if name not in connected:
                    data[name] = "unknown"
                    continue
                show = subprocess.run(
                    ["nmcli", "-t", "-f", "DHCP4.OPTION", "device", "show", name],
                    capture_output=True, text=True, errors="ignore", timeout=10,
                )
                if show.returncode != 0:
                    errors.append(f"nmcli device show {name} failed: {(show.stderr or show.stdout).strip()}")
                    data[name] = "unknown"
                    continue
                entry = {"dhcp_server": None, "lease_time_seconds": None}
                for oline in show.stdout.splitlines():
                    if "dhcp_server_identifier" in oline:
                        m = re.search(r"dhcp_server_identifier\s*=\s*(\S+)", oline)
                        if m:
                            entry["dhcp_server"] = m.group(1)
                    if "dhcp_lease_time" in oline:
                        m = re.search(r"dhcp_lease_time\s*=\s*(\S+)", oline)
                        if m:
                            entry["lease_time_seconds"] = _to_int(m.group(1))
                data[name] = entry
            if not data:
                errors.append("no interfaces found to check DHCP lease info for")

        elif SYSTEM == "Darwin":
            interfaces, _ = get_interface_status()
            found_any = False
            for iface in interfaces:
                name = iface["name"]
                try:
                    result = subprocess.run(["ipconfig", "getpacket", name],
                                             capture_output=True, text=True, errors="ignore", timeout=5)
                except FileNotFoundError:
                    errors.append("ipconfig (Apple's, not Windows') not found -- unexpected on macOS")
                    break
                if result.returncode != 0 or not result.stdout.strip():
                    continue
                found_any = True
                entry = {"dhcp_server": None, "lease_time_seconds": None}
                m = re.search(r"server_identifier[^=]*=\s*([\d.]+)", result.stdout)
                if m:
                    entry["dhcp_server"] = m.group(1)
                m = re.search(r"lease_time[^=]*=\s*0x[0-9a-fA-F]+\s*=\s*(\d+)", result.stdout)
                if m:
                    entry["lease_time_seconds"] = int(m.group(1))
                data[name] = entry
            if not found_any:
                errors.append("ipconfig getpacket returned nothing for any interface -- may not be "
                               "on DHCP, or the lease cache is empty")
    except Exception as e:
        errors.append(f"unexpected error reading DHCP lease info: {e}")
    return data, errors


def _dhcp_option_ip(packet, code):
    """Walks a DHCP packet's options section (starting right after the
    240-byte fixed header + magic cookie) looking for a 4-byte IP-valued
    option of the given code, e.g. 54 (DHCP Server Identifier). Returns
    None if not found or the packet is too short/malformed to walk."""
    pos = 240
    while pos < len(packet):
        opt = packet[pos]
        if opt == 255:
            break
        if opt == 0:
            pos += 1
            continue
        if pos + 1 >= len(packet):
            break
        length = packet[pos + 1]
        value = packet[pos + 2:pos + 2 + length]
        if opt == code and length == 4:
            return ".".join(str(b) for b in value)
        pos += 2 + length
    return None


def _own_mac_bytes():
    """
    Best-effort own MAC address for a hand-built DHCPDISCOVER's chaddr
    field, via the stdlib uuid module (uuid.getnode() -- cross-platform,
    no subprocess). If the platform couldn't determine a real hardware
    address, uuid.getnode() falls back to a random 48-bit number with
    the multicast bit set (RFC 4122) -- detected here and treated the
    same as "unknown" rather than logged as if it were real, since a
    random-looking chaddr would be actively misleading. Returns 6 zero
    bytes in that case; the DHCPDISCOVER is still valid without a real
    value here (chaddr just tells a server where to *unicast* an offer
    back to, and this function only reads replies via broadcast/its own
    bound socket, not by trusting the offer's own yiaddr routing).
    """
    node = uuid.getnode()
    if node & 0x010000000000:
        return b"\x00" * 6
    return node.to_bytes(6, "big")


def detect_rogue_dhcp_servers(timeout=2.5):
    """
    Broadcasts a hand-built DHCPDISCOVER (RFC 2131 wire format -- a UDP
    payload via SOCK_DGRAM, not a raw socket) and collects DHCPOFFER
    replies within a short window, to catch a second/unexpected DHCP
    server answering on the LAN: a classic, hard-to-diagnose fault --
    a misconfigured switch port bridging two networks, a consumer
    router plugged in downstream with its own DHCP server still turned
    on, or genuine malicious rogue DHCP.

    LAN-broadcast only, not one of A1's five internet-touching
    exceptions -- gated by its own --no-dhcp-probe flag instead, the
    same class of decision as --no-upnp (a separate protocol/socket
    path on the LAN, not a skip of the internet checks).

    Needs root/admin to bind UDP port 68 (a privileged port <1024) on
    Linux/macOS -- same class of requirement check_firewall_rules()
    already documents for reading the full firewall ruleset, and
    PermissionError is caught and explained the same way. Windows may
    not enforce the same restriction on privileged ports; that's stated
    here as untested, not confirmed either way -- no Windows machine to
    check it against.

    Returns (data, errors). data = {"responding_servers": [ip, ...],
    "count": n}.
    """
    data = {"responding_servers": [], "count": 0}
    errors = []
    xid = random.randint(0, 0xFFFFFFFF)
    chaddr = _own_mac_bytes() + b"\x00" * 10
    packet = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128sI",
        1, 1, 6, 0,
        xid, 0, 0x8000,
        b"\x00\x00\x00\x00", b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00", b"\x00\x00\x00\x00",
        chaddr, b"\x00" * 64, b"\x00" * 128,
        0x63825363,
    )
    packet += bytes([53, 1, 1, 255])  # option 53 (msg type) = DISCOVER, then end

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("0.0.0.0", 68))
    except PermissionError:
        errors.append(
            "Could not bind UDP port 68 (a privileged port) -- rogue DHCP server detection "
            "needs root/admin on Linux/macOS. Try running with sudo, or skip this check with "
            "--no-dhcp-probe. (Untested whether Windows enforces the same restriction.)"
        )
        sock.close()
        return data, errors
    except OSError as e:
        errors.append(f"could not bind UDP port 68: {e} (a real DHCP client already running on "
                       "this machine may already be using it)")
        sock.close()
        return data, errors

    servers = []
    sock.settimeout(0.5)
    deadline = time.monotonic() + timeout
    try:
        sock.sendto(packet, ("255.255.255.255", 67))
        while time.monotonic() < deadline:
            try:
                resp, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(resp) < 240 or resp[0] != 2:  # too short, or not BOOTREPLY
                continue
            resp_xid = struct.unpack("!I", resp[4:8])[0]
            if resp_xid != xid:
                continue
            server_ip = _dhcp_option_ip(resp, 54) or addr[0]
            if server_ip not in servers:
                servers.append(server_ip)
    except OSError as e:
        errors.append(f"error during DHCP broadcast/listen: {e}")
    finally:
        sock.close()

    data["responding_servers"] = servers
    data["count"] = len(servers)
    if not servers and not errors:
        errors.append("no DHCPOFFER responses seen within the discovery window -- either no DHCP "
                       "server answered, or broadcast/UDP 67-68 is filtered here; not necessarily a fault")
    return data, errors


def detect_duplicate_ip(arp_before, arp_after):
    """
    Best-effort duplicate-IP detection -- NOT a guarantee, stated
    explicitly in the returned "note" and worth repeating here: this
    only catches an IP whose MAC address changed between two ARP-table
    reads a few seconds apart (arp_before, taken right before the ping
    sweep, and arp_after, taken right after -- see run_discovery()'s
    call order). A duplicate that doesn't happen to change MAC during
    that exact window, or one that was already stable before the scan
    started, will not be caught this way.

    On Linux only, also best-effort greps the last 200 lines of `dmesg`
    for "duplicate address detected" -- wrapped in try/except since
    dmesg often needs elevated privileges (kernel.dmesg_restrict) and
    may just return nothing; that's fine, not an error, same as any
    other best-effort OS-log scrape in this file.

    Returns (data, errors). data = {"conflicts": [{"ip", "mac_before",
    "mac_after"}], "dmesg_matches": [str, ...], "note": str}.
    """
    conflicts = []
    for ip, mac_after in arp_after.items():
        mac_before = arp_before.get(ip)
        if mac_before and mac_after and mac_before != mac_after:
            conflicts.append({"ip": ip, "mac_before": mac_before, "mac_after": mac_after})

    dmesg_matches = []
    if SYSTEM == "Linux":
        try:
            result = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.splitlines()[-200:]:
                    if "duplicate address detected" in line.lower():
                        dmesg_matches.append(line.strip())
        except Exception:
            # dmesg needing permissions it doesn't have (or not existing
            # at all) is a normal, expected outcome here, not an error --
            # this whole check is best-effort on top of the ARP
            # comparison above.
            pass

    note = (
        "Best-effort only, not a guarantee: this catches a MAC address change for the same IP "
        "between two ARP-table reads taken a few seconds apart (around the ping sweep), plus "
        "(Linux only) any 'duplicate address detected' kernel log line still in the dmesg buffer. "
        "A duplicate that doesn't change MAC during that exact window, or whose kernel log entry "
        "has since rotated out, will not be caught."
    )
    return {"conflicts": conflicts, "dmesg_matches": dmesg_matches, "note": note}, []
def discover_upnp_devices(timeout=3.0):
    """
    Generalizes _ssdp_discover()/_fetch_device_description_xml() (used
    by query_upnp_gateway() to find just the router's IGD service) to
    collect and describe EVERY SSDP responder on the LAN within the
    discovery window, not filter down to the gateway. Useful on its own
    -- smart TVs, media servers, printers, and plenty of IoT devices all
    answer SSDP even though they have nothing to do with the router's
    WAN connection.

    For each distinct LOCATION URL seen, fetches and parses that
    device's description XML (same unauthenticated plain HTTP GET
    query_upnp_gateway() already does) and extracts whatever of
    {device_type, friendly_name, manufacturer} the description offers.

    Returns (devices, errors) -- devices is a list of {"location", "ip",
    "device_type", "friendly_name", "manufacturer"}.
    """
    devices = []
    errors = []
    locations = _ssdp_discover(timeout=timeout, search_target="ssdp:all")
    if not locations:
        errors.append("No SSDP devices responded (some routers/devices have UPnP off by default)")
        return devices, errors

    def tag(name):
        return f"{{{_UPNP_DEVICE_NS}}}{name}"

    fetch_failures = 0
    for location in locations:
        root = _fetch_device_description_xml(location, timeout=timeout)
        if root is None:
            fetch_failures += 1
            continue
        parsed = urllib.parse.urlparse(location)
        device_elem = root.find(tag("device"))
        device_type = friendly_name = manufacturer = None
        if device_elem is not None:
            device_type = device_elem.findtext(tag("deviceType"))
            friendly_name = device_elem.findtext(tag("friendlyName"))
            manufacturer = device_elem.findtext(tag("manufacturer"))
        devices.append({
            "location": location,
            "ip": parsed.hostname,
            "device_type": device_type,
            "friendly_name": friendly_name,
            "manufacturer": manufacturer,
        })

    if not devices:
        errors.append(f"Found {len(locations)} SSDP responder(s) but couldn't fetch/parse any device description XML")
    elif fetch_failures:
        errors.append(f"{fetch_failures} of {len(locations)} SSDP responder(s) didn't return usable description XML")
    return devices, errors


def _decode_dns_name(data, offset):
    """
    Decodes a (possibly compressed) DNS/mDNS name starting at `offset`
    in `data`, following 0xC0 compression pointers per RFC 1035 section
    4.1.4. Returns (name, offset_immediately_after_the_name_as_originally
    _encoded) -- the second value only ever advances past the *first*
    pointer byte pair even if that pointer jumps backwards into the
    packet, so the caller's outer read position still advances correctly
    through the rest of the message.
    """
    labels = []
    pos = offset
    next_pos = None
    hops = 0
    while hops < 128:
        hops += 1
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            if next_pos is None:
                next_pos = pos
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if next_pos is None:
                next_pos = pos + 2
            pos = pointer
            continue
        pos += 1
        labels.append(data[pos:pos + length].decode("ascii", errors="ignore"))
        pos += length
    return ".".join(labels), (next_pos if next_pos is not None else pos)


def _parse_mdns_answers(data):
    """
    Walks an mDNS response's answer/authority/additional resource
    records, extracting what PTR/TXT/A/SRV records it can. This is a
    real RR walk -- unlike _parse_dns_response()'s 12-byte-header-only
    check (which is all the plain unicast DNS resolution test needs),
    mDNS responses carry full records that actually have to be read to
    get anything useful out of them.

    Returns None if the packet is too short/malformed to even read the
    12-byte header; a dict otherwise ({"names": [...], "services":
    [...], "txt": {...}}), possibly with empty lists if nothing in the
    packet was understood -- under-claiming rather than guessing at a
    malformed record.
    """
    if len(data) < 12:
        return None
    try:
        _msg_id, _flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return None

    pos = 12
    for _ in range(qdcount):
        if pos >= len(data):
            return {"names": [], "services": [], "txt": {}}
        _name, pos = _decode_dns_name(data, pos)
        pos += 4  # qtype + qclass
        if pos > len(data):
            return {"names": [], "services": [], "txt": {}}

    names = []
    services = []
    txt = {}
    for _ in range(ancount + nscount + arcount):
        if pos >= len(data):
            break
        name, pos = _decode_dns_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata_start = pos
        if rdata_start + rdlength > len(data):
            break

        if rtype == 12:  # PTR
            target, _ = _decode_dns_name(data, rdata_start)
            if target:
                services.append(target)
        elif rtype == 16:  # TXT
            tpos = rdata_start
            end = rdata_start + rdlength
            while tpos < end:
                tlen = data[tpos]
                tpos += 1
                if tpos + tlen > end:
                    break
                item = data[tpos:tpos + tlen].decode("utf-8", errors="ignore")
                tpos += tlen
                if "=" in item:
                    k, _, v = item.partition("=")
                    txt[k] = v
                elif item:
                    txt[item] = True
        elif rtype == 1 and rdlength == 4:  # A
            ip = ".".join(str(b) for b in data[rdata_start:rdata_start + 4])
            names.append(f"A:{ip}")
        elif rtype == 33 and name:  # SRV -- the record's own name is the service instance
            names.append(name)

        pos = rdata_start + rdlength

    return {"names": sorted(set(names)), "services": sorted(set(services)), "txt": txt}


def discover_mdns_devices(timeout=3.0):
    """
    Sends a multicast DNS query (a PTR query for
    _services._dns-sd._udp.local, the standard mDNS "list every service
    type this network advertises" query) to 224.0.0.251:5353 and collects
    responses within a short window -- same
    sendto-then-poll-recvfrom-against-a-deadline shape as _ssdp_discover(),
    adapted for mDNS's need to actually join the multicast group and bind
    port 5353 to see replies (which are normally sent back multicast, not
    unicast to the querier).

    LAN-multicast only, not one of A1's five internet-touching
    exceptions -- gated by its own --no-mdns flag, same class of decision
    as --no-dhcp-probe and --no-upnp.

    This is more parsing work than anything else in this file -- see
    _parse_mdns_answers()/_decode_dns_name() for the actual record walk,
    which goes further than _parse_dns_response()'s header-only check
    since mDNS responses carry full records. If a response can't be
    parsed at all, its raw responder IP is still reported (rather than
    dropped silently) with a note in errors -- better to under-claim
    than to guess at a malformed record or crash.

    Returns (devices, errors) -- devices is a list of {"ip", "names",
    "services", "txt"}, one per distinct responding IP.
    """
    devices = []
    errors = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    try:
        sock.bind(("0.0.0.0", 5353))
    except OSError as e:
        errors.append(f"could not bind UDP port 5353 for mDNS discovery: {e}")
        sock.close()
        return devices, errors
    try:
        mreq = struct.pack("4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton("0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        # Disable multicast loopback -- without this, our own outgoing
        # query gets delivered straight back into this same socket (any
        # host that's joined a multicast group receives its own sends to
        # that group by default), which shows up as a phantom "device"
        # that's really just our own request echoing back with zero
        # answer records. Caught by real testing in this sandbox, not
        # anticipated blind -- see the v0.15.0 changelog.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    except OSError as e:
        errors.append(f"could not join the mDNS multicast group (224.0.0.251): {e}")
        sock.close()
        return devices, errors

    query_id = random.randint(0, 65535)
    query = _build_dns_query("_services._dns-sd._udp.local", query_id, qtype=12)  # PTR
    sock.settimeout(0.5)
    deadline = time.monotonic() + timeout
    responses = []
    try:
        sock.sendto(query, ("224.0.0.251", 5353))
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            responses.append((data, addr))
    finally:
        sock.close()

    if not responses:
        errors.append("No mDNS responses received within the discovery window (mDNS may be "
                       "blocked/filtered, or no Bonjour/Avahi-speaking devices are on the LAN)")
        return devices, errors

    by_ip = {}
    for data, addr in responses:
        ip = addr[0]
        parsed = _parse_mdns_answers(data)
        if parsed is None:
            errors.append(f"received an mDNS response from {ip} but couldn't parse its records "
                           "(malformed/truncated packet) -- reporting the IP only")
            parsed = {"names": [], "services": [], "txt": {}}
        if ip not in by_ip:
            by_ip[ip] = {"ip": ip, "names": set(parsed["names"]), "services": set(parsed["services"]), "txt": dict(parsed["txt"])}
        else:
            by_ip[ip]["names"] |= set(parsed["names"])
            by_ip[ip]["services"] |= set(parsed["services"])
            by_ip[ip]["txt"].update(parsed["txt"])

    for entry in by_ip.values():
        devices.append({
            "ip": entry["ip"],
            "names": sorted(entry["names"]),
            "services": sorted(entry["services"]),
            "txt": entry["txt"],
        })
    return devices, errors
def get_routing_table():
    """
    Reads the OS routing table. Windows: `netsh interface ipv4/ipv6 show
    route`. Linux: `ip route show`. macOS: `netstat -rn -f inet` (BSD
    netstat -- there's no `ip route` on macOS). Each platform's own
    output shape decides the fields a route dict actually has
    (destination always present; gateway/interface/metric/flags where
    that platform's tool reports them) rather than forcing one uniform
    shape none of the three naturally produce.

    Returns (routes, errors) -- routes is a list of route dicts.
    """
    routes = []
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                r4 = subprocess.run(["netsh", "interface", "ipv4", "show", "route"],
                                     capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("netsh not found (unexpected on Windows)")
                return routes, errors
            if r4.returncode == 0:
                started = False
                for line in r4.stdout.splitlines():
                    if line.strip().startswith("---"):
                        started = True
                        continue
                    if not started:
                        continue
                    parts = line.split()
                    if len(parts) >= 6:
                        routes.append({
                            "family": "ipv4", "destination": parts[3], "metric": _to_int(parts[2]),
                            "interface_idx": parts[4], "gateway": parts[5],
                        })
            else:
                errors.append(f"netsh interface ipv4 show route failed: {(r4.stderr or r4.stdout).strip()}")

            try:
                r6 = subprocess.run(["netsh", "interface", "ipv6", "show", "route"],
                                     capture_output=True, text=True, errors="ignore", timeout=10)
                if r6.returncode == 0:
                    started = False
                    for line in r6.stdout.splitlines():
                        if line.strip().startswith("---"):
                            started = True
                            continue
                        if not started:
                            continue
                        parts = line.split()
                        if len(parts) >= 5:
                            routes.append({
                                "family": "ipv6", "destination": parts[3], "metric": _to_int(parts[2]),
                                "interface_idx": parts[4], "gateway": parts[5] if len(parts) > 5 else None,
                            })
            except FileNotFoundError:
                pass
            if not routes:
                errors.append("netsh ran but no routes were parsed -- output may not match the expected format")

        elif SYSTEM == "Linux":
            try:
                result = subprocess.run(["ip", "route", "show"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("`ip` command not found")
                return routes, errors
            if result.returncode != 0:
                errors.append(f"ip route show failed: {(result.stderr or result.stdout).strip()}")
                return routes, errors
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if not parts:
                    continue
                route = {"family": "ipv4", "destination": parts[0], "gateway": None, "interface": None, "metric": None}
                if "via" in parts:
                    route["gateway"] = parts[parts.index("via") + 1]
                if "dev" in parts:
                    route["interface"] = parts[parts.index("dev") + 1]
                if "metric" in parts:
                    route["metric"] = _to_int(parts[parts.index("metric") + 1])
                routes.append(route)
            if not routes:
                errors.append("ip route show ran but returned no routes")

        elif SYSTEM == "Darwin":
            try:
                result = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("netstat not found (unexpected on macOS)")
                return routes, errors
            if result.returncode != 0:
                errors.append(f"netstat -rn -f inet failed: {(result.stderr or result.stdout).strip()}")
                return routes, errors
            started = False
            for line in result.stdout.splitlines():
                if line.strip().startswith("Destination"):
                    started = True
                    continue
                if not started or not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    routes.append({
                        "family": "ipv4", "destination": parts[0], "gateway": parts[1],
                        "flags": parts[2], "interface": parts[3],
                    })
            if not routes:
                errors.append("netstat -rn -f inet ran but no routes were parsed")
    except Exception as e:
        errors.append(f"unexpected error reading routing table: {e}")
    return routes, errors


def _parse_traceroute_output(text):
    """Parses standard Unix traceroute output (Linux/macOS), e.g.
    ' 1  192.0.2.1  0.177 ms  0.138 ms  0.068 ms' or ' 2  * * *'."""
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        if rest.strip().startswith("*"):
            hops.append({"hop": int(m.group(1)), "ip": None, "rtts_ms": []})
            continue
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
        rtts = [float(x) for x in re.findall(r"([\d.]+)\s*ms", rest)]
        hops.append({"hop": int(m.group(1)), "ip": ip_m.group(1) if ip_m else None, "rtts_ms": rtts})
    return hops


def _parse_tracert_output(text):
    """Parses Windows `tracert -d` output, e.g.
    '  1     1 ms     1 ms     1 ms  192.168.1.1' or a timed-out hop
    ('Request timed out.')."""
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        if "Request timed out" in rest:
            hops.append({"hop": int(m.group(1)), "ip": None, "rtts_ms": []})
            continue
        rtts = [float(t.replace("<", "")) for t in re.findall(r"(<?\d+)\s*ms", rest)]
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s*$", rest)
        hops.append({"hop": int(m.group(1)), "ip": ip_m.group(1) if ip_m else None, "rtts_ms": rtts})
    return hops


def _parse_tracepath_output(text):
    """Parses `tracepath` output (the iputils fallback used on Linux
    when traceroute itself isn't installed), e.g.
    ' 1:  192.0.2.1    0.177ms' or ' 2:  no reply'."""
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\??:\s+(.*)$", line)
        if not m:
            continue
        rest = m.group(2).strip()
        if rest.startswith("no reply"):
            hops.append({"hop": int(m.group(1)), "ip": None, "rtts_ms": []})
            continue
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
        rtt_m = re.search(r"([\d.]+)ms", rest)
        hops.append({
            "hop": int(m.group(1)),
            "ip": ip_m.group(1) if ip_m else None,
            "rtts_ms": [float(rtt_m.group(1))] if rtt_m else [],
        })
    return hops


def traceroute_to_gateway(gateway_ip, max_hops=15):
    """
    Traces the path to the gateway -- LAN-only (should normally resolve
    in one hop), not one of A1's internet-touching exceptions, so this
    is NOT gated by any of the new --no-* flags, matching
    check_gateway_latency()'s existing precedent of always running.

    Shells out to the OS traceroute/tracert binary and regexes its hop
    lines -- same template check_gateway_latency() already uses for
    `ping`, no raw ICMP packets built here. Windows: `tracert -d -h N`.
    Linux: `traceroute -n -m N` first, falling back to `tracepath` (from
    iputils, usually already present) if traceroute itself isn't
    installed -- not every minimal distro ships it. macOS: `traceroute
    -n` (BSD traceroute, preinstalled).

    Returns (hops, errors) -- hops is a list of {"hop", "ip", "rtts_ms"}.
    """
    hops = []
    errors = []
    if not gateway_ip:
        errors.append("no gateway IP to traceroute to")
        return hops, errors
    try:
        if SYSTEM == "Windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), gateway_ip]
        elif SYSTEM == "Linux":
            cmd = ["traceroute", "-n", "-m", str(max_hops), gateway_ip]
        elif SYSTEM == "Darwin":
            cmd = ["traceroute", "-n", gateway_ip]
        else:
            errors.append(f"unrecognized platform: {SYSTEM}")
            return hops, errors

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, errors="ignore",
                                     timeout=max_hops * 3 + 10)
        except FileNotFoundError:
            if SYSTEM == "Linux":
                try:
                    tp = subprocess.run(["tracepath", gateway_ip], capture_output=True, text=True,
                                         errors="ignore", timeout=max_hops * 3 + 10)
                    hops = _parse_tracepath_output(tp.stdout)
                    if not hops:
                        errors.append("traceroute isn't installed; tracepath ran but no hops were parsed")
                    return hops, errors
                except FileNotFoundError:
                    errors.append("neither traceroute nor tracepath is installed")
                    return hops, errors
            errors.append(f"{cmd[0]} not found")
            return hops, errors
        except subprocess.TimeoutExpired:
            errors.append(f"{cmd[0]} to {gateway_ip} timed out")
            return hops, errors

        hops = _parse_tracert_output(result.stdout) if SYSTEM == "Windows" else _parse_traceroute_output(result.stdout)
        if not hops:
            errors.append(f"{cmd[0]} ran but no hops were parsed -- output may not match the expected format")
    except Exception as e:
        errors.append(f"unexpected error running traceroute to gateway: {e}")
    return hops, errors


def traceroute_to_internet(target=None, max_hops=15):
    """
    A1's third deliberate exception to "only A7 touches the internet"
    (see CLAUDE.md's Architecture section, and check_internet_reachability()
    / check_dns_resolution() for the first two) -- traces the path
    toward a public internet host to show where along the way a
    connection is actually failing, rather than just "reachable" or
    "not reachable". This is a diagnostic TEST like the other
    exceptions: nothing else in A1 depends on it succeeding. Skippable
    with its own --no-traceroute flag, independent of --no-internet and
    the other four new internet-exception flags -- see CLAUDE.md's
    "narrow, deliberate exception" framing and this file's other
    exception functions for why each gets its own flag.

    Targets the first entry of INTERNET_CHECK_TARGETS by default (the
    same well-known anycast IP check_internet_reachability() already
    uses). Reuses traceroute_to_gateway()'s shell-out/regex machinery --
    same OS binaries, same hop-line parsing, just a different target and
    a plain-dict return shape to match this file's other exception
    functions.

    Returns a plain dict ({"target", "hops": [...], "errors": [...]}) --
    not the (data, errors) tuple the rest of this file uses, matching
    check_internet_reachability()'s shape instead.
    """
    if target is None:
        target = INTERNET_CHECK_TARGETS[0][0]
    hops, errors = traceroute_to_gateway(target, max_hops=max_hops)
    return {"target": target, "hops": hops, "errors": errors}
def read_hosts_file():
    """
    Parses the OS hosts file directly -- plain open()/read, no
    subprocess at all. Windows: %SystemRoot%\\System32\\drivers\\etc\\hosts.
    Linux/macOS: /etc/hosts.

    Runs unconditionally on every scan, NOT gated by any skip flag --
    A4 needs this captured as a baseline to diff against later, same
    reasoning as get_system_proxy_config() and (on Linux)
    get_wifi_power_management() also running unconditionally.

    A line commented out with a leading "#" but otherwise hosts-file-
    shaped (an IP followed by hostnames) is still captured with
    active=False rather than skipped outright -- a customer's hosts
    file with something commented out (an old ad-blocking entry, or a
    leftover from a previous fix) is itself diagnostically useful, not
    noise to discard.

    Returns (entries, errors) -- entries is a list of {"ip",
    "hostnames": [...], "active": bool, "line_raw": str}.
    """
    data = []
    errors = []
    try:
        if SYSTEM == "Windows":
            path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                 "System32", "drivers", "etc", "hosts")
        else:
            path = "/etc/hosts"
        try:
            with open(path, "r", errors="ignore") as f:
                lines = f.readlines()
        except FileNotFoundError:
            errors.append(f"hosts file not found at {path}")
            return data, errors
        except PermissionError:
            errors.append(f"permission denied reading {path}")
            return data, errors

        for raw_line in lines:
            line = raw_line.rstrip("\n").rstrip("\r")
            stripped = line.strip()
            if not stripped:
                continue
            active = True
            content = stripped
            if content.startswith("#"):
                content = content.lstrip("#").strip()
                active = False
                if not content:
                    continue
            parts = content.split()
            if len(parts) < 2:
                continue
            try:
                ipaddress.ip_address(parts[0])
            except ValueError:
                continue
            hostnames = [p for p in parts[1:] if not p.startswith("#")]
            if not hostnames:
                continue
            data.append({"ip": parts[0], "hostnames": hostnames, "active": active, "line_raw": line})
        if not data:
            errors.append(f"{path} was read but no host entries (active or commented-out) were parsed")
    except Exception as e:
        errors.append(f"unexpected error reading hosts file: {e}")
    return data, errors


def dump_dns_cache():
    """
    Attempts to dump the OS's resolved-name DNS cache. Windows has a
    real, clean tool for this (`ipconfig /displaydns`) and this parses
    its Record Name/Record Type/Time To Live/data blocks properly.
    Linux and macOS do not have an equivalent -- stated honestly per
    platform rather than faked:

      - Linux: no true per-entry cache-dump tool exists. `resolvectl
        statistics` (systemd-resolved) is read instead, but it only
        gives aggregate hit/miss/cache-size counters, not the actual
        cached names -- returned with an explicit error/note saying so,
        so it can't be mistaken for a real dump. If this machine isn't
        using systemd-resolved at all, resolvectl won't even be
        present, and that's reported as its own error.
      - macOS: no clean non-root option exists. The only known method
        (`killall -INFO mDNSResponder` + scraping the result out of
        syslog) needs root and is fragile enough not to be worth
        building -- same class of decision as this file's already-
        documented removal of macOS Wi-Fi nearby-network scanning
        (Apple removed the clean tool; this isn't a parsing gap).

    Returns (entries, errors).
    """
    data = []
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True,
                                         errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("ipconfig not found (unexpected on Windows)")
                return data, errors
            if result.returncode != 0:
                errors.append(f"ipconfig /displaydns failed: {(result.stderr or result.stdout).strip()}")
                return data, errors

            current = None
            for line in result.stdout.splitlines():
                stripped = line.strip()
                name_m = re.match(r"^([\w.\-]+)$", stripped)
                if name_m and "." in stripped:
                    if current:
                        data.append(current)
                    current = {"name": name_m.group(1), "type": None, "ttl": None, "data": None}
                    continue
                if current is None:
                    continue
                m = re.match(r"Record Type\s*\.*\s*:\s*(\d+)", stripped)
                if m:
                    current["type"] = int(m.group(1))
                    continue
                m = re.match(r"Time To Live\s*\.*\s*:\s*(\d+)", stripped)
                if m:
                    current["ttl"] = int(m.group(1))
                    continue
                m = re.match(r"^(?:A \(Host\)|CNAME|AAAA|PTR)[^:]*:\s*(.+)$", stripped)
                if m:
                    current["data"] = m.group(1).strip()
            if current:
                data.append(current)
            if not data:
                errors.append("ipconfig /displaydns ran but no cached records were parsed -- the cache may genuinely be empty")

        elif SYSTEM == "Linux":
            try:
                result = subprocess.run(["resolvectl", "statistics"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("resolvectl not found -- this machine isn't using systemd-resolved, "
                               "and no per-entry or aggregate DNS cache source is read here")
                return data, errors
            if result.returncode != 0:
                errors.append(f"resolvectl statistics failed: {(result.stderr or result.stdout).strip()}")
                return data, errors
            stats = {}
            for line in result.stdout.splitlines():
                m = re.search(r"(Current Cache Size|Cache Hits|Cache Misses)\s*:\s*(\d+)", line)
                if m:
                    stats[m.group(1)] = int(m.group(2))
            data = [{"aggregate_stats": stats}] if stats else []
            errors.append(
                "Linux has no true per-entry DNS cache dump tool -- this is aggregate resolvectl "
                "statistics (hit/miss/cache-size counts), not a real per-name dump like Windows' "
                "ipconfig /displaydns gives. Treat this as 'is the cache being used at all', not "
                "'what's in it'."
            )
            if not stats:
                errors.append("resolvectl statistics ran but no hit/miss/cache-size counters were parsed")

        elif SYSTEM == "Darwin":
            errors.append(
                "No clean, non-root way to dump the DNS cache on macOS -- the only known method "
                "(killall -INFO mDNSResponder, then scraping the result out of syslog) needs root "
                "and is fragile enough that it's not worth building. Same class of decision as this "
                "file's already-documented macOS Wi-Fi-scan removal: Apple removed/never shipped a "
                "clean tool for this, it isn't a parsing gap."
            )
    except Exception as e:
        errors.append(f"unexpected error dumping DNS cache: {e}")
    return data, errors


def get_dns_suffix_search_list(ipconfig_extra=None):
    """
    The DNS suffix search list -- the domain(s) appended to an
    unqualified hostname lookup (e.g. "printer" -> "printer.office.local").
    Windows pulls it from get_windows_ipconfig_extra() (called internally
    if not already fetched by the caller). Linux reads /etc/resolv.conf
    directly (no subprocess) for a `search`/`domain` line. macOS shells
    out to `scutil --dns` and greps its `search domain[n]` lines -- the
    same tool get_dns_servers() already uses as its own macOS fallback,
    reused here rather than enumerating every network service via
    `networksetup -getsearchdomains <service>`, since scutil --dns
    already reports the effective merged list in one call.

    Returns (domains, errors).
    """
    data = []
    errors = []
    try:
        if SYSTEM == "Windows":
            if ipconfig_extra is None:
                ipconfig_extra, ie_errors = get_windows_ipconfig_extra()
                errors.extend(ie_errors)
            data = list(ipconfig_extra.get("dns_suffix_search_list", []))
            if not data and not errors:
                errors.append("no DNS suffix search list found in ipconfig /all output")

        elif SYSTEM == "Linux":
            try:
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("search") or line.startswith("domain"):
                            data.extend(line.split()[1:])
            except FileNotFoundError:
                errors.append("/etc/resolv.conf not found")
            if not data and not errors:
                errors.append("/etc/resolv.conf was read but no 'search'/'domain' line was found")

        elif SYSTEM == "Darwin":
            try:
                result = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("scutil not found (unexpected on macOS)")
                return data, errors
            if result.returncode != 0:
                errors.append(f"scutil --dns failed: {(result.stderr or result.stdout).strip()}")
                return data, errors
            for line in result.stdout.splitlines():
                m = re.search(r"search domain\[\d+\]\s*:\s*(\S+)", line)
                if m and m.group(1) not in data:
                    data.append(m.group(1))
            if not data:
                errors.append("scutil --dns ran but no search domain entries were found")
    except Exception as e:
        errors.append(f"unexpected error reading DNS suffix search list: {e}")
    return data, errors
def get_system_proxy_config():
    """
    Reads the OS's configured proxy settings. Runs unconditionally on
    every scan, NOT gated by any skip flag -- A4 needs a baseline every
    scan, same reasoning as read_hosts_file() and (on Linux)
    get_wifi_power_management().

    Windows uses the stdlib `winreg` module directly (guarded behind
    `if SYSTEM == "Windows": import winreg`, since this module still has
    to import cleanly on non-Windows) rather than shelling out to `reg
    query` -- a deliberate departure from this file's usual shell-out-
    and-regex style. winreg is stdlib and exists exactly for this, so
    it's the right tool here, not a style violation: reads
    HKCU\\...\\Internet Settings directly (ProxyEnable, ProxyServer,
    AutoConfigURL -- the last of which may legitimately not exist, and
    is treated that way rather than as an error).

    Linux reads the http_proxy/https_proxy/no_proxy environment
    variables (both casings checked), plus a best-effort `gsettings get
    org.gnome.system.proxy mode` -- not every Linux desktop has
    gsettings (or a desktop at all), which is fine, not an error, just
    skipped.

    macOS shells out to `scutil --proxy` and parses its key-value block.

    Returns (data, errors).
    """
    data = {}
    errors = []
    try:
        if SYSTEM == "Windows":
            import winreg  # stdlib -- the right tool for a direct registry read, see docstring
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                      r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            except OSError as e:
                errors.append(f"could not open Internet Settings registry key: {e}")
                return data, errors
            try:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                data["proxy_enabled"] = bool(enabled)
            except FileNotFoundError:
                data["proxy_enabled"] = None
                errors.append("ProxyEnable value not found in the registry")
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                data["proxy_server"] = server
            except FileNotFoundError:
                data["proxy_server"] = None
            try:
                pac, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                data["auto_config_url"] = pac
            except FileNotFoundError:
                data["auto_config_url"] = None
            winreg.CloseKey(key)

        elif SYSTEM == "Linux":
            def _env(name):
                return os.environ.get(name) or os.environ.get(name.upper())
            data["http_proxy"] = _env("http_proxy")
            data["https_proxy"] = _env("https_proxy")
            data["no_proxy"] = _env("no_proxy")
            try:
                result = subprocess.run(["gsettings", "get", "org.gnome.system.proxy", "mode"],
                                         capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    data["gnome_proxy_mode"] = result.stdout.strip().strip("'")
            except FileNotFoundError:
                pass  # not every Linux desktop has gsettings -- not an error

        elif SYSTEM == "Darwin":
            try:
                result = subprocess.run(["scutil", "--proxy"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("scutil not found (unexpected on macOS)")
                return data, errors
            if result.returncode != 0:
                errors.append(f"scutil --proxy failed: {(result.stderr or result.stdout).strip()}")
                return data, errors
            for line in result.stdout.splitlines():
                m = re.match(r"\s*(\w+)\s*:\s*(.+)", line)
                if m:
                    data[m.group(1)] = m.group(2).strip()
            if not data:
                errors.append("scutil --proxy ran but no key-value pairs were parsed")
    except Exception as e:
        errors.append(f"unexpected error reading system proxy config: {e}")
    return data, errors


_VPN_NAME_PATTERNS = {
    "Windows": re.compile(r"(tap|tun|vpn|wintun|wireguard)", re.IGNORECASE),
    "Linux": re.compile(r"^(tun|tap|wg)\d+"),
    # utun<N> is the standard macOS tunnel-interface naming, used by
    # every VPN client and by Apple's own Personal Hotspot/Continuity
    # features -- not VPN-exclusive, but the closest name-based signal
    # macOS offers.
    "Darwin": re.compile(r"^utun\d+"),
}


def detect_vpn_adapters(interfaces=None):
    """
    Classifies interfaces get_interface_status() already returned as
    VPN or not, by name-pattern matching -- NOT a new OS query. Windows:
    name contains tap/tun/vpn/wintun/wireguard (case-insensitive).
    Linux: name starts with tun/tap/wg followed by a digit. macOS: name
    starts with utun followed by a digit.

    Returns (vpn_interfaces, errors) -- vpn_interfaces is a list of
    {"name", "type"} for interfaces that matched, not a full re-dump of
    interface data.
    """
    if interfaces is None:
        interfaces, _ = get_interface_status()
    pattern = _VPN_NAME_PATTERNS.get(SYSTEM)
    vpn_interfaces = []
    if pattern:
        for iface in interfaces:
            if pattern.search(iface["name"]):
                vpn_interfaces.append({"name": iface["name"], "type": iface.get("type")})
    return vpn_interfaces, []


_PMTU_LADDER = (1400, 1450, 1472, 1500)


def check_pmtu_blackhole(target=None, sizes=_PMTU_LADDER):
    """
    A1's fourth deliberate exception to "only A7 touches the internet"
    (see check_internet_reachability(), check_dns_resolution(),
    traceroute_to_internet(), and CLAUDE.md's Architecture section).
    Skippable with its own --no-pmtu flag.

    Pings a ladder of payload sizes (1400/1450/1472/1500 bytes,
    straddling the ~1500-byte standard Ethernet MTU boundary -- 1472
    bytes of ICMP payload plus the 28-byte IP+ICMP header lands exactly
    at 1500) against the target with the DF (Don't Fragment) bit set,
    using the OS ping binary's native flags -- no raw sockets built
    here. Windows: `ping -f -l <size> -n 1`. Linux: `ping -M do -s
    <size> -c 1`. macOS: `ping -D -s <size> -c 1`.

    A PMTU blackhole's signature is a smaller size succeeding while a
    larger size times out with NO explicit ICMP "Fragmentation Needed"
    message -- that silence, rather than an explicit rejection, is what
    marks it as a blackhole rather than a normal network correctly
    telling us to fragment/resize.

    The returned "note" states this plainly: this can't distinguish a
    true PMTU blackhole from a network that simply filters ICMP
    outright -- both look identical from ping's output alone -- and
    this sandbox has no real blackholed path to test against, so this
    function is logic-reviewed only here, not verified against a real
    failure case.

    Returns a plain dict ({"target", "sizes_tested": [...],
    "blackhole_suspected": bool|None, "note", "errors": [...]}).
    """
    if target is None:
        target = INTERNET_CHECK_TARGETS[0][0]
    results = []
    errors = []
    for size in sizes:
        if SYSTEM == "Windows":
            cmd = ["ping", "-f", "-l", str(size), "-n", "1", target]
        elif SYSTEM == "Darwin":
            cmd = ["ping", "-D", "-s", str(size), "-c", "1", target]
        else:
            cmd = ["ping", "-M", "do", "-s", str(size), "-c", "1", target]

        entry = {"size": size, "success": False, "frag_needed_reported": False, "raw_note": None}
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=6)
        except FileNotFoundError:
            errors.append(f"{cmd[0]} not found")
            break
        except subprocess.TimeoutExpired:
            entry["raw_note"] = "timed out"
            results.append(entry)
            continue

        out = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 and re.search(r"1 (packets )?received|bytes from|Reply from", out):
            entry["success"] = True
        else:
            low = out.lower()
            if "frag" in low or "message too long" in low or "needs to be fragmented" in low:
                entry["frag_needed_reported"] = True
            tail = out.strip().splitlines()
            entry["raw_note"] = tail[-1] if tail else None
        results.append(entry)

    blackhole_suspected = None
    smaller_ok = [r for r in results if r["size"] < 1472 and r["success"]]
    larger = [r for r in results if r["size"] >= 1472]
    if smaller_ok and larger:
        larger_all_silent_fail = all((not r["success"]) and (not r["frag_needed_reported"]) for r in larger)
        if larger_all_silent_fail:
            blackhole_suspected = True
        elif any(r["success"] for r in larger):
            blackhole_suspected = False

    note = (
        "This can't distinguish a true PMTU blackhole (a path silently drops oversized DF-set "
        "packets instead of returning an explicit ICMP type 3 code 4 'Fragmentation Needed') from "
        "a network/firewall that filters ICMP outright -- both look identical from ping's output "
        "alone. This sandbox has no real blackholed path to test against, so this function is "
        "logic-reviewed only here, not verified against a real failure case."
    )
    return {"target": target, "sizes_tested": results, "blackhole_suspected": blackhole_suspected,
            "note": note, "errors": errors}


_CAPTIVE_PORTAL_URL = "http://connectivitycheck.gstatic.com/generate_204"


def check_captive_portal(url=_CAPTIVE_PORTAL_URL, timeout=5.0):
    """
    A1's fifth deliberate exception to "only A7 touches the internet"
    (see check_internet_reachability(), check_dns_resolution(),
    traceroute_to_internet(), check_pmtu_blackhole(), and CLAUDE.md's
    Architecture section). Skippable with its own --no-captive-portal
    flag.

    Plain HTTP GET (deliberately HTTP, not HTTPS -- captive portals
    intercept HTTP specifically, which is exactly what this detection
    mechanism relies on being interceptable) to
    http://connectivitycheck.gstatic.com/generate_204 -- Android's own
    captive-portal-detection endpoint, chosen as a well-known, stable
    public default. A working, uncaptured connection gets back an exact
    HTTP 204 No Content with an empty body; anything else (a 200, a
    redirect, different content) means something along the path
    intercepted the request -- a captive portal login page, most likely.

    Errors from urllib are caught and reported explicitly (via
    urllib.error), not silently swallowed.

    Returns a plain dict: {"portal_detected": bool, "status_code":
    int|None, "error": str|None}.
    """
    result = {"portal_detected": False, "status_code": None, "error": None}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "network_discovery-A1/0.15.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.getcode()
                body = resp.read(2048)
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                body = e.read(2048)
            except Exception:
                body = b""
        result["status_code"] = status
        if status != 204 or len(body) > 0:
            result["portal_detected"] = True
    except urllib.error.URLError as e:
        result["error"] = f"request failed: {getattr(e, 'reason', e)}"
    except Exception as e:
        result["error"] = f"unexpected error: {e}"
    return result
def _windows_wlan_show_interfaces_raw():
    """Runs `netsh wlan show interfaces` once; both get_wifi_radio_state()
    and get_wifi_connection_details() parse different fields out of the
    same raw output instead of each shelling out separately. Returns
    (stdout, error) -- error is None on success."""
    try:
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                 capture_output=True, text=True, errors="ignore", timeout=10)
    except FileNotFoundError:
        return None, "netsh not found (unexpected on Windows)"
    if result.returncode != 0:
        return None, f"netsh wlan show interfaces failed: {(result.stderr or result.stdout).strip()}"
    return result.stdout, None


def _linux_wifi_interface_name(errors):
    """Finds the first Wi-Fi interface name via `iw dev` -- shared by
    get_wifi_connection_details() and get_wifi_power_management(), same
    interface-detection logic _scan_wifi_iw() already uses inline for
    its own scan."""
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("iw not installed")
        return None
    if result.returncode != 0:
        errors.append(f"iw dev failed: {(result.stderr or result.stdout).strip()}")
        return None
    m = re.search(r"Interface (\S+)", result.stdout)
    if not m:
        errors.append("iw dev found no wireless interface")
        return None
    return m.group(1)


def get_wifi_connection_details():
    """
    Link rate/signal/noise/802.11-standard for the CURRENTLY ASSOCIATED
    Wi-Fi network only -- deliberately separate from scan_wifi_networks()
    (which describes every nearby SSID a scan found, none of which carry
    this kind of live link-quality data for networks we're not actually
    connected to).

    Windows reuses the same `netsh wlan show interfaces` output
    get_wifi_radio_state() already fetches (via the shared
    _windows_wlan_show_interfaces_raw() helper) rather than shelling out
    a second time, parsing Signal/Receive rate/Transmit rate/Radio type
    out of it. Linux uses `iw dev <iface> link` (rate, signal in dBm)
    plus `iw dev <iface> survey dump` for a noise floor -- driver-
    dependent, many mac80211 drivers don't report it at all, in which
    case noise_dbm just stays None, not an error. macOS uses
    `system_profiler SPAirPortDataType`, the richest of the three
    platforms here (PHY Mode, a real Signal/Noise dBm pair together, Tx
    Rate) since it reports the current network's block directly.

    Returns (data, errors). data = {"ssid", "signal_percent", "signal_dbm",
    "noise_dbm", "rx_rate_mbps", "tx_rate_mbps", "radio_type", "channel"}.
    """
    data = {"ssid": None, "signal_percent": None, "signal_dbm": None, "noise_dbm": None,
            "rx_rate_mbps": None, "tx_rate_mbps": None, "radio_type": None, "channel": None}
    errors = []
    try:
        if SYSTEM == "Windows":
            stdout, err = _windows_wlan_show_interfaces_raw()
            if err:
                errors.append(err)
                return data, errors
            m = re.search(r"^\s*SSID\s*:\s*(.+)$", stdout, re.MULTILINE)
            if m:
                data["ssid"] = m.group(1).strip()
            m = re.search(r"Signal\s*:\s*(\d+)%", stdout)
            if m:
                data["signal_percent"] = int(m.group(1))
            m = re.search(r"Receive rate \(Mbps\)\s*:\s*([\d.]+)", stdout)
            if m:
                data["rx_rate_mbps"] = float(m.group(1))
            m = re.search(r"Transmit rate \(Mbps\)\s*:\s*([\d.]+)", stdout)
            if m:
                data["tx_rate_mbps"] = float(m.group(1))
            m = re.search(r"Radio type\s*:\s*(.+)", stdout)
            if m:
                data["radio_type"] = m.group(1).strip()
            m = re.search(r"^\s*Channel\s*:\s*(\d+)", stdout, re.MULTILINE)
            if m:
                data["channel"] = int(m.group(1))
            if data["ssid"] is None:
                errors.append("netsh wlan show interfaces ran but no SSID was parsed -- likely not currently connected to Wi-Fi")

        elif SYSTEM == "Linux":
            iface = _linux_wifi_interface_name(errors)
            if not iface:
                return data, errors
            try:
                link = subprocess.run(["iw", "dev", iface, "link"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("iw not installed")
                return data, errors
            if "Not connected" in link.stdout:
                errors.append("iw dev link reports not currently connected to Wi-Fi")
                return data, errors
            if link.returncode != 0:
                errors.append(f"iw dev {iface} link failed: {(link.stderr or link.stdout).strip()}")
                return data, errors

            m = re.search(r"SSID:\s*(.+)", link.stdout)
            if m:
                data["ssid"] = m.group(1).strip()
            m = re.search(r"signal:\s*(-?\d+)\s*dBm", link.stdout)
            if m:
                data["signal_dbm"] = int(m.group(1))
            m = re.search(r"rx bitrate:\s*([\d.]+)", link.stdout)
            if m:
                data["rx_rate_mbps"] = float(m.group(1))
            m = re.search(r"tx bitrate:\s*([\d.]+)", link.stdout)
            if m:
                data["tx_rate_mbps"] = float(m.group(1))
            m = re.search(r"freq:\s*(\d+)", link.stdout)
            if m:
                data["channel"] = _freq_to_channel(m.group(1))

            # Noise floor lives in `iw dev survey dump` on drivers that
            # support it -- many mac80211 drivers simply don't report
            # it, in which case this just stays None, not an error.
            try:
                survey = subprocess.run(["iw", "dev", iface, "survey", "dump"], capture_output=True, text=True, timeout=10)
                if survey.returncode == 0:
                    m = re.search(r"in use.*?noise:\s*(-?\d+)\s*dBm", survey.stdout, re.DOTALL)
                    if m:
                        data["noise_dbm"] = int(m.group(1))
            except FileNotFoundError:
                pass

        elif SYSTEM == "Darwin":
            try:
                result = subprocess.run(["system_profiler", "SPAirPortDataType"], capture_output=True, text=True, timeout=15)
            except FileNotFoundError:
                errors.append("system_profiler not found (unexpected on macOS)")
                return data, errors
            if result.returncode != 0:
                errors.append(f"system_profiler SPAirPortDataType failed: {(result.stderr or result.stdout).strip()}")
                return data, errors
            m = re.search(r"Current Network Information:\s*\n\s*(.+?):\s*\n(.*?)(?:\n\S|\Z)", result.stdout, re.DOTALL)
            if not m:
                errors.append("system_profiler ran but no 'Current Network Information' block was found -- likely not currently connected to Wi-Fi")
                return data, errors
            data["ssid"] = m.group(1).strip()
            block = m.group(2)
            phy_m = re.search(r"PHY Mode:\s*(\S+)", block)
            if phy_m:
                data["radio_type"] = phy_m.group(1)
            sn_m = re.search(r"Signal / Noise:\s*(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", block)
            if sn_m:
                data["signal_dbm"] = int(sn_m.group(1))
                data["noise_dbm"] = int(sn_m.group(2))
            rate_m = re.search(r"Tx Rate:\s*([\d.]+)", block)
            if rate_m:
                data["tx_rate_mbps"] = float(rate_m.group(1))
            ch_m = re.search(r"Channel:\s*(\d+)", block)
            if ch_m:
                data["channel"] = int(ch_m.group(1))
    except Exception as e:
        errors.append(f"unexpected error getting Wi-Fi connection details: {e}")
    return data, errors


def get_wifi_power_management():
    """
    Wi-Fi adapter power-save state -- Linux-only by explicit product
    decision. `iw dev <iface> get power_save` is clean, reliable, and
    needs no root on Linux. Windows has no clean non-guessing CLI
    source (PowerShell-only -- same class of limitation as this file's
    declined real Airplane Mode read, see get_wifi_radio_state()'s
    docstring), and macOS ties this to the system-wide Energy Saver
    setting with no discrete per-adapter CLI toggle -- both stated as
    data (a returned error explaining why), not silently skipped.

    Runs unconditionally when SYSTEM == "Linux" in run_discovery(), NOT
    gated by a skip flag -- A4's new Linux-only diff category needs a
    baseline every scan, same reasoning as read_hosts_file() and
    get_system_proxy_config().

    Returns (state, errors) -- state is "on"/"off"/None.
    """
    if SYSTEM != "Linux":
        return None, [
            "Wi-Fi power-management reading is Linux-only -- no clean, non-guessing CLI source "
            "exists on Windows (PowerShell-only, same class of limitation as this file's declined "
            "Airplane Mode read) or macOS (tied to system-wide Energy Saver, no discrete "
            "per-adapter CLI toggle)."
        ]
    errors = []
    iface = _linux_wifi_interface_name(errors)
    if not iface:
        return None, errors
    try:
        result = subprocess.run(["iw", "dev", iface, "get", "power_save"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        errors.append("iw not installed")
        return None, errors
    if result.returncode != 0:
        errors.append(f"iw dev {iface} get power_save failed: {(result.stderr or result.stdout).strip()}")
        return None, errors
    m = re.search(r"Power save:\s*(\w+)", result.stdout)
    if not m:
        errors.append("iw dev get power_save ran but no 'Power save' line was found")
        return None, errors
    return m.group(1).lower(), errors
def get_ipv6_status(ipv4_present=True, ipconfig_extra=None):
    """
    Per-interface IPv6 address(es), an IPv6 default gateway if present,
    IPv6 DNS servers, and a pure-logic stack_type classification
    ("dual_stack"/"ipv4_only"/"ipv6_only") computed from whatever this
    function gathered plus `ipv4_present` -- the already-known IPv4
    presence, passed in by the caller (run_discovery() already knows
    local_ip by the time this runs) rather than this function making
    its own separate IPv4 determination.

    Windows pulls addresses/gateway from get_windows_ipconfig_extra()
    (called internally if not already fetched by the caller). Linux:
    `ip -6 addr show` for addresses, `ip -6 route show default` for the
    gateway, `nmcli -t -f IP6.DNS device show <iface>` for DNS servers
    per interface (matches how IPv4 DNS is already read elsewhere in
    this file). macOS: `ifconfig` regexed for `inet6` lines per
    interface block, plus `networksetup -getinfo <service>` for the
    IPv6 configuration mode where it's reported.

    Returns (data, errors). data = {"interfaces": {name: {"addresses":
    [...]}}, "default_gateway", "dns_servers": [...], "stack_type"}.
    """
    data = {"interfaces": {}, "default_gateway": None, "dns_servers": [], "stack_type": None}
    errors = []
    try:
        if SYSTEM == "Windows":
            if ipconfig_extra is None:
                ipconfig_extra, ie_errors = get_windows_ipconfig_extra()
                errors.extend(ie_errors)
            for name, info in ipconfig_extra.get("interfaces", {}).items():
                if info.get("ipv6_addresses"):
                    data["interfaces"][name] = {"addresses": info["ipv6_addresses"]}
                if info.get("ipv6_gateway") and not data["default_gateway"]:
                    data["default_gateway"] = info["ipv6_gateway"]
            if not data["interfaces"] and not errors:
                errors.append("no IPv6 addresses found in ipconfig /all output")

        elif SYSTEM == "Linux":
            try:
                result = subprocess.run(["ip", "-6", "addr", "show"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("`ip` command not found")
                return data, errors
            if result.returncode != 0:
                errors.append(f"ip -6 addr show failed: {(result.stderr or result.stdout).strip()}")
            else:
                current = None
                for line in result.stdout.splitlines():
                    m = re.match(r"^\d+:\s+([^:@]+)[:@]", line)
                    if m:
                        current = m.group(1)
                        if current != "lo":
                            data["interfaces"].setdefault(current, {"addresses": []})
                        continue
                    if current and current != "lo":
                        addr_m = re.search(r"inet6\s+([0-9a-fA-F:]+)/(\d+)\s+scope\s+(\S+)", line)
                        if addr_m:
                            data["interfaces"][current]["addresses"].append({
                                "address": addr_m.group(1), "prefix_len": int(addr_m.group(2)),
                                "scope": addr_m.group(3),
                            })
                if not data["interfaces"]:
                    errors.append("ip -6 addr show ran but found no non-loopback IPv6 addresses")

            try:
                route6 = subprocess.run(["ip", "-6", "route", "show", "default"], capture_output=True, text=True, timeout=10)
                if route6.returncode == 0:
                    m = re.search(r"default via ([0-9a-fA-F:]+)", route6.stdout)
                    if m:
                        data["default_gateway"] = m.group(1)
            except FileNotFoundError:
                pass

            for iface_name in list(data["interfaces"].keys()):
                try:
                    dns6 = subprocess.run(["nmcli", "-t", "-f", "IP6.DNS", "device", "show", iface_name],
                                           capture_output=True, text=True, errors="ignore", timeout=10)
                except FileNotFoundError:
                    break
                if dns6.returncode == 0:
                    for line in dns6.stdout.splitlines():
                        m = re.match(r"IP6\.DNS\[\d+\]:(.+)", line)
                        if m:
                            server = m.group(1).strip()
                            if server and server not in data["dns_servers"]:
                                data["dns_servers"].append(server)

        elif SYSTEM == "Darwin":
            try:
                result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("ifconfig not found")
                return data, errors
            if result.returncode != 0:
                errors.append(f"ifconfig failed: {(result.stderr or result.stdout).strip()}")
            else:
                for block in result.stdout.split("\n\n"):
                    m = re.match(r"^(\w+):", block)
                    if not m or m.group(1) == "lo0":
                        continue
                    name = m.group(1)
                    addrs = []
                    for line in block.splitlines():
                        addr_m = re.search(r"inet6\s+([0-9a-fA-F:]+)(?:%\w+)?\s+prefixlen\s+(\d+)", line)
                        if addr_m:
                            addrs.append({"address": addr_m.group(1), "prefix_len": int(addr_m.group(2))})
                    if addrs:
                        data["interfaces"][name] = {"addresses": addrs}
                if not data["interfaces"]:
                    errors.append("ifconfig ran but found no non-loopback IPv6 addresses")

            for device, service in _macos_hardware_ports():
                if device not in data["interfaces"]:
                    continue
                try:
                    info_out = subprocess.run(["networksetup", "-getinfo", service],
                                               capture_output=True, text=True, errors="ignore", timeout=10)
                except FileNotFoundError:
                    break
                m = re.search(r"IPv6:\s*(.+)", info_out.stdout)
                if m:
                    data["interfaces"][device]["ipv6_config_mode"] = m.group(1).strip()
        else:
            errors.append(f"unrecognized platform: {SYSTEM}")
    except Exception as e:
        errors.append(f"unexpected error reading IPv6 status: {e}")

    has_ipv6 = any(bool(info.get("addresses")) for info in data["interfaces"].values())
    if has_ipv6 and ipv4_present:
        data["stack_type"] = "dual_stack"
    elif has_ipv6:
        data["stack_type"] = "ipv6_only"
    elif ipv4_present:
        data["stack_type"] = "ipv4_only"
    else:
        data["stack_type"] = "unknown"
    return data, errors


def check_clock_drift():
    """
    Reads each OS's own already-computed clock-sync status -- a purely
    local read, no new outbound NTP traffic. Deliberately NOT an
    independent live NTP query: that would be an unapproved SIXTH
    internet exception beyond the five explicitly approved for this
    batch (traceroute_to_internet, check_pmtu_blackhole,
    check_captive_portal, measure_throughput, check_nat_type).

    Windows: `w32tm /query /status` (Source line). Linux: `timedatectl
    show` (NTPSynchronized=yes/no) plus, if chrony is the active
    service, `chronyc tracking`'s "System time" line for an actual
    offset-in-seconds figure -- chrony not being installed/active is
    normal and not an error, timedatectl's boolean still stands on its
    own. macOS: `systemsetup -getusingnetworktime`, which only exposes
    an On/Off boolean -- macOS doesn't give a drift figure via any clean
    CLI tool the way chrony does on Linux.

    Known gap, stated in the returned "note": this only reflects the
    OS's own last successful sync status -- if the machine's own NTP
    client is itself stopped or broken, this can't independently detect
    real drift.

    Returns (data, errors). data = {"synchronized": bool|None,
    "offset_seconds": float|None, "source": str|None, "note": str}.
    """
    data = {
        "synchronized": None, "offset_seconds": None, "source": None,
        "note": "This only reflects the OS's own last successful sync status -- if the machine's "
                "own NTP client is itself stopped or broken, this can't independently detect real "
                "drift (that would need an independent live NTP query, which this file deliberately "
                "doesn't do -- see docstring).",
    }
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(["w32tm", "/query", "/status"], capture_output=True, text=True, errors="ignore", timeout=10)
            except FileNotFoundError:
                errors.append("w32tm not found (unexpected on Windows)")
                return data, errors
            if result.returncode != 0:
                errors.append(f"w32tm /query /status failed: {(result.stderr or result.stdout).strip()}")
                return data, errors
            m = re.search(r"Source:\s*(.+)", result.stdout)
            if m:
                data["source"] = m.group(1).strip()
                data["synchronized"] = "Local CMOS Clock" not in data["source"]
            else:
                errors.append("w32tm /query /status ran but no Source line was found")

        elif SYSTEM == "Linux":
            try:
                result = subprocess.run(["timedatectl", "show"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("timedatectl not installed")
                return data, errors
            if result.returncode != 0:
                errors.append(f"timedatectl show failed: {(result.stderr or result.stdout).strip()}")
            else:
                m = re.search(r"NTPSynchronized=(\w+)", result.stdout)
                if m:
                    data["synchronized"] = m.group(1) == "yes"
                else:
                    errors.append("timedatectl show ran but no NTPSynchronized field was found")

            try:
                chrony = subprocess.run(["chronyc", "tracking"], capture_output=True, text=True, timeout=10)
                if chrony.returncode == 0:
                    m = re.search(r"System time\s*:\s*([\d.]+)\s*seconds\s*(fast|slow)", chrony.stdout)
                    if m:
                        offset = float(m.group(1))
                        data["offset_seconds"] = -offset if m.group(2) == "slow" else offset
                        data["source"] = "chrony"
            except FileNotFoundError:
                pass  # chrony isn't the active time-sync service here -- not an error

        elif SYSTEM == "Darwin":
            try:
                result = subprocess.run(["systemsetup", "-getusingnetworktime"], capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                errors.append("systemsetup not found (unexpected on macOS)")
                return data, errors
            if result.returncode != 0:
                msg = (result.stderr or result.stdout).strip()
                errors.append(f"systemsetup -getusingnetworktime failed: {msg}")
                if "must be root" in msg.lower() or "permission" in msg.lower():
                    errors.append("systemsetup usually needs root to read this -- try running with sudo.")
                return data, errors
            m = re.search(r"Network Time:\s*(On|Off)", result.stdout, re.IGNORECASE)
            if m:
                data["synchronized"] = m.group(1).lower() == "on"
            else:
                errors.append("systemsetup -getusingnetworktime ran but no Network Time on/off line was found")
    except Exception as e:
        errors.append(f"unexpected error checking clock drift/sync status: {e}")
    return data, errors


_THROUGHPUT_TEST_URL = "https://speed.cloudflare.com/__down?bytes=2000000"  # 2 MB


def measure_throughput(url=_THROUGHPUT_TEST_URL, timeout=15.0):
    """
    A1's exception function for a real download-speed measurement.
    Skippable with its own --no-throughput flag.

    HTTP GETs a fixed-size payload via stdlib urllib.request.urlopen()
    (no third-party HTTP library) from Cloudflare's public speed-test
    endpoint, https://speed.cloudflare.com/__down?bytes=2000000 -- a
    real, stable, publicly documented endpoint built exactly for this
    purpose, requested here as 2,000,000 bytes (2 MB). Wall-clock
    elapsed time is measured with time.monotonic(); Mbps is bytes
    received * 8 / elapsed seconds / 1,000,000. A 15-second timeout
    keeps a genuinely broken connection from hanging the whole scan.

    Returns a plain dict: {"mbps": float|None, "bytes_received": int,
    "elapsed_s": float|None, "error": str|None}.
    """
    result = {"mbps": None, "bytes_received": 0, "elapsed_s": None, "error": None}
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "network_discovery-A1/0.15.0"})
        total = 0
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
        elapsed = time.monotonic() - start
        result["bytes_received"] = total
        result["elapsed_s"] = round(elapsed, 3)
        if elapsed > 0 and total > 0:
            result["mbps"] = round((total * 8) / elapsed / 1_000_000, 2)
        else:
            result["error"] = "downloaded 0 bytes"
    except urllib.error.URLError as e:
        result["elapsed_s"] = round(time.monotonic() - start, 3)
        result["error"] = f"request failed: {getattr(e, 'reason', e)}"
    except Exception as e:
        result["elapsed_s"] = round(time.monotonic() - start, 3)
        result["error"] = f"unexpected error: {e}"
    return result


_STUN_MAGIC_COOKIE = 0x2112A442
_STUN_BINDING_REQUEST = 0x0001
_STUN_BINDING_SUCCESS = 0x0101
_STUN_XOR_MAPPED_ADDRESS = 0x0020
_STUN_MAPPED_ADDRESS = 0x0001


def _build_stun_binding_request():
    """Hand-builds a minimal RFC 5389 STUN Binding Request: message
    type 0x0001, the fixed magic cookie 0x2112A442, a random 96-bit
    transaction ID, and a zero-length attribute section -- the simplest
    possible valid request. Returns (packet_bytes, transaction_id)."""
    txid = os.urandom(12)
    header = struct.pack(">HHI12s", _STUN_BINDING_REQUEST, 0, _STUN_MAGIC_COOKIE, txid)
    return header, txid


def _parse_stun_response(data, expected_txid):
    """Parses a STUN Binding Success Response far enough to pull out
    XOR-MAPPED-ADDRESS (preferred) or the older MAPPED-ADDRESS, IPv4
    only. Returns (ip, port) or None."""
    if len(data) < 20:
        return None
    msg_type, msg_len, cookie, txid = struct.unpack(">HHI12s", data[:20])
    if txid != expected_txid or msg_type != _STUN_BINDING_SUCCESS:
        return None
    attrs = data[20:20 + msg_len]
    pos = 0
    mapped = None
    xor_mapped = None
    while pos + 4 <= len(attrs):
        atype, alen = struct.unpack(">HH", attrs[pos:pos + 4])
        aval = attrs[pos + 4:pos + 4 + alen]
        if atype == _STUN_XOR_MAPPED_ADDRESS and len(aval) >= 8 and aval[1] == 0x01:
            xport = struct.unpack(">H", aval[2:4])[0] ^ (_STUN_MAGIC_COOKIE >> 16)
            cookie_bytes = struct.pack(">I", _STUN_MAGIC_COOKIE)
            xip = bytes(b ^ c for b, c in zip(aval[4:8], cookie_bytes))
            xor_mapped = (".".join(str(b) for b in xip), xport)
        elif atype == _STUN_MAPPED_ADDRESS and len(aval) >= 8 and aval[1] == 0x01:
            port = struct.unpack(">H", aval[2:4])[0]
            mapped = (".".join(str(b) for b in aval[4:8]), port)
        pos += 4 + alen + ((4 - (alen % 4)) % 4)  # attrs are padded to a 4-byte boundary
    return xor_mapped or mapped


def check_nat_type(stun_server=("stun.l.google.com", 19302),
                    second_stun_server=("stun1.l.google.com", 19302), timeout=3.0):
    """
    A1's exception function for STUN-based public address discovery.
    Skippable with its own --no-nat-type flag.

    Hand-builds a minimal RFC 5389 STUN Binding Request (see
    _build_stun_binding_request() -- same hand-built-packet-over-UDP
    pattern as the existing DNS query builder in check_dns_resolution())
    and sends it via SOCK_DGRAM to the well-known public Google STUN
    server stun.l.google.com:19302, parsing the response's
    XOR-MAPPED-ADDRESS (falling back to the older MAPPED-ADDRESS) to
    learn this machine's own public IP:port as seen from the internet --
    genuinely useful data on its own, even without full NAT-type
    classification.

    Full RFC 3489-style NAT-type classification (Full Cone/Restricted/
    Port-Restricted/Symmetric) needs comparing responses from multiple
    servers/ports and is a materially bigger lift than this function
    attempts. What it DOES do: query a second STUN server
    (stun1.l.google.com:19302) and compare the returned external port --
    the same port from both suggests a Cone-type NAT (Full/Restricted/
    Port-Restricted are indistinguishable from this alone), a different
    port suggests Symmetric NAT. This is a coarse heuristic, explicitly
    NOT the full RFC 3489 classification algorithm -- stated here and in
    the changelog rather than overclaimed.

    Returns a plain dict: {"public_ip", "public_port", "server",
    "nat_type_guess", "error"}.
    """
    result = {"public_ip": None, "public_port": None, "server": f"{stun_server[0]}:{stun_server[1]}",
              "nat_type_guess": None, "error": None}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    request, txid = _build_stun_binding_request()
    try:
        sock.sendto(request, stun_server)
        data, _addr = sock.recvfrom(2048)
        mapped = _parse_stun_response(data, txid)
        if mapped:
            result["public_ip"], result["public_port"] = mapped
        else:
            result["error"] = "STUN server responded but no MAPPED-ADDRESS/XOR-MAPPED-ADDRESS attribute was found"
    except socket.timeout:
        result["error"] = "STUN request to primary server timed out"
    except OSError as e:
        result["error"] = f"STUN request failed: {e}"
    finally:
        sock.close()

    if result["public_ip"] and second_stun_server:
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(timeout)
        request2, txid2 = _build_stun_binding_request()
        try:
            sock2.sendto(request2, second_stun_server)
            data2, _addr2 = sock2.recvfrom(2048)
            mapped2 = _parse_stun_response(data2, txid2)
            if mapped2:
                if mapped2[1] == result["public_port"]:
                    result["nat_type_guess"] = ("cone (same external port seen by two STUN servers -- "
                                                 "Full/Restricted/Port-Restricted Cone are indistinguishable "
                                                 "from this alone)")
                else:
                    result["nat_type_guess"] = ("symmetric (a different external port was allocated per "
                                                 "server -- consistent with Symmetric NAT)")
        except (socket.timeout, OSError):
            pass  # the second server is a bonus signal, not required for the primary result
        finally:
            sock2.close()
    return result


def get_driver_info():
    """
    Per-interface network driver name/version. Linux is the cleanest of
    the three: `ethtool -i <iface>` gives driver/version/firmware-version
    lines directly, plus a best-effort `modinfo <driver>` follow-up for a
    vermagic field (optional extra detail, not worth over-investing in --
    if it's missing or fails, ethtool's own fields already cover the
    useful part). Windows uses `wmic path win32_pnpsigneddriver ...` --
    wmic is a deprecated tool Microsoft is phasing out of newer Windows
    versions, flagged the same way get_interface_link_info() already
    flags its own wmic use. macOS has no single clean CLI source for
    per-interface driver info the way ethtool/wmic give Linux/Windows --
    `system_profiler SPNetworkDataType` gives a best-effort mapping of
    BSD device name to service name only, genuinely thinner than the
    other two platforms, stated honestly rather than padded out.

    Returns (data, errors) -- data is keyed by interface/device name.
    """
    data = {}
    errors = []
    try:
        if SYSTEM == "Windows":
            try:
                result = subprocess.run(
                    ["wmic", "path", "win32_pnpsigneddriver", "where", "DeviceName like '%Network%'",
                     "get", "DeviceName,DriverVersion,DriverDate", "/format:csv"],
                    capture_output=True, text=True, errors="ignore", timeout=20,
                )
            except FileNotFoundError:
                errors.append("wmic not found -- it's a deprecated tool Microsoft is phasing out of "
                               "newer Windows versions, this machine may not have it")
                return data, errors
            if result.returncode != 0:
                errors.append(f"wmic path win32_pnpsigneddriver failed: {(result.stderr or result.stdout).strip()}")
                return data, errors
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            if len(lines) >= 2:
                header = lines[0].split(",")
                for line in lines[1:]:
                    parts = line.split(",")
                    if len(parts) != len(header):
                        continue
                    row = dict(zip(header, parts))
                    name = row.get("DeviceName", "").strip()
                    if name:
                        data[name] = {
                            "driver_version": row.get("DriverVersion", "").strip() or None,
                            "driver_date": row.get("DriverDate", "").strip() or None,
                        }
            if not data:
                errors.append("wmic ran but no network device driver rows were parsed -- output may not match the expected format")

        elif SYSTEM == "Linux":
            interfaces, _ = get_interface_status()
            for iface in interfaces:
                name = iface["name"]
                try:
                    result = subprocess.run(["ethtool", "-i", name], capture_output=True, text=True, timeout=10)
                except FileNotFoundError:
                    errors.append("ethtool not installed")
                    break
                if result.returncode != 0:
                    errors.append(f"ethtool -i {name} failed: {(result.stderr or result.stdout).strip()}")
                    continue
                entry = {"driver": None, "version": None, "firmware_version": None}
                for line in result.stdout.splitlines():
                    if line.startswith("driver:"):
                        entry["driver"] = line.split(":", 1)[1].strip()
                    elif line.startswith("version:"):
                        entry["version"] = line.split(":", 1)[1].strip()
                    elif line.startswith("firmware-version:"):
                        entry["firmware_version"] = line.split(":", 1)[1].strip() or None
                if entry["driver"]:
                    try:
                        mod = subprocess.run(["modinfo", entry["driver"]], capture_output=True, text=True, timeout=10)
                        if mod.returncode == 0:
                            vm = re.search(r"^vermagic:\s*(.+)$", mod.stdout, re.MULTILINE)
                            if vm:
                                entry["vermagic"] = vm.group(1).strip()
                    except FileNotFoundError:
                        pass
                data[name] = entry
            if not data and not errors:
                errors.append("no interfaces found to read driver info for")

        elif SYSTEM == "Darwin":
            try:
                result = subprocess.run(["system_profiler", "SPNetworkDataType"], capture_output=True, text=True, timeout=15)
            except FileNotFoundError:
                errors.append("system_profiler not found (unexpected on macOS)")
                return data, errors
            if result.returncode != 0:
                errors.append(f"system_profiler SPNetworkDataType failed: {(result.stderr or result.stdout).strip()}")
                return data, errors
            current_name = None
            for line in result.stdout.splitlines():
                header_m = re.match(r"^\s{4}(\S.*):\s*$", line)
                if header_m and "BSD Device Name" not in line:
                    current_name = header_m.group(1).strip()
                bsd_m = re.search(r"BSD Device Name:\s*(\S+)", line)
                if bsd_m and current_name:
                    data[bsd_m.group(1)] = {"service_name": current_name}
            if not data:
                errors.append("system_profiler ran but no network services with a BSD device name were "
                               "found -- macOS driver info via CLI is genuinely less standardized than "
                               "Linux/Windows here")
    except Exception as e:
        errors.append(f"unexpected error reading driver info: {e}")
    return data, errors


def run_discovery(skip_ports=False, skip_wifi=False, skip_internet=False, skip_upnp=False, skip_firewall=False,
                   skip_dhcp_probe=False, skip_mdns=False, skip_traceroute=False, skip_pmtu=False,
                   skip_captive_portal=False, skip_throughput=False, skip_nat_type=False):
    print("Detecting local network...")
    local_ip, network_str = get_local_ip_and_subnet()
    gateway_ip = get_default_gateway()
    dns_servers, dns_errors = get_dns_servers()
    ip_mode, ip_mode_errors = get_ip_assignment_mode(local_ip)
    print(f"  Local IP: {local_ip} ({ip_mode})")
    print(f"  Subnet:   {network_str}")
    print(f"  Gateway:  {gateway_ip or 'not found'}")
    print(f"  DNS:      {', '.join(dns_servers) if dns_servers else 'not found'}")
    for err in dns_errors + ip_mode_errors:
        print(f"  ! {err}")

    gateway_latency = check_gateway_latency(gateway_ip)
    if gateway_latency["target"]:
        print(f"  Gateway latency: {gateway_latency['received']}/{gateway_latency['sent']} replies, "
              f"{gateway_latency['loss_percent']}% loss, avg {gateway_latency['avg_ms']}ms, "
              f"jitter {gateway_latency['jitter_ms']}ms")

    print("Tracing route to gateway...")
    gateway_traceroute, gateway_traceroute_errors = traceroute_to_gateway(gateway_ip)
    for err in gateway_traceroute_errors:
        print(f"  ! {err}")

    print("\nChecking network interfaces...")
    interfaces, iface_errors = get_interface_status()
    for err in iface_errors:
        print(f"  ! {err}")
    for iface in interfaces:
        admin = "enabled" if iface["admin_enabled"] else "DISABLED"
        if iface["connected"] is None:
            conn = "connected: unknown"
        else:
            conn = "connected" if iface["connected"] else "not connected"
        mtu = f"mtu={iface['mtu']}" if iface["mtu"] else "mtu=?"
        print(f"  {iface['name']:<12} type={iface['type']:<9} {admin:<10} {conn:<16} {mtu}")

    iface_net_config, iface_net_config_errors = get_interface_network_config()
    for err in iface_net_config_errors:
        print(f"  ! {err}")

    link_info, link_info_errors = get_interface_link_info()
    for err in link_info_errors:
        print(f"  ! {err}")

    # Windows-only: one ipconfig /all pass shared by get_dhcp_lease_info(),
    # get_dns_suffix_search_list(), and get_ipv6_status() below, instead of
    # each one shelling out separately for data this single command
    # already reports together.
    ipconfig_extra, ipconfig_extra_errors = get_windows_ipconfig_extra()
    for err in ipconfig_extra_errors:
        print(f"  ! {err}")

    dhcp_leases, dhcp_lease_errors = get_dhcp_lease_info(ipconfig_extra)
    for err in dhcp_lease_errors:
        print(f"  ! {err}")

    dns_suffix_search_list, dns_suffix_errors = get_dns_suffix_search_list(ipconfig_extra)
    for err in dns_suffix_errors:
        print(f"  ! {err}")

    vpn_interfaces, _vpn_errors = detect_vpn_adapters(interfaces)
    if vpn_interfaces:
        print(f"  VPN/tunnel interface(s) detected: {', '.join(v['name'] for v in vpn_interfaces)}")

    driver_info, driver_info_errors = get_driver_info()
    for err in driver_info_errors:
        print(f"  ! {err}")

    print("\nReading routing table...")
    routing_table, routing_table_errors = get_routing_table()
    for err in routing_table_errors:
        print(f"  ! {err}")
    print(f"  {len(routing_table)} route(s) found")

    wifi_radio, wifi_radio_errors = get_wifi_radio_state()
    if wifi_radio["hardware"] or wifi_radio["software"]:
        print(f"  Wi-Fi radio: hardware={wifi_radio['hardware'] or '?'} software={wifi_radio['software'] or '?'}")
        if wifi_radio["software"] == "off":
            print("    Wi-Fi is software-disabled -- this is what Airplane Mode or an Fn-key Wi-Fi toggle turns off.")
        if wifi_radio["hardware"] == "off":
            print("    Wi-Fi is hardware-disabled -- check for a physical Wi-Fi switch.")
    for err in wifi_radio_errors:
        print(f"  ! {err}")

    wifi_connection, wifi_connection_errors = get_wifi_connection_details()
    if wifi_connection.get("ssid"):
        print(f"  Wi-Fi connected: {wifi_connection['ssid']} "
              f"(rx={wifi_connection.get('rx_rate_mbps')}Mbps tx={wifi_connection.get('tx_rate_mbps')}Mbps)")
    for err in wifi_connection_errors:
        print(f"  ! {err}")

    wifi_power_save = None
    wifi_power_save_errors = []
    if SYSTEM == "Linux":
        wifi_power_save, wifi_power_save_errors = get_wifi_power_management()
        for err in wifi_power_save_errors:
            print(f"  ! {err}")

    print("\nReading hosts file...")
    hosts_file_entries, hosts_file_errors = read_hosts_file()
    for err in hosts_file_errors:
        print(f"  ! {err}")

    print("Reading system proxy configuration...")
    proxy_config, proxy_config_errors = get_system_proxy_config()
    for err in proxy_config_errors:
        print(f"  ! {err}")

    print("\nPinging subnet (this can take a bit)...")
    arp_before = get_arp_table()
    alive = ping_sweep(network_str)

    print("Reading ARP table...")
    arp_after = get_arp_table()
    arp_table = arp_after

    duplicate_ip, _dup_errors = detect_duplicate_ip(arp_before, arp_after)
    if duplicate_ip["conflicts"] or duplicate_ip["dmesg_matches"]:
        print("  ! possible duplicate IP address activity detected -- see duplicate_ip in the results")

    if not skip_dhcp_probe:
        print("Probing for rogue DHCP servers (broadcast, needs root to bind port 68)...")
        rogue_dhcp, rogue_dhcp_errors = detect_rogue_dhcp_servers()
        for err in rogue_dhcp_errors:
            print(f"  ! {err}")
        if rogue_dhcp["count"] > 1:
            print(f"  ! {rogue_dhcp['count']} different DHCP servers responded: {rogue_dhcp['responding_servers']}")
        elif rogue_dhcp["count"] == 1:
            print(f"  1 DHCP server responded: {rogue_dhcp['responding_servers'][0]}")
    else:
        rogue_dhcp, rogue_dhcp_errors = {"responding_servers": [], "count": 0}, []

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

    pool_usage = calculate_pool_usage(network_str, len(all_ips))
    print(f"\nIP pool usage: {pool_usage['used']}/{pool_usage['total_usable']} "
          f"({pool_usage['percent_used']}%) -- across the scanned subnet, "
          f"not necessarily the router's actual DHCP range")

    wifi_networks, wifi_errors = [], []
    channel_recommendation = {}
    if not skip_wifi:
        print("\nScanning Wi-Fi networks...")
        wifi_networks, wifi_errors = scan_wifi_networks()

        for err in wifi_errors:
            print(f"  ! {err}")

        if wifi_networks:
            for net in wifi_networks:
                print(f"  {net}")
            channel_recommendation = suggest_best_channel(wifi_networks)
            if channel_recommendation:
                print("\nChannel recommendation:")
                for band, info in channel_recommendation.items():
                    print(f"  {band}: use channel {info['recommended_channel']} "
                          f"(congestion by channel: {info['congestion_by_channel']})")
        elif not wifi_errors:
            print("  No Wi-Fi networks found.")

    if not skip_mdns:
        print("\nDiscovering mDNS/Bonjour devices...")
        mdns_devices, mdns_errors = discover_mdns_devices()
        for err in mdns_errors:
            print(f"  ! {err}")
        for dev in mdns_devices:
            print(f"  {dev['ip']:<15} services={dev['services'] or '-'}")
    else:
        mdns_devices, mdns_errors = [], []

    internet = {"reachable": None, "checks": []}
    if not skip_internet:
        print("\nChecking internet reachability...")
        internet = check_internet_reachability()
        if internet["reachable"]:
            ok = next(c for c in internet["checks"] if c["reachable"])
            print(f"  Reachable ({ok['target']} in {ok['latency_ms']}ms)")
        else:
            tried = ", ".join(c["target"] for c in internet["checks"])
            print(f"  NOT reachable (tried {tried})")

    dns_resolution = {"servers_tested": [], "any_working": None}
    if not skip_internet:
        print("\nChecking DNS resolution (not just configured -- actually tested)...")
        if dns_servers:
            dns_resolution = check_dns_resolution(dns_servers)
            for result in dns_resolution["servers_tested"]:
                if result["working"]:
                    print(f"  {result['server']:<15} working ({result['latency_ms']}ms)")
                else:
                    print(f"  {result['server']:<15} NOT working ({result['error']})")
            if internet["reachable"] and not dns_resolution["any_working"]:
                print("  Internet is reachable but no configured DNS server is resolving names -- "
                      "this looks like a DNS problem, not a general connectivity problem.")
        else:
            print("  No DNS servers were found to test (see the ! line under DNS above).")

    if not skip_traceroute:
        print("\nTracing route to the internet...")
        internet_traceroute = traceroute_to_internet()
        for err in internet_traceroute["errors"]:
            print(f"  ! {err}")
        print(f"  {len(internet_traceroute['hops'])} hop(s) to {internet_traceroute['target']}")
    else:
        internet_traceroute = {"target": None, "hops": [], "errors": []}

    if not skip_pmtu:
        print("\nChecking for a PMTU blackhole...")
        pmtu_result = check_pmtu_blackhole()
        for err in pmtu_result["errors"]:
            print(f"  ! {err}")
        if pmtu_result["blackhole_suspected"]:
            print("  ! possible PMTU blackhole suspected (see pmtu_check.note in the results)")
    else:
        pmtu_result = {"target": None, "sizes_tested": [], "blackhole_suspected": None, "note": None, "errors": []}

    if not skip_captive_portal:
        print("\nChecking for a captive portal...")
        captive_portal = check_captive_portal()
        if captive_portal["error"]:
            print(f"  ! {captive_portal['error']}")
        elif captive_portal["portal_detected"]:
            print(f"  ! captive portal suspected (status {captive_portal['status_code']})")
        else:
            print("  No captive portal detected.")
    else:
        captive_portal = {"portal_detected": False, "status_code": None, "error": None}

    if not skip_throughput:
        print("\nMeasuring download throughput...")
        throughput = measure_throughput()
        if throughput["error"]:
            print(f"  ! {throughput['error']}")
        else:
            print(f"  {throughput['mbps']} Mbps ({throughput['bytes_received']} bytes in {throughput['elapsed_s']}s)")
    else:
        throughput = {"mbps": None, "bytes_received": 0, "elapsed_s": None, "error": None}

    if not skip_nat_type:
        print("\nDiscovering public address via STUN...")
        nat_type = check_nat_type()
        if nat_type["error"]:
            print(f"  ! {nat_type['error']}")
        else:
            print(f"  Public address: {nat_type['public_ip']}:{nat_type['public_port']} "
                  f"(nat_type_guess={nat_type['nat_type_guess']})")
    else:
        nat_type = {"public_ip": None, "public_port": None, "server": None, "nat_type_guess": None, "error": None}

    firewall_rules, firewall_errors = [], []
    if not skip_firewall:
        print("\nChecking local firewall rules for DNS/HTTP/HTTPS/DHCP/ICMP blocks...")
        firewall_rules, firewall_errors = check_firewall_rules()
        for err in firewall_errors:
            print(f"  ! {err}")
        if firewall_rules:
            for r in firewall_rules:
                if r["service"] == "ALL":
                    print(f"  ! {r['name']} blocks ALL outbound traffic")
                else:
                    print(f"  ! {r['name']} blocks {r['service']}" + (f" (port {r['port']})" if r["port"] else ""))
        elif not firewall_errors:
            print("  No rules blocking DNS/HTTP/HTTPS/DHCP/ICMP found.")

    upnp_gateway, upnp_errors = {}, []
    upnp_devices, upnp_devices_errors = [], []
    if not skip_upnp:
        print("\nChecking router via UPnP (no credentials needed)...")
        upnp_gateway, upnp_errors = query_upnp_gateway()
        for err in upnp_errors:
            print(f"  ! {err}")
        if upnp_gateway.get("external_ip"):
            print(f"  External IP: {upnp_gateway['external_ip']}")
        if upnp_gateway.get("connection_status"):
            print(f"  Connection:  {upnp_gateway['connection_status']}"
                  + (f" (uptime {upnp_gateway['uptime_seconds']}s)" if upnp_gateway.get("uptime_seconds") else ""))
        if upnp_gateway.get("total_bytes_sent") or upnp_gateway.get("total_bytes_received"):
            print(f"  Traffic:     sent={upnp_gateway.get('total_bytes_sent', '?')} "
                  f"received={upnp_gateway.get('total_bytes_received', '?')}")
        for note in upnp_gateway.get("notes", []):
            print(f"  ! {note}")

        print("\nDiscovering other UPnP/SSDP devices on the LAN...")
        upnp_devices, upnp_devices_errors = discover_upnp_devices()
        for err in upnp_devices_errors:
            print(f"  ! {err}")
        for dev in upnp_devices:
            print(f"  {dev['ip']:<15} {dev.get('friendly_name') or '?'} ({dev.get('manufacturer') or '?'})")

    print("\nReading IPv6 status...")
    ipv6_status, ipv6_errors = get_ipv6_status(ipv4_present=bool(local_ip), ipconfig_extra=ipconfig_extra)
    for err in ipv6_errors:
        print(f"  ! {err}")
    print(f"  Stack type: {ipv6_status['stack_type']}")

    print("Checking clock sync status...")
    clock_drift, clock_drift_errors = check_clock_drift()
    for err in clock_drift_errors:
        print(f"  ! {err}")

    print("Dumping DNS cache (best-effort)...")
    dns_cache, dns_cache_errors = dump_dns_cache()
    for err in dns_cache_errors:
        print(f"  ! {err}")

    return {
        "local_ip": local_ip,
        "ip_assignment_mode": ip_mode,
        "ip_assignment_errors": ip_mode_errors,
        "subnet": network_str,
        "gateway": gateway_ip,
        "gateway_latency": gateway_latency,
        "dns_servers": dns_servers,
        "dns_scan_errors": dns_errors,
        "interfaces": interfaces,
        "interface_scan_errors": iface_errors,
        "interface_network_config": iface_net_config,
        "interface_network_config_errors": iface_net_config_errors,
        "wifi_radio_state": wifi_radio,
        "wifi_radio_errors": wifi_radio_errors,
        "pool_usage": pool_usage,
        "devices": devices,
        "wifi_networks": wifi_networks,
        "wifi_scan_errors": wifi_errors,
        "channel_recommendation": channel_recommendation,
        "internet": internet,
        "dns_resolution": dns_resolution,
        "firewall_rules": firewall_rules,
        "firewall_scan_errors": firewall_errors,
        "upnp_gateway": upnp_gateway,
        "upnp_errors": upnp_errors,
        # --- v0.15.0 additions below, appended after the original
        # upnp_errors key rather than interleaved above, per this
        # file's established "new keys append at the end" convention ---
        "gateway_traceroute": gateway_traceroute,
        "gateway_traceroute_errors": gateway_traceroute_errors,
        "interface_link_info": link_info,
        "interface_link_info_errors": link_info_errors,
        "dhcp_leases": dhcp_leases,
        "dhcp_lease_errors": dhcp_lease_errors,
        "dns_suffix_search_list": dns_suffix_search_list,
        "dns_suffix_search_list_errors": dns_suffix_errors,
        "vpn_interfaces": vpn_interfaces,
        "driver_info": driver_info,
        "driver_info_errors": driver_info_errors,
        "routing_table": routing_table,
        "routing_table_errors": routing_table_errors,
        "wifi_connection": wifi_connection,
        "wifi_connection_errors": wifi_connection_errors,
        "wifi_power_save": wifi_power_save,
        "wifi_power_save_errors": wifi_power_save_errors,
        "hosts_file": hosts_file_entries,
        "hosts_file_errors": hosts_file_errors,
        "system_proxy_config": proxy_config,
        "system_proxy_config_errors": proxy_config_errors,
        "arp_table": arp_table,
        "duplicate_ip": duplicate_ip,
        "rogue_dhcp_servers": rogue_dhcp,
        "rogue_dhcp_servers_errors": rogue_dhcp_errors,
        "mdns_devices": mdns_devices,
        "mdns_errors": mdns_errors,
        "internet_traceroute": internet_traceroute,
        "pmtu_check": pmtu_result,
        "captive_portal": captive_portal,
        "throughput": throughput,
        "nat_type": nat_type,
        "upnp_devices": upnp_devices,
        "upnp_devices_errors": upnp_devices_errors,
        "ipv6_status": ipv6_status,
        "ipv6_status_errors": ipv6_errors,
        "clock_drift": clock_drift,
        "clock_drift_errors": clock_drift_errors,
        "dns_cache": dns_cache,
        "dns_cache_errors": dns_cache_errors,
    }


def main():
    parser = argparse.ArgumentParser(description="Offline network discovery (Module A1)")
    parser.add_argument("--json", nargs="?", const="-", default=None,
                         help="Export results as JSON. Give a path to write to a file, "
                              "or omit the path to print JSON to stdout.")
    parser.add_argument("--no-ports", action="store_true", help="Skip port probing (faster)")
    parser.add_argument("--no-wifi", action="store_true", help="Skip Wi-Fi network scanning (faster)")
    parser.add_argument("--no-internet", action="store_true",
                         help="Skip the internet reachability check (A1's one exception to staying fully offline)")
    parser.add_argument("--no-upnp", action="store_true",
                         help="Skip the UPnP router query (still LAN-only, but a separate protocol/socket path)")
    parser.add_argument("--no-firewall", action="store_true",
                         help="Skip the local firewall rule scan (reading the full ruleset needs root on Linux/macOS)")
    parser.add_argument("--no-dhcp-probe", action="store_true",
                         help="Skip the rogue DHCP server probe (LAN broadcast, needs root/admin to bind UDP port 68)")
    parser.add_argument("--no-mdns", action="store_true",
                         help="Skip mDNS/Bonjour device discovery (LAN multicast, a separate protocol/socket path)")
    parser.add_argument("--no-traceroute", action="store_true",
                         help="Skip the traceroute to the internet (A1's third exception to staying fully offline; "
                              "the gateway traceroute is LAN-only and always runs)")
    parser.add_argument("--no-pmtu", action="store_true",
                         help="Skip the PMTU blackhole check (A1's fourth exception to staying fully offline)")
    parser.add_argument("--no-captive-portal", action="store_true",
                         help="Skip the captive portal check (A1's fifth exception to staying fully offline)")
    parser.add_argument("--no-throughput", action="store_true",
                         help="Skip the download throughput measurement (A1's sixth exception to staying fully offline)")
    parser.add_argument("--no-nat-type", action="store_true",
                         help="Skip the STUN public-address/NAT-type check (A1's seventh exception to staying fully offline)")
    parser.add_argument("--cache", action="store_true",
                         help="Also write this scan straight into A6 (Encrypted Local Cache) via write_scan(). "
                              "Needs a6_encrypted_cache_v*.py next to this file and the 'cryptography' package.")
    parser.add_argument("--cache-db", default=None,
                         help="A6 database path (default: A6's own default, network_cache.db)")
    parser.add_argument("--cache-key", default=None,
                         help="A6 key file path (default: A6's own default, network_cache.key)")
    args = parser.parse_args()

    results = run_discovery(
        skip_ports=args.no_ports, skip_wifi=args.no_wifi,
        skip_internet=args.no_internet, skip_upnp=args.no_upnp,
        skip_firewall=args.no_firewall,
        skip_dhcp_probe=args.no_dhcp_probe, skip_mdns=args.no_mdns,
        skip_traceroute=args.no_traceroute, skip_pmtu=args.no_pmtu,
        skip_captive_portal=args.no_captive_portal, skip_throughput=args.no_throughput,
        skip_nat_type=args.no_nat_type,
    )

    if args.json:
        payload = json.dumps(results, indent=2)
        if args.json == "-":
            print("\n" + payload)
        else:
            with open(args.json, "w") as f:
                f.write(payload)
            print(f"\nWrote JSON results to {args.json}")

    if args.cache:
        # _import_a6() itself can raise (e.g. ImportError if 'cryptography' isn't
        # installed -- A6's own module-level import fails the moment we try to
        # load it) so it has to be inside this try too, not just the A6Cache
        # calls below it -- otherwise that exception is unhandled and crashes
        # A1 with a raw traceback instead of the clean message this is meant
        # to give, even though the scan itself already finished successfully.
        try:
            a6 = _import_a6()
            if a6 is None:
                print("\n! --cache: no a6_encrypted_cache_v*.py found next to this file -- scan not cached.",
                      file=sys.stderr)
            else:
                kwargs = {}
                if args.cache_db:
                    kwargs["db_path"] = args.cache_db
                if args.cache_key:
                    kwargs["key_path"] = args.cache_key
                with a6.A6Cache(**kwargs) as cache:
                    scan_id = cache.write_scan(results, source_version=os.path.basename(__file__))
                print(f"\nCached scan as A6 scan id {scan_id} "
                      f"({args.cache_db or a6.DEFAULT_DB_PATH})")
        except ImportError as e:
            print(f"\n! --cache: {e} -- scan not cached (A1 itself still ran fine).", file=sys.stderr)
        except Exception as e:
            print(f"\n! --cache: failed to write to A6: {e} -- scan not cached.", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
