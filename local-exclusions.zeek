# ============================================================================
# LOCAL EXCLUSIONS & SITE TUNING  —  THIS FILE IS YOURS.
# ============================================================================
#
# Everything site-specific lives here: your allowlisted domains, your proxy
# configuration, your interception CA, and any VLAN/host exclusions.
#
# WHY THIS FILE EXISTS
#   The package ships a curated allowlist in `allowlists.zeek`. That file is
#   maintained upstream and is REPLACED when you upgrade the package. If you
#   edited it directly, every upgrade would wipe your additions.
#
#   This file is different. It only ever EXTENDS the package sets with `+=`,
#   so the upstream lists can grow underneath you without conflict, and your
#   local entries are never touched by a package update.
#
# UPGRADE RULE
#   When upgrading the package, preserve THIS file. Overwrite everything else.
#   This file ships production-ready with your site entries already in place.
#   If your deployment's upgrade tooling would replace the package scripts
#   wholesale, exclude this one file from the overwrite (or re-apply it after).
#
#   (When distributed as a public zkg package the same rule applies: keep your
#   copy of this file across `zkg upgrade`. The package's own curated lists in
#   allowlists.zeek will pick up new well-known domains automatically.)
#
# HOW MATCHING WORKS (same as allowlists.zeek)
#   Leading "."  -> suffix match (any subdomain OR the apex):
#                   ".example.com" matches a.example.com AND example.com
#   No leading "." -> exact FQDN match only:
#                   "host.example.com" matches only that exact name
# ============================================================================

module C2_SSL;

# ----------------------------------------------------------------------------
# 1. Locally allowlisted destinations (FULL BYPASS).
#
#    SNIs / CONNECT hosts ending in (or equal to) any of these are ignored
#    entirely — no beacon, tunnel, or reverse-flow analysis. Use ONLY for
#    destinations you have decided are infeasible-to-abuse or are sanctioned
#    first-party / vendor infrastructure for YOUR environment.
# ----------------------------------------------------------------------------
redef C2_SSL::safe_sni_suffixes += {
    # --- Sanctioned RMM / patch-management instance (exact host) ---
    # Our specific Action1 tenant. The RMM package separately covers the
    # broader .action1.com as an RMM tool; here we bypass C2-SSL analysis
    # for our own managed instance so it does not page the SOC as a beacon.
    "server.eu.action1.com",

    # --- Sanctioned attack-simulation / BAS platform ---
    # NOTE: this deliberately SUPPRESSES C2-like traffic to this domain.
    # ISRG-simulation is our approved breach-and-attack-simulation target.
    # Only keep this while the simulation platform is sanctioned; removing
    # it restores full detection of traffic to that domain.
    ".isrg-simulation.com",

    # Add your own below, one per line, with a comment explaining why:
    # ".vendor.example.com",     # <reason it is safe to bypass>
};

# ----------------------------------------------------------------------------
# 2. Locally trusted-pivot destinations (STILL ANALYSED, JA3-rarity checked).
#
#    Use for abusable-but-legitimate platforms you want kept under analysis
#    rather than fully bypassed (e.g. a CDN or PaaS your org uses but which
#    could also front C2). These are NOT bypassed — they still get full
#    beacon/tunnel analysis plus rare-fingerprint pivot detection.
# ----------------------------------------------------------------------------
redef C2_SSL::trusted_pivot_suffixes += {
    # ".yourcdn.example.com",    # <platform we use but want watched>
};

# ----------------------------------------------------------------------------
# 3. Trusted originator / destination subnets.
#
#    trusted_orig_subnets: client VLANs whose egress you fully trust and do
#      not want analysed (e.g. an isolated management VLAN). Use sparingly —
#      a compromised host here would be invisible.
#    trusted_dest_subnets: internal server ranges to exclude as destinations.
#
#    You can exclude by SUBNET or by INDIVIDUAL IP:
#      *_subnets take set[subnet]  (e.g. 10.99.0.0/24)
#      *_hosts   take set[addr]    (e.g. 10.99.0.5)  — convenience for
#                                    one-off hosts, same effect as a /32.
#
#    ORIGINATOR exclusions (client side): traffic FROM these is never
#      analysed. Use for device VLANs / hosts that legitimately beacon.
#    DESTINATION exclusions (server side): traffic TO these is bypassed.
#      Use narrowly for specific known-good external endpoints that would
#      otherwise look beacon-shaped and have no stable SNI to allowlist.
# ----------------------------------------------------------------------------
# By subnet:
# redef C2_SSL::trusted_orig_subnets += { 10.99.0.0/24, 10.40.0.0/16 };
# redef C2_SSL::trusted_dest_subnets += { 10.0.0.0/8 };
#
# By individual IP:
# redef C2_SSL::trusted_orig_hosts   += { 10.12.7.50, 10.12.7.51 };
# redef C2_SSL::trusted_dest_hosts   += { 203.0.113.10 };

# ----------------------------------------------------------------------------
# 4. PROXY CONFIGURATION  (site-specific — belongs here, not in the package).
#
#    Declare your explicit web proxies so client->proxy flows key against the
#    real destination (SNI / CONNECT host) rather than the proxy IP.
# ----------------------------------------------------------------------------
# redef C2_SSL::proxy_hosts += {
#     10.50.0.10,
#     10.50.0.11,
# };
# redef C2_SSL::proxy_subnets += { 10.50.0.0/24 };

#    Proxy TLS mode. PROXY_INTERCEPTING (default) = SSL-bump / TLS inspection
#    with your own CA. PROXY_NON_INTERCEPTING = plain CONNECT tunnel.
# redef C2_SSL::proxy_mode = C2_SSL::PROXY_INTERCEPTING;

#    Interception CA identification (INTERCEPTING mode). Populate ANY of the
#    three — a match on any one confirms a flow was inspected by YOUR proxy
#    (so its cert / JA3S are the proxy's, not the real upstream). Get these
#    from sanitised proxied ssl.log / x509.log samples.
# redef C2_SSL::proxy_ca_issuers += {
#     "CN=SJH TLS Inspection CA",       # your inspection CA issuer DN fragment
# };
# redef C2_SSL::proxy_ca_fingerprints += {
#     "a1b2c3...full_sha256...",        # from x509.log / cert_chain_fps
# };
# redef C2_SSL::proxy_ja3s += {
#     "2ab44dd8c27bdce434a961463587356a",  # proxy ServerHello JA3S
# };
# redef C2_SSL::proxy_ja4s += {
#     "t120500_c02f_6471ab80eb72",         # proxy ServerHello JA4S
# };

#    Behavioural credit for confirmed-intercepted beacons (offsets the loss
#    of cert signals). Default 0.15. Raise if intercepted beacons sit just
#    under threshold; lower/zero if it over-fires.
# redef C2_SSL::proxy_intercept_behaviour_credit = 0.15;
