# C2 Detection Framework — SSL/TLS module
#
# Behavioural detection of C2 over TLS without per-malware signatures.
# Detects:
#   * Periodic SSL beaconing with low jitter (full handshake or session-resumption pinned)
#   * Long-lived tunnels carrying covert keep-alive / command traffic
#   * Reverse-flow control sessions (server-driven RAT / backdoor command-then-exfil)
#   * Tunnelled-protocol-inside-TLS (TLS-in-TLS or opaque binary tunnel)
#   * Living-off-trusted-sites pivots (rare client fingerprint to popular CDN)
#
# Loads in a deliberate order: config and allowlists first (other files redef them),
# then shared types and helpers, then the detection logic itself.

@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/http
# Site framework — provides Site::is_local_addr / Site::local_nets, used by
# the outbound-only direction filter. Loaded by default in most setups, but
# we require it explicitly so is_internal_addr() always resolves.
@load base/utils/site
# Intel framework — used only for CORROBORATION. Intel hits never fire a C2
# alert on their own; they escalate a behavioural detection whose destination
# also has an operator-provided intel hit. If no Intel feeds are configured
# this loads harmlessly and the corroboration simply never triggers.
@load base/frameworks/intel
# NOTE: do NOT @load base/protocols/x509 — it was merged into
#       base/protocols/ssl in Zeek 5 and no longer exists as a
#       standalone path. Loading it causes the fatal error you saw.

@load ./config
@load ./allowlists
@load ./shared
@load ./detect

# Site-specific tuning that SURVIVES package upgrades. This file only
# extends the package sets with `+=`, and must be preserved (not
# overwritten) when the package is updated. See local-exclusions.zeek
# for the full explanation. Loaded LAST so its redefs win and so it can
# reference types (e.g. ProxyMode) declared by the package above.
@load ./local-exclusions
