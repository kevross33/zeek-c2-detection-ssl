# C2_SSL — non-TLS sessions on TLS ports.
#
# Detects a genuine, bidirectional TCP session that is NOT TLS on a port
# where TLS is expected (nontls_ports, default 443/tcp) — the signature of a
# custom binary C2 protocol hiding on 443 (e.g. SECTOPRAT/ArechClient2).
#
# Deliberately strict. A session is only judged if Zeek saw it START (client
# SYN and server SYN-ACK), with no content gaps, data in both directions,
# and no protocol analyzer confirmed. It then alerts only with corroborated
# evidence — see the "Non-TLS sessions on TLS ports" block in config.zeek.
#
# No SPL is available here (spl-spt only measures TLS records), so the
# detector works from connection-level facts: history, bytes, duration,
# repeated-session cadence, threat intel and host state.
#
# Exclusions: trusted hosts/subnets, proxies and popular destinations apply
# through triage_skip as for TLS; IPs learned from allowlisted SNIs apply as
# for SNI-less TLS; and domain entries in safe_sni_suffixes apply through
# DNS answers (nontls_dns_exclusions), since these sessions have no SNI.

@load base/protocols/conn
@load base/protocols/dns

@load ./config
@load ./allowlists
@load ./shared
@load ./detect

module C2_SSL;

export {
    # T if a connection history shows the session was observed from its
    # start, with data in both directions and no content gaps.
    global nontls_history_ok: function(h: string): bool;

    # Alert decision from the five evidence items. Returns the number of
    # evidence items when the alert rule is met, else 0.
    global nontls_decide: function(intel: bool, host: bool, cadence: bool,
                                   exfil: bool, session: bool): count;
}

# Repeated gated sessions per (originator, server IP, server port), for the
# cadence evidence. Only sessions that passed the hard gate are stored, so
# this stays tiny; idle expiry follows the beacon detector.
type NontlsFlow: record {
    ts:         vector of time &default = vector();
    total:      count          &default = 0;
    last_alert: time           &default = double_to_time(0);
};

global nontls_flows: table[string] of NontlsFlow
    &write_expire = beacon_max_interval;

# Sessions already alerted (LongConnection may report a session repeatedly).
global nontls_alerted_uids: set[string] &create_expire = 1day;

# Server IPs returned by DNS for allowlisted domains (nontls_dns_exclusions).
global nontls_dns_safe_ips: set[addr] &write_expire = nontls_dns_safe_expiry;

# Per-name allowlist verdict cache, so each DNS name is matched against the
# suffix list once rather than on every reply.
global nontls_dns_name_safe: table[string] of bool &read_expire = 30min;

# ----------------------------------------------------------------------
# Pure helpers (unit-tested).
# ----------------------------------------------------------------------

function nontls_history_ok(h: string): bool
    {
    # Zeek history: S = client SYN, h = server SYN-ACK, D/d = data from
    # client/server, g/G = content gap.
    if ( |h| < 4 )
        return F;
    if ( h[0] != "S" )
        return F;               # joined mid-stream: the start was not seen
    if ( "h" !in h )
        return F;               # no server SYN-ACK observed
    if ( "D" !in h || "d" !in h )
        return F;               # not bidirectional
    if ( "g" in h || "G" in h )
        return F;               # content gap: a ClientHello may be missing
    return T;
    }

function nontls_decide(intel: bool, host: bool, cadence: bool,
                       exfil: bool, session: bool): count
    {
    local n = 0;
    if ( intel )   ++n;
    if ( host )    ++n;
    if ( cadence ) ++n;
    if ( exfil )   ++n;
    if ( session ) ++n;
    if ( n < nontls_min_evidence )
        return 0;
    # At least one EXTERNAL corroborator ...
    if ( ! ( intel || host || cadence ) )
        return 0;
    # ... and at least one STRONG behaviour.
    if ( ! ( intel || cadence || exfil ) )
        return 0;
    return n;
    }

# ----------------------------------------------------------------------
# DNS-driven exclusions.
# ----------------------------------------------------------------------

function nontls_name_is_safe(name: string): bool
    {
    if ( name == "" )
        return F;
    local lc = to_lower(name);
    if ( lc !in nontls_dns_name_safe )
        nontls_dns_name_safe[lc] = is_sni_fully_safe(lc);
    return nontls_dns_name_safe[lc];
    }

function nontls_note_dns_answer(c: connection, ans: dns_answer, a: addr)
    {
    if ( ! nontls_enabled || ! nontls_dns_exclusions )
        return;
    # The answer's owner name, or the original question (CNAME chains end on
    # a CDN name — the question is the allowlisted one).
    if ( nontls_name_is_safe(ans$query) ||
         ( c?$dns && c$dns?$query && nontls_name_is_safe(c$dns$query) ) )
        add nontls_dns_safe_ips[a];
    }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    nontls_note_dns_answer(c, ans, a);
    }

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    nontls_note_dns_answer(c, ans, a);
    }

# ----------------------------------------------------------------------
# Hard gate.
# ----------------------------------------------------------------------

# Cheap pre-check, run on every connection before anything else.
function nontls_candidate(c: connection): bool
    {
    if ( ! nontls_enabled )
        return F;
    if ( c$id$resp_p !in nontls_ports )
        return F;
    if ( get_port_transport_proto(c$id$resp_p) != tcp )
        return F;
    # Any confirmed analyzer (TLS, HTTP, SSH, ...) means it is not an
    # unidentified protocol.
    if ( |c$service| > 0 )
        return F;
    if ( c?$ssl && c$ssl?$established && c$ssl$established )
        return F;
    return T;
    }

function nontls_admit(c: connection): bool
    {
    if ( ! nontls_history_ok(c$history) )
        {
        trace(c$id$orig_h, fmt("%s non-TLS skip: history %s (start not seen, gap, or one-way)",
                               c$uid, c$history));
        return F;
        }
    local ob = c$orig$size;
    local rb = c$resp$size;
    if ( ob == 0 || rb == 0 || ob + rb < nontls_min_bytes )
        {
        trace(c$id$orig_h, fmt("%s non-TLS skip: %d/%d bytes", c$uid, ob, rb));
        return F;
        }
    if ( is_proxy_destination(c$id$resp_h) )
        return F;
    # Outbound scope, trusted hosts/subnets, IPs learned from allowlisted
    # SNIs, popular destinations.
    if ( triage_skip(c) )
        return F;
    if ( c$id$resp_h in nontls_dns_safe_ips )
        {
        trace(c$id$orig_h, fmt("%s non-TLS skip: %s resolved from an allowlisted domain",
                               c$uid, c$id$resp_h));
        return F;
        }
    return T;
    }

# ----------------------------------------------------------------------
# Evaluation.
# ----------------------------------------------------------------------

function nontls_flow_key(c: connection): string
    {
    return fmt("%s|%s|%s", c$id$orig_h, c$id$resp_h, c$id$resp_p);
    }

# Record one completed gated session for the cadence evidence.
function nontls_note_session(c: connection)
    {
    local key = nontls_flow_key(c);
    if ( key !in nontls_flows )
        nontls_flows[key] = NontlsFlow();
    local f = nontls_flows[key];
    f$ts += c$start_time;
    ++f$total;
    if ( |f$ts| > beacon_window_size )
        f$ts = f$ts[1:];
    nontls_flows[key] = f;
    }

# Returns "" when the cadence is not a tight beacon, else a details string.
function nontls_cadence(c: connection): string
    {
    local key = nontls_flow_key(c);
    if ( key !in nontls_flows )
        return "";
    local f = nontls_flows[key];
    if ( f$total < nontls_beacon_min_count || |f$ts| < nontls_beacon_min_count )
        return "";
    if ( f$ts[|f$ts| - 1] - f$ts[0] < beacon_min_observation_duration )
        return "";
    local gaps = ts_gaps(f$ts);
    if ( |gaps| < 2 )
        return "";
    local med = median(gaps);
    if ( med < interval_to_double(nontls_beacon_min_interval) ||
         med > interval_to_double(beacon_max_interval) )
        return "";
    local jitter = mad(gaps, med) / med;
    if ( jitter > beacon_max_jitter )
        return "";
    return fmt(" cnt=%d int=%.1fs jit=%.0f%%", f$total, med, jitter * 100.0);
    }

function nontls_evaluate(c: connection)
    {
    if ( c$uid in nontls_alerted_uids )
        return;

    local dest_id = dest_identity(c);
    note_dest_client(dest_id, c$id$orig_h);
    if ( is_dest_popular(dest_id) )
        return;
    local clients = dest_client_n(dest_id);
    if ( clients > nontls_max_dest_clients )
        {
        trace(c$id$orig_h, fmt("%s non-TLS skip: %s has %d clients", c$uid,
                               dest_id, clients));
        return;
        }

    local ob = c$orig$size;
    local rb = c$resp$size;
    local p = pcr(ob, rb);
    local dur = interval_to_double(c$duration);

    local intel_desc = intel_hit_for_dest(c$id$resp_h);
    local e_intel   = intel_desc != "";
    local e_host    = is_host_compromised(c$id$orig_h);
    local cad       = nontls_cadence(c);
    local e_cadence = cad != "";
    local e_exfil   = ob >= nontls_exfil_min_bytes && p >= nontls_exfil_min_pcr;
    local e_session = dur >= interval_to_double(nontls_session_min_duration);

    local n = nontls_decide(e_intel, e_host, e_cadence, e_exfil, e_session);
    trace(c$id$orig_h, fmt("%s non-TLS %s: intel=%s host=%s cadence=%s exfil=%s session=%s -> %s",
                           c$uid, dest_id,
                           e_intel ? "T" : "F", e_host ? "T" : "F",
                           e_cadence ? "T" : "F", e_exfil ? "T" : "F",
                           e_session ? "T" : "F",
                           n > 0 ? "ALERT" : "below"));
    if ( n == 0 )
        return;

    # Cooldown per originator/server/port.
    local key = nontls_flow_key(c);
    if ( key !in nontls_flows )
        nontls_flows[key] = NontlsFlow();
    local f = nontls_flows[key];
    if ( f$last_alert != double_to_time(0) &&
         network_time() - f$last_alert < alert_cooldown )
        return;
    f$last_alert = network_time();
    nontls_flows[key] = f;
    add nontls_alerted_uids[c$uid];

    local indicators: set[string] = set();
    add indicators["non_tls_on_tls_port"];
    if ( e_intel )   add indicators[fmt("intel_hit:%s", intel_desc)];
    if ( e_host )    add indicators["compromised_host_activity"];
    if ( e_cadence ) add indicators["regular_cadence"];
    if ( e_exfil )   add indicators["exfil_upload_shape"];
    if ( e_session ) add indicators["long_lived_session"];
    if ( clients <= 1 )
        add indicators["single_client_destination"];
    else
        add indicators[fmt("rare_destination_%d_clients", clients)];

    local conf = 0.80 + 0.10 * (n - 2);
    local det_cat = e_cadence ? NONTLS_TLS_PORT_BEACON : NONTLS_TLS_PORT_SESSION;
    local details = fmt("non-tls port=%s dur=%.0fs orig=%d resp=%d pcr=%.2f hist=%s evidence=%d%s",
                        c$id$resp_p, dur, ob, rb, p, c$history, n, cad);

    emit_from_conn(det_cat, conf, c, "", F, details, indicators, INNER_UNKNOWN);
    }

# Completed sessions: count toward cadence, then evaluate.
event connection_state_remove(c: connection) &priority = -5
    {
    if ( ! nontls_candidate(c) )
        return;
    if ( ! nontls_admit(c) )
        return;
    nontls_note_session(c);
    nontls_evaluate(c);
    }

# Long-running sessions: evaluate while still open (not counted for cadence).
event LongConnection::long_conn_found(c: connection)
    {
    if ( ! nontls_candidate(c) )
        return;
    if ( ! nontls_admit(c) )
        return;
    nontls_evaluate(c);
    }
