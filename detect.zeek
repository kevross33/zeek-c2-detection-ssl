# C2_SSL — main detection logic.
#
# Detectors in this file:
#   1. evaluate_beacon       — periodic full-handshake beaconing
#   2. evaluate_sparse       — slow-roll hour-scale beaconing
#   3. evaluate_tunnel       — long-lived keep-alive / command channel
#   4. evaluate_reverse_flow — server-driven RAT (idle→command→exfil shape)
#   5. evaluate_pivot        — rare JA3 fingerprint to abusable CDN/pivot host
#   6. assess_inner_protocol — what protocol is running inside TLS
#
# Design notes
# -----------
# * Triage runs BEFORE any state allocation. On 30k+ user networks this
#   is the critical path: allowlist hits never touch per-flow tables.
# * All Microsoft 365 / Teams / Exchange / SharePoint / Entra ID
#   infrastructure is in safe_sni_suffixes (full bypass) — see allowlists.zeek.
# * JA3S/JA4S are blanked in alerts when via_proxy=T (they belong to the
#   proxy, not the upstream server, and would mislead analysts).
# * No per-malware signatures anywhere in this file. Detection is purely
#   behavioural: timing, sizing, PCR, resumption patterns, inner-protocol
#   framing. The framework catches unknown tooling as well as known families.

@load ./config
@load ./allowlists
@load ./shared

@load base/protocols/conn
@load base/protocols/ssl

module C2_SSL;

# ====================================================================
# CONNECT-host correlation (explicit-proxy HTTPS)
# ====================================================================
#
# For proxied HTTPS the client sends a plaintext "CONNECT host:port"
# to the proxy before the (tunnelled) TLS handshake. Zeek's HTTP
# analyzer exposes this as an http_request with method "CONNECT" on the
# SAME connection uid as the subsequent SSL activity. We capture the
# CONNECT host keyed by uid so the SSL detectors can recover the real
# destination even when SNI is absent (e.g. Encrypted Client Hello) or
# when we simply want a second, authoritative identity signal.
#
# The table self-expires: entries are only needed for the brief window
# between the CONNECT and the flow being scored.
global connect_host_by_uid: table[string] of string
    &create_expire = 1hr;

# Record the CONNECT target host for this connection uid.
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority = 5
    {
    if ( method != "CONNECT" ) return;
    # For CONNECT the URI is "host:port". Strip the trailing :port.
    # IPv6 literals are bracketed ("[2001:db8::1]:443") so we split on the
    # LAST colon, which always precedes the port for both host forms.
    local host = original_URI;
    local port_sep = 0;
    local idx = 1;
    local n = |original_URI|;
    while ( idx <= n )
        {
        if ( original_URI[idx - 1:idx] == ":" )
            port_sep = idx;
        ++idx;
        }
    if ( port_sep > 1 )
        host = original_URI[0:port_sep - 1];
    # Strip IPv6 brackets if present.
    if ( |host| >= 2 && host[0:1] == "[" && host[|host| - 1:] == "]" )
        host = host[1:|host| - 1];
    if ( host != "" )
        connect_host_by_uid[c$uid] = to_lower(host);
    }



# Returns T if this connection should be completely ignored.
# Called from every entry point before any work is done.
function triage_skip(c: connection): bool
    {
    # Direction / scope gate — OUTBOUND C2 ONLY. Drop inbound
    # (external->internal, e.g. RDP brute-force) and, by default, east-west
    # flows. This is the single point that scopes every detector to internal
    # clients calling out. See c2_require_outbound / c2_internal_nets.
    if ( c2_require_outbound && ! is_outbound_flow(c) )
        return T;

    if ( is_orig_trusted(c$id$orig_h) )   return T;
    if ( is_dest_trusted(c$id$resp_h) )   return T;
    # Skip flows where the originator IS a proxy (proxy→upstream)
    if ( is_proxy_destination(c$id$orig_h) ) return T;
    # An operator allowlist entry is ABSOLUTE. If a destination has been
    # explicitly declared safe it is never analysed, and nothing revokes that
    # — no certificate condition, no cert/SNI mismatch, no validation
    # failure. Rationale: an allowlist the tool silently overrides is worse
    # than no allowlist, because the operator cannot reason about what the
    # tool is doing. Plenty of legitimate infrastructure (on-prem appliances,
    # vendor devices, embedded web UIs, medical/lab equipment) serves a real
    # hostname with a self-signed or non-matching certificate, and revoking
    # the bypass for those produced intermittent false positives that
    # devalued every alert around them.
    #
    # Domain fronting is NOT abandoned — it is handled where it belongs:
    #   * trusted_pivot_suffixes: legitimate-but-abusable platforms stay
    #     under full behavioural analysis rather than being bypassed.
    #   * cert_sni_mismatch is still scored on every non-allowlisted flow.
    # Reliable SNI-vs-Host-header comparison requires decryption and is a
    # proxy/firewall function; this package detects C2 by BEHAVIOUR, so a
    # fronted channel is caught by its beacon/tunnel shape, not by its cert.
    if ( c?$ssl && c$ssl?$server_name &&
         is_sni_fully_safe(c$ssl$server_name) )
        return T;
    # Also honour the plaintext CONNECT host for the safe-SNI bypass. This
    # matters for proxied HTTPS where SNI may be absent (Encrypted Client
    # Hello) but the CONNECT target is a known-safe first-party service.
    if ( c$uid in connect_host_by_uid &&
         is_sni_fully_safe(connect_host_by_uid[c$uid]) )
        return T;

    # Popularity bypass — destinations contacted by >popular_dest_threshold
    # distinct clients in the network are skipped entirely. This is the
    # primary defence against tracking legitimate niche browsing traffic
    # without needing pre-curated allowlists for every service.
    if ( is_dest_popular(dest_identity(c)) )
        return T;

    return F;
    }

# Returns T if the connection is too small/short/aborted to track.
function below_track_floor(c: connection): bool
    {
    if ( ! c?$duration )            return T;
    if ( c$duration < min_track_duration ) return T;
    if ( ! c?$conn )                return T;
    # conn_state is &optional in Conn::Info — guard the field access.
    if ( ! c$conn?$conn_state )     return T;
    if ( c$conn$conn_state !in valid_conn_states ) return T;
    local total: count = 0;
    if ( c?$orig && c$orig?$size ) total += c$orig$size;
    if ( c?$resp && c$resp?$size ) total += c$resp$size;
    if ( total < min_track_bytes )  return T;
    return F;
    }

# ====================================================================
# SECTION 2 — ALERT EMISSION
# ====================================================================

function emit(category: Category, confidence: double,
              orig_h: addr, resp_h: addr, resp_p: port,
              st: FlowState, details: string,
              indicators: set[string], sample_uid: string,
              inner: InnerProto)
    {
    local rec: Info;
    rec$ts               = network_time();
    rec$category         = category;
    rec$confidence       = confidence > 1.0 ? 1.0 : confidence;
    rec$orig_h           = orig_h;
    rec$resp_h           = resp_h;
    rec$resp_p           = resp_p;
    rec$sni              = st$sni;
    rec$via_proxy        = st$via_proxy;
    rec$proxy_intercepted = st$proxy_intercepted;
    rec$connect_host     = st$connect_host;
    rec$details          = details;
    rec$sample_count     = st$total_seen;
    rec$total_orig_bytes = st$total_orig_bytes;
    rec$total_resp_bytes = st$total_resp_bytes;
    rec$duration_seen    = st$last_seen - st$first_seen;
    rec$pcr              = pcr(st$total_orig_bytes, st$total_resp_bytes);
    rec$tls_version      = st$tls_version;
    rec$cert_issuer      = st$cert_issuer;
    rec$cert_validation  = st$cert_validation;
    rec$alpn             = st$alpn;
    rec$inner_proto      = inner;
    rec$ja3              = st$ja3;
    rec$ja4              = st$ja4;
    # st$ja3s/st$ja4s are only populated for flows where the fingerprint is
    # the REAL upstream's (direct, or non-intercepting proxy). For a
    # confirmed-intercepted flow they were never stored, so emitting them
    # directly is correct in all cases.
    rec$ja3s             = st$ja3s;
    rec$ja4s             = st$ja4s;
    rec$sample_uid   = sample_uid;
    rec$indicators   = indicators;
    Log::write(C2_SSL::LOG, rec);

    # Notices are disabled by default (generate_notices = F).
    # Enable only after tuning thresholds — to avoid alerting pipelines
    # firing on benign traffic during initial deployment.
    if ( generate_notices )
        {
        NOTICE([$note        = C2_Detected,
                $src         = orig_h,
                $dst         = resp_h,
                $p           = resp_p,
                $msg         = fmt("[c2-detection-ssl] %s conf=%.2f sni=%s %s",
                                   cat(category), confidence,
                                   st$sni == "" ? "(no-sni)" : st$sni,
                                   details),
                $identifier  = fmt("%s-%s-%s", orig_h, resp_h,
                                   st$sni == "" ? fmt("%s", resp_h) : st$sni),
                $suppress_for = alert_cooldown]);
        }
    }

# Emit variant for single-connection events (tunnel / reverse-flow).
function emit_from_conn(category: Category, confidence: double,
                        c: connection, sni: string, via_proxy: bool,
                        details: string, indicators: set[string],
                        inner: InnerProto)
    {
    local rec: Info;
    rec$ts           = network_time();
    rec$category     = category;
    rec$confidence   = confidence > 1.0 ? 1.0 : confidence;
    rec$orig_h       = c$id$orig_h;
    rec$resp_h       = c$id$resp_h;
    rec$resp_p       = c$id$resp_p;
    rec$sni          = sni;
    rec$via_proxy    = via_proxy;
    # Real destination from the plaintext CONNECT, when available.
    if ( c$uid in connect_host_by_uid )
        rec$connect_host = connect_host_by_uid[c$uid];
    rec$details      = details;
    rec$sample_count = 1;
    if ( c?$orig && c$orig?$size ) rec$total_orig_bytes = c$orig$size;
    if ( c?$resp && c$resp?$size ) rec$total_resp_bytes = c$resp$size;
    if ( c?$duration )             rec$duration_seen    = c$duration;
    rec$pcr        = pcr(rec$total_orig_bytes, rec$total_resp_bytes);
    rec$inner_proto = inner;

    # Determine whether this proxied flow is a confirmed interception, so
    # we (a) flag it and (b) decide whether the server fingerprints are the
    # proxy's (blank them) or the real upstream's (keep them).
    local emit_intercepted = F;
    if ( via_proxy && proxy_mode == PROXY_INTERCEPTING && c?$ssl )
        {
        local ei = (c$ssl?$issuer) ? c$ssl$issuer : "";
        local e3 = (c$ssl?$ja3s) ? c$ssl$ja3s : "";
        local e4 = (c$ssl?$ja4s) ? c$ssl$ja4s : "";
        if ( is_proxy_ca_issuer(ei) || is_proxy_server_fp(e3, e4) )
            emit_intercepted = T;
        }
    rec$proxy_intercepted = emit_intercepted;

    if ( c?$ssl )
        {
        if ( c$ssl?$version )           rec$tls_version    = c$ssl$version;
        if ( c$ssl?$next_protocol )     rec$alpn           = c$ssl$next_protocol;
        if ( c$ssl?$ja3 )               rec$ja3            = c$ssl$ja3;
        if ( c$ssl?$ja4 )               rec$ja4            = c$ssl$ja4;
        # Cert issuer/validation only meaningful when NOT intercepted.
        if ( ! emit_intercepted )
            {
            if ( c$ssl?$validation_status ) rec$cert_validation = c$ssl$validation_status;
            if ( c$ssl?$issuer )            rec$cert_issuer    = c$ssl$issuer;
            }
        # Keep server fingerprints unless they belong to the proxy: that is
        # the case only for a confirmed interception. A non-intercepting
        # proxy yields real end-to-end ja3s/ja4s worth logging.
        if ( ! emit_intercepted )
            {
            if ( c$ssl?$ja3s ) rec$ja3s = c$ssl$ja3s;
            if ( c$ssl?$ja4s ) rec$ja4s = c$ssl$ja4s;
            }
        }
    rec$sample_uid   = c$uid;
    rec$indicators   = indicators;
    Log::write(C2_SSL::LOG, rec);

    if ( generate_notices )
        {
        NOTICE([$note        = C2_Detected,
                $conn        = c,
                $src         = c$id$orig_h,
                $dst         = c$id$resp_h,
                $p           = c$id$resp_p,
                $msg         = fmt("[c2-detection-ssl] %s conf=%.2f sni=%s %s",
                                   cat(category), rec$confidence,
                                   sni == "" ? "(no-sni)" : sni,
                                   details),
                $identifier  = fmt("%s-%s-%s", c$id$orig_h, c$id$resp_h,
                                   sni == "" ? fmt("%s", c$id$resp_h) : sni),
                $suppress_for = alert_cooldown]);
        }
    }

# ====================================================================
# SECTION 3 — INNER PROTOCOL ASSESSMENT
# ====================================================================
#
# Classifies what protocol is likely running inside the TLS tunnel by
# examining:
#   a) ALPN — if the negotiated protocol is not HTTP/1.1 or h2, it is
#      immediately flagged as non-standard.
#   b) Packet size distribution (from SPL orig_spl) — HTTPS has wide
#      variance (small headers + large TLS app-data records); fixed-framing
#      protocols (SSH, RDP, custom binary C2) have tight distributions.
#   c) Packet size ratio (max/median) — low ratio = fixed framing.
#
# Returns the InnerProto classification and a set of indicator strings.
# Zeek has no &out / pass-by-reference parameter attributes; both values
# are bundled in a record and the caller merges the indicators.
type InnerProtoResult: record {
    proto:      InnerProto;
    indicators: set[string];
};

function assess_inner_protocol(c: connection): InnerProtoResult
    {
    local result: InnerProtoResult;
    result$proto      = INNER_UNKNOWN;
    result$indicators = set();

    # --- ALPN check ---
    local alpn = "";
    if ( c?$ssl && c$ssl?$next_protocol )
        alpn = to_lower(c$ssl$next_protocol);

    if ( alpn != "" && alpn != "-" && alpn !in known_https_alpn )
        {
        add result$indicators["nonstandard_alpn"];
        result$proto = INNER_NONSTANDARD_ALPN;
        return result;
        }

    # --- SPL packet-size analysis ---
    if ( ! c?$spl || ! c$spl?$orig_spl )
        return result;

    local spl = c$spl$orig_spl;
    local n = |spl|;
    if ( n < inner_proto_min_spl_pkts )
        return result;

    # Build a double vector for statistics (SPL is vector of count).
    local sizes: vector of double = vector();
    local i = 0;
    while ( i < n )
        {
        sizes += spl[i] + 0.0;
        ++i;
        }

    local med = median(sizes);
    if ( med <= 0.0 )
        return result;

    local var = variance_double(sizes, med);

    # Find max size for ratio test.
    local max_sz = 0.0;
    i = 0;
    while ( i < n )
        {
        if ( sizes[i] > max_sz ) max_sz = sizes[i];
        ++i;
        }
    local size_ratio = max_sz / med;

    # Very small, very uniform packets = heartbeat / keepalive C2.
    if ( med < 100.0 && var < 500.0 )
        {
        add result$indicators["tiny_uniform_packets"];
        result$proto = INNER_SMALL_UNIFORM;
        return result;
        }

    # Tight size distribution + low max/median ratio = fixed framing.
    # (SSH-over-TLS, RDP-over-TLS, hVNC, inner TLS records all qualify)
    if ( var < inner_proto_size_variance_max &&
         size_ratio < inner_proto_max_size_ratio )
        {
        add result$indicators["fixed_frame_inner_protocol"];
        result$proto = INNER_FIXED_FRAME;
        return result;
        }

    # Wide max/median ratio with high variance = consistent with HTTPS
    # (small header frames mixed with large app-data records).
    if ( size_ratio > 10.0 && var > 50000.0 )
        {
        result$proto = INNER_LIKELY_HTTPS;
        return result;
        }

    # Irregular large bursts suggest binary file-transfer C2.
    if ( size_ratio > inner_proto_max_size_ratio && var > 5000.0 )
        {
        add result$indicators["binary_burst_inner_protocol"];
        result$proto = INNER_BINARY_BURST;
        return result;
        }

    return result;
    }

# ====================================================================
# SECTION 4 — BEACON SCORING
# ====================================================================

function resumption_ratio(st: FlowState): double
    {
    local n = |st$resumed_window|;
    if ( n == 0 ) return 0.0;
    local r = 0;
    local i = 0;
    while ( i < n ) { if ( st$resumed_window[i] ) ++r; ++i; }
    return (r + 0.0) / (n + 0.0);
    }

# has_beacon_or_tunnel_shape — does this flow's accumulated state exhibit
# genuine beaconing/tunnel BEHAVIOUR (not just "several connections")? Applies
# the same core behavioural bar the beacon detector uses: enough samples over
# enough time, a real timing cadence (tight/jittered-but-bounded), OR
# resumption pinning. Used to STRONGLY GATE the trusted-pivot detector so it
# only fires on living-off-trusted-sites C2 that actually beacons/tunnels to
# the trusted domain — not on ordinary cloud/API chatter that merely happens
# to use a rare client fingerprint. This only ever ADDS a requirement, so it
# cannot increase false positives.
# Collapse runs of connections within beacon_burst_collapse into one
# event. Prevents a single page-load from looking like sub-second beaconing.
function collapse_bursts(ts: vector of time): vector of time
    {
    local out: vector of time = vector();
    local n = |ts|;
    if ( n == 0 ) return out;
    out += ts[0];
    local last = ts[0];
    local i = 1;
    while ( i < n )
        {
        if ( ts[i] - last >= beacon_burst_collapse )
            { out += ts[i]; last = ts[i]; }
        ++i;
        }
    return out;
    }

# has_beacon_or_tunnel_shape — does this flow's accumulated state exhibit
# genuine beaconing/tunnel BEHAVIOUR (not just "several connections")? Applies
# the same core behavioural bar the beacon detector uses: enough samples over
# enough time, a real timing cadence (tight/jittered-but-bounded), OR
# resumption pinning. Used to STRONGLY GATE the trusted-pivot detector so it
# only fires on living-off-trusted-sites C2 that actually beacons/tunnels to
# the trusted domain — not on ordinary cloud/API chatter that merely happens
# to use a rare client fingerprint. This only ever ADDS a requirement, so it
# cannot increase false positives. Defined here (after collapse_bursts, which
# it calls) so all its callees are already in scope.
function has_beacon_or_tunnel_shape(st: FlowState): bool
    {
    # Must carry real data (the 0-byte "connection" case is not a channel).
    if ( st$total_orig_bytes == 0 && st$total_resp_bytes == 0 )
        return F;

    # Enough repeated contact over enough time (same bar as the beacon path).
    if ( st$total_seen < beacon_min_count )
        return F;
    if ( st$last_seen - st$first_seen < beacon_min_observation_duration )
        return F;

    # Resumption pinning is itself a strong C2 cadence signal.
    local res_ratio = resumption_ratio(st);
    if ( st$total_seen >= pinning_min_count && res_ratio >= pinning_min_ratio )
        return T;

    # Otherwise require a genuine periodic cadence: collapse bursts, need a
    # healthy number of intervals, a positive median within the beacon range,
    # and jitter no worse than the jittered-beacon tier (chaotic = not a
    # beacon).
    local collapsed = collapse_bursts(st$ts_window);
    if ( |collapsed| < beacon_min_count )
        return F;
    local gaps = ts_gaps(collapsed);
    if ( |gaps| < 5 )
        return F;
    local med = median(gaps);
    if ( med <= 0.0 )
        return F;
    if ( med > interval_to_double(beacon_max_median_interval) )
        return F;
    local jitter = mad(gaps, med) / med;
    if ( jitter > beacon_jittered_max )
        return F;

    return T;
    }

# Count payload sizes that are more than 2x the modal size.
# These are task-delivery or exfil events within an otherwise-uniform flow.
function count_anomalous_payloads(sizes: vector of count): count
    {
    local n = |sizes|;
    if ( n == 0 ) return 0;
    local m = mode_count(sizes);
    if ( m == 0 ) return 0;
    local hits = 0;
    local i = 0;
    while ( i < n )
        {
        if ( sizes[i] + 0.0 > (m + 0.0) * 2.0 ) ++hits;
        ++i;
        }
    return hits;
    }

# Evaluate whether the accumulated FlowState looks like a beacon.
function evaluate_beacon(k: FlowKey, st: FlowState, resp_p: port)
    {
    if ( st$total_seen < beacon_min_count )
        return;

    # ---- Bidirectionality gate ----
    # Require that we have seen a server fingerprint (ja3s or ja4s) for
    # this flow. If the server never responded — firewall dropped, host
    # unreachable, DNS failure — we will never have a server fingerprint.
    # Blocked connections often look beacon-shaped (malware retrying on a
    # timer) but represent zero actual C2 communication. Skip them.
    if ( require_bidirectional && ! st$server_seen )
        return;

    # ---- RDP suppression for trusted destinations ----
    # If the responder is a known-legitimate RDP destination, skip beacon
    # analysis entirely. Lateral RDP (internal→internal not in this set)
    # is still in scope.
    if ( |trusted_rdp_dest_subnets| > 0 && st?$last_resp_h &&
         resp_p in rdp_ports )
        {
        for ( s in trusted_rdp_dest_subnets )
            if ( st$last_resp_h in s )
                return;
        }

    # ---- Observation duration gate ----
    # The flow must have been observed for at least beacon_min_observation_duration
    # before we'll alert. This is the dominant time-based confidence
    # gate: even a perfect-shape beacon with 50 samples in 90 seconds (a
    # web app keep-alive burst, or a sandbox replay running fast) will
    # not alert until it has been seen for long enough. A real C2
    # implant will sit on a network for hours/days, so we lose nothing.
    #
    # EXCEPTION — strong session-resumption pinning. A flow that has
    # resumed the same TLS session many times in a short window is not a
    # web keep-alive: benign browsers and apps do not pin-and-resume 20+
    # times to one destination in a couple of minutes. TLS resumption at
    # that volume is a machine hammering a session ticket — beacon-shaped
    # regardless of wall-clock span. So a strongly-pinned, well-sampled
    # flow may satisfy this gate on pinning alone. This is what catches a
    # dense Cobalt Strike / Havoc burst captured over only a few minutes,
    # while the ALPN/cert suppressors below still keep benign resumed web
    # traffic (which carries h2 ALPN + valid certs) from firing.
    local early_res_ratio = resumption_ratio(st);
    local strong_pinned = (st$total_seen >= pinning_strong_count &&
                           early_res_ratio >= pinning_min_ratio);
    if ( st$last_seen - st$first_seen < beacon_min_observation_duration &&
         ! strong_pinned )
        return;

    # Cooldown guard.
    if ( st$last_alert != double_to_time(0) &&
         network_time() - st$last_alert < alert_cooldown )
        return;

    local collapsed = collapse_bursts(st$ts_window);
    if ( |collapsed| < beacon_min_count )
        return;

    local gaps = ts_gaps(collapsed);
    if ( |gaps| < 5 )
        return;

    local med = median(gaps);
    if ( med <= 0.0 )
        return;
    local m = mad(gaps, med);
    local jitter = m / med;

    # ---- Maximum interval gate ----
    # Connections slower than beacon_max_median_interval are not fast
    # beacons and are ignored. Without this gate, very-slow regular polling
    # produces high-confidence FPs.
    if ( med > interval_to_double(beacon_max_median_interval) )
        return;

    local res_ratio = resumption_ratio(st);
    local is_pinned = (st$total_seen >= pinning_min_count &&
                       res_ratio >= pinning_min_ratio);

    # ---- Jitter classification ----
    # Modern C2 (Cobalt Strike, Sliver, Havoc, Brute Ratel) deliberately
    # jitters beacon intervals to defeat naive periodicity detection.
    # CS default jitter is 0-37%; operators routinely set 20-50%. We must
    # NOT treat "has jitter" as "not a beacon" — that is exactly the evasion
    # the malware is paying for. Instead we recognise three tiers:
    #
    #   tight   (jitter <= beacon_max_jitter, default 0.30): classic beacon
    #   jittered(jitter <= beacon_jittered_max, default 0.60): jittered C2 —
    #           still highly regular relative to human browsing, needs a
    #           slightly higher sample count and corroborating signal
    #   chaotic (jitter > beacon_jittered_max): genuinely irregular; only
    #           pursued if resumption-pinned (which is itself C2-defining)
    local is_tight    = jitter <= beacon_max_jitter;
    local is_jittered = ! is_tight && jitter <= beacon_jittered_max;

    # ---- Machine-driven gate (jitter-aware) ----
    # Sub-threshold intervals are definitionally machine-driven. Above that,
    # the flow must be tight, jittered-with-enough-samples, or pinned.
    # A chaotic non-pinned flow with a fast median is not pursued.
    if ( med > interval_to_double(machine_driven_min_interval) &&
         ! is_tight && ! is_pinned )
        {
        # Jittered beacons are allowed through ONLY when we have enough
        # samples to be confident the regularity is real (a handful of
        # coincidentally-spaced connections shouldn't qualify).
        if ( ! ( is_jittered && st$total_seen >= beacon_jittered_min_count ) )
            return;
        }

    # ---- Active abandonment: genuinely chaotic, unpinned, well-sampled. ----
    #
    # Only abandon a flow as "definitely not a beacon" when it is beyond
    # even the jittered tier AND unpinned AND we have plenty of samples.
    # This is far more conservative than before (which abandoned at 50%),
    # so jittered C2 in the 30-60% band is retained and scored rather than
    # silently dropped — trading a little memory for fewer false negatives.
    if ( jitter > beacon_chaotic_threshold && ! is_pinned &&
         st$total_seen >= early_jitter_sample_floor )
        {
        delete flow_state[k];
        return;
        }

    if ( ! is_pinned && st$total_seen < beacon_alert_min_count )
        return;

    # Count sleeps and payload anomalies.
    local sleep_count = 0;
    local i = 0;
    while ( i < |gaps| )
        {
        if ( gaps[i] > interval_to_double(beacon_sleep_threshold) )
            ++sleep_count;
        ++i;
        }
    local tasks = count_anomalous_payloads(st$resp_size_window);
    local exfil  = count_anomalous_payloads(st$orig_size_window);

    # ---- Confidence assembly ----
    #
    # time_score rewards regularity. For a jittered beacon we don't want to
    # collapse the score to near-zero just because jitter is 0.4-0.6 — the
    # flow is still far more regular than human browsing. We use a scaled
    # score: tight beacons (<=0.30) score high, jittered beacons retain a
    # meaningful floor, and the periodicity itself is treated as a positive
    # behavioural signal rather than only a multiplier.
    local time_score = 0.0;
    if ( is_tight )
        # 0% jitter → 1.0, 30% jitter → ~0.85
        time_score = 1.0 - (jitter * 0.5);
    else if ( is_jittered )
        # 30% jitter → ~0.85, 45% → ~0.70, 60% jitter → ~0.55. A jittered-
        # but-regular beacon still earns a solid behavioural score. The
        # gentle slope (1.00) is deliberate: false negatives are the priority,
        # so a jittered beacon with a single corroborating signal (suspect
        # cert, no SNI, rare dest) should reach threshold. Legitimate browsing
        # at this jitter still can't fire without such a signal, and a
        # valid-cert penalty keeps benign services well clear.
        time_score = 0.85 - ((jitter - beacon_max_jitter) * 1.00);
    else
        # chaotic but pinned (only path that reaches here): timing adds little
        time_score = 0.20;

    if ( time_score < 0.0 ) time_score = 0.0;

    # ---- Timing-symmetry (Bowley skewness) adjustment ----
    # Complements the jitter tiers: even a jittered beacon has a SYMMETRIC
    # inter-arrival distribution, whereas bursty traffic that merely clusters
    # tends to be lopsided. Gated on sample count (Bowley is noisy on small
    # windows) and applied as a bounded nudge to time_score, never a gate.
    local skew_tag = "";
    if ( beacon_skew_enabled && |gaps| >= beacon_skew_min_samples )
        {
        local skew = bowley_skewness(gaps);
        local abs_skew = skew < 0.0 ? -skew : skew;

        if ( abs_skew <= beacon_skew_symmetric_max )
            {
            # Symmetric timing — corroborates a genuine beacon. This helps a
            # jittered-but-regular beacon recover confidence (FN priority).
            time_score += beacon_skew_symmetric_bonus;
            skew_tag = "symmetric_timing";
            }
        else if ( abs_skew >= beacon_skew_asymmetric_min && ! is_pinned )
            {
            # Strongly asymmetric timing on a NON-pinned flow — lopsided tail
            # is uncharacteristic of a machine beacon. Pinned flows are exempt
            # (pinning is C2-defining and can legitimately carry sleeps).
            time_score -= beacon_skew_asymmetric_penalty;
            skew_tag = "asymmetric_timing";
            }

        if ( time_score < 0.0 ) time_score = 0.0;
        if ( time_score > 1.0 ) time_score = 1.0;
        }

    local conf = 0.0;

    if ( is_pinned )
        {
        # Pinning weight scales with resumption ratio (80% → 0.40, 100% → 0.50).
        # Time uniformity contributes a 25% weight. A 99%-pinned flow reaches
        # ~0.66 from behavioural signals alone; any weak secondary indicator
        # pushes it over the 0.70 threshold.
        conf = (res_ratio * 0.50) + (time_score * 0.25);
        }
    else
        {
        # Non-pinned base: the behavioural beacon shape is worth more than
        # before (0.65 weight) so that a clean jittered beacon can approach
        # threshold on timing regularity alone, then cross it with one
        # corroborating TLS/population signal.
        conf = time_score * 0.65;
        }

    local indicators: set[string] = set();
    if ( is_pinned )
        add indicators["session_resumption_pinned"];

    # Tag the jitter tier so analysts can see the beacon character.
    if ( is_jittered )
        add indicators["jittered_beacon"];

    # Tag the timing-symmetry verdict (Bowley skewness) when it applied.
    if ( skew_tag != "" )
        add indicators[skew_tag];

    # ---- Payload-size Peak Density corroborator ----
    # Attackers jitter timing, but an idle check-in is a fixed size. Strong
    # concentration of the response-size distribution is therefore a
    # timing-independent "mechanical heartbeat" signal. Applied as a positive
    # corroborator only; it never creates or blocks a detection. The larger
    # bonus is reserved for the UPPER-TIER (jittered) case, where timing looks
    # evasive but the fixed payload size betrays the beacon — the specific
    # false-negative this is meant to rescue.
    if ( peak_density_enabled &&
         |st$resp_size_window| >= peak_density_min_samples )
        {
        local pdens = peak_density(st$resp_size_window);
        if ( pdens >= peak_density_strong )
            {
            if ( is_jittered )
                {
                conf += peak_density_jittered_bonus;
                add indicators["fixed_size_heartbeat_jittered"];
                }
            else
                {
                conf += peak_density_bonus;
                add indicators["fixed_size_heartbeat"];
                }
            }
        }

    # No SNI — common in lower-quality C2 tooling contacting raw IPs.
    if ( st$sni == "" || st$sni == "(empty)" )
        {
        conf += 0.10;
        add indicators["no_sni"];
        }

    # ---- Certificate-based signals ----
    # These are only meaningful when we can see the REAL server cert. For a
    # confirmed proxy-intercepted flow the cert is the proxy's re-signed
    # cert, so issuer / validation / SNI-match tell us nothing about the
    # upstream. We skip them entirely and compensate below so the loss of
    # cert signal does not become a false negative.
    if ( ! st$proxy_intercepted )
        {
        # Suspect certificate issuer.
        if ( has_suspect_issuer(st$cert_issuer) )
            {
            conf += 0.25;
            add indicators["suspect_issuer"];
            }

        # Certificate validation failures.
        if ( st$cert_validation != "" && st$cert_validation != "ok" &&
             st$cert_validation != "-" )
            {
            if ( "self signed"        in st$cert_validation ||
                 "expired"            in st$cert_validation ||
                 "signature failure"  in st$cert_validation )
                {
                conf += 0.15;
                add indicators["bad_cert_validation"];
                }
            else if ( "unable to get local issuer" in st$cert_validation )
                {
                # Weaker signal on its own — common in some enterprise PKI
                # configs — but meaningful in combination with beaconing.
                conf += 0.05;
                add indicators["unrooted_cert_chain"];
                }
            }
        }
    else
        {
        # ---- Intercepted-flow compensation ----
        # We have lost all cert signals for this flow. To avoid a false
        # negative, give a modest behavioural credit: a flow that beacons
        # regularly THROUGH the inspecting proxy to a destination the proxy
        # bothered to tunnel is still a beacon. The credit is deliberately
        # small (it must not fire on its own) and is only awarded to flows
        # that already exhibit beacon shape (we are past the jitter gates
        # by this point). Real benign web traffic is suppressed later by
        # the web-ALPN / popularity logic, which still works through a proxy.
        conf += proxy_intercept_behaviour_credit;
        add indicators["proxy_intercepted"];
        }

    # ---- Web-traffic suppression (the big FP killer) ----
    #
    # If this flow has EVER negotiated an HTTP-family ALPN (h2 / http/1.1
    # / etc.), it's web traffic and very probably benign. The flag is
    # sticky: once set, it stays set even when subsequent (resumed)
    # sessions don't re-negotiate ALPN. This kills the Facebook /
    # messenger.com / fbcdn.net FP class outright, and any other web
    # service that beacons from a stock browser keep-alive.
    if ( st$seen_web_alpn )
        {
        conf -= web_alpn_penalty;
        add indicators["web_alpn_observed"];
        }

    # ---- Browser-JA4 penalty (fuzzy fingerprint, gated) ----
    #
    # Apply the browser-cipher penalty ONLY when the current flow's
    # own JA4 first-segment ALPN field also indicates HTTP. Same cipher
    # set + HTTP ALPN = browser doing HTTPS = legitimate. Same cipher
    # set + no ALPN = malware reusing OpenSSL/Chrome cipher list to look
    # ordinary, but exposing itself by not offering ALPN.
    #
    # This catches the subtle case where C2 borrows browser cipher
    # ordering but skips ALPN because the inner protocol isn't HTTP.
    local cur_ja4_alpn = ja4_alpn_field(st$ja4);
    local cur_ja4_is_web = (cur_ja4_alpn == "h2" || cur_ja4_alpn == "h1" ||
                            cur_ja4_alpn == "h0");
    if ( st$ja4 != "" && is_browser_ja4(st$ja4) && cur_ja4_is_web )
        {
        conf -= browser_ja4_penalty;
        add indicators["browser_ja4_cipher_set"];
        }

    # ---- "Browser cipher set without ALPN" — positive C2 indicator ----
    # Same cipher set we've seen do HTTPS elsewhere, but THIS flow
    # offers no ALPN. Strong indicator of malware mimicking Chrome's
    # TLS handshake without actually doing HTTP. The JA4 ALPN field
    # of "00" means the client offered no ALPN at all.
    if ( st$ja4 != "" && is_browser_ja4(st$ja4) && cur_ja4_alpn == "00" )
        {
        conf += 0.20;
        add indicators["browser_cipher_no_alpn"];
        }

    # ---- TLS 1.3 + no ALPN = Go-based TLS stack ----
    # Legitimate TLS 1.3 clients (browsers, OS agents, enterprise apps)
    # ALWAYS offer at least h2 or http/1.1 ALPN in the ClientHello.
    # TLS 1.3 without ANY ALPN (JA4 ALPN field = "00") is characteristic
    # of Go's crypto/tls — the default TLS library used by Sliver, Cobalt
    # Strike (Go variant), BazarLoader, and many other C2 frameworks.
    # This is the key signal when x509 cert data is unavailable, and
    # fires regardless of whether the cipher has been seen doing HTTPS.
    # The check for cur_ja4_alpn == "00" AND tls version being 1.3 targets
    # exactly the Go-TLS fingerprint without over-flagging TLS 1.2 clients
    # which more legitimately omit ALPN (some older enterprise software).
    if ( st$ja4 != "" && cur_ja4_alpn == "00" &&
         (st$tls_version == "TLSv13" || st$tls_version == "TLS13") )
        {
        conf += 0.15;
        add indicators["tls13_no_alpn"];
        }

    # ---- ALPN positively-suspicious anomaly ----
    # A non-HTTP ALPN explicitly advertised (not just "no ALPN") means
    # the client is using TLS to wrap something else — relatively rare,
    # genuinely interesting.
    if ( st$alpn != "" && st$alpn != "-" && ! is_web_alpn(st$alpn) )
        {
        conf += 0.10;
        add indicators["nonstandard_alpn"];
        }

    # ---- Certificate / SNI mismatch (SAN-aware) ----
    # Use Zeek's built-in c$ssl$sni_matches_cert verdict — it checks
    # CN AND every SAN entry via x509_check_cert_hostname() and handles
    # wildcards correctly. A pure CN check is unsafe: messenger.com's
    # cert has CN=*.facebook.com but a SAN of messenger.com, so
    # CN-only would falsely flag mismatch. Trusting Zeek's verdict
    # avoids that whole class of FP.
    #
    # Catches: `CN=jquery.com` for `zuppohealth.com`, `CN=localhost`
    # for arbitrary destinations, and any cert reuse across unrelated
    # hostnames typical of stolen / repurposed C2 certs.
    if ( st$sni_matches_cert == "F" )
        {
        conf += cert_sni_mismatch_bonus;
        add indicators["cert_sni_mismatch"];
        }

    # ---- Valid CA chain + SNI matches cert = probably-legitimate service ----
    # When the cert chain validates AND Zeek's SAN-aware match returns T,
    # the destination is often a legitimate publicly-issued service, so we
    # apply a penalty. BUT free CAs (Let's Encrypt, ZeroSSL) are trivial to
    # obtain and extremely common in modern C2 — CobaltStrike and Sliver
    # over Let's Encrypt is a dominant real-world pattern. A valid cert must
    # therefore NOT be able to single-handedly suppress an otherwise strong
    # behavioural beacon.
    #
    # Two protections:
    #  1. The penalty is REDUCED (not full) when the flow is resumption-
    #     pinned or tight-jittered — those are strong C2-defining behaviours
    #     that a cheap cert should not override.
    #  2. The penalty never drops a strong-behaviour beacon below the
    #     alert threshold on its own; it can only reduce ranking confidence.
    if ( st$sni_matches_cert == "T" && st$cert_validation == "ok" )
        {
        local strong_behaviour = is_pinned || is_tight;
        local applied_penalty = strong_behaviour ?
                                valid_cert_match_penalty_strong_beacon :
                                valid_cert_match_penalty;
        conf -= applied_penalty;
        add indicators["valid_cert_match"];
        }

    # ---- Pure-download suppression ----
    # PCR < -0.95 means more than 97% of bytes flowed server→client
    # (downloads, video, file fetches). Even RATs upload command
    # results, so a near-pure-download flow is very rarely C2.
    local flow_pcr = pcr(st$total_orig_bytes, st$total_resp_bytes);
    if ( flow_pcr < max_download_pcr )
        {
        conf -= pure_download_penalty;
        add indicators["pure_download_flow"];
        }

    # ---- Bulk-payload suppression (C2 check-in vs bulk transfer) ----
    # A genuine C2 check-in is a SHORT, tightly-bound exchange. Legitimate
    # no-SNI / self-signed flows that are periodic by coincidence — firmware
    # updates, update pollers, file drops, telemetry blobs — instead show a
    # bulk sizing profile: large, sustained response payloads. If the median
    # response payload across the flow is large, this is a transfer shape,
    # not a beacon check-in. We penalise it rather than hard-drop, so a
    # strongly-pinned/tight beacon can still surface; and we optionally skip
    # the penalty when the cert is already suspect/self-signed (a big-payload
    # self-signed periodic flow is genuinely more interesting).
    local med_resp_payload = median_count(st$resp_size_window);
    if ( med_resp_payload > beacon_max_checkin_payload )
        {
        local has_suspect_cert =
            has_suspect_issuer(st$cert_issuer) ||
            ( st$cert_validation != "" && st$cert_validation != "ok" &&
              st$cert_validation != "-" &&
              ( "self signed" in st$cert_validation ||
                "expired" in st$cert_validation ||
                "signature failure" in st$cert_validation ) );

        if ( ! ( beacon_bulk_penalty_skip_if_suspect_cert && has_suspect_cert ) )
            {
            conf -= beacon_bulk_payload_penalty;
            add indicators["bulk_payload_shape"];
            }
        }

    # Network-wide fingerprint rarity (rare client fingerprint to raw-IP
    # target). Uses the PRIMARY fingerprint (JA4 when present, else JA3) so
    # GREASE/order noise doesn't make browsers look rare. A browser-SHAPE JA4
    # is never treated as rare here even if its exact hash is uncommon.
    local fp = primary_fp(st$ja3, st$ja4);
    local fp_pop = fp_client_count(fp);
    local fp_is_browser = ja4_is_browser_shape(st$ja4);
    if ( fp != "" && fp_pop > 0 && fp_pop <= 3 && ! fp_is_browser &&
         (st$sni == "" || st$sni == "(empty)") )
        {
        conf += 0.10;
        add indicators["rare_fingerprint_to_raw_ip"];
        }

    # ---- Common-fingerprint penalty ----
    # When the primary fingerprint is shared by many distinct clients in the
    # network, OR its JA4 prefix is a browser shape, the originator is almost
    # certainly running a stock browser, mail client, or OS update agent. If
    # the destination is also moderately-popular (most of the way to
    # popular_dest_threshold), we are very probably looking at legitimate
    # traffic. Apply a confidence penalty. NOTE: this only lowers confidence
    # on an already-marginal flow; it never overrides a strong behavioural
    # beacon — malware can wear a common/browser fingerprint (injection,
    # common backend), so timing/shape detection is unaffected.
    if ( fp_pop >= common_ja3_client_floor || fp_is_browser )
        {
        local dest_pop_n = (k$dest_id in dest_client_count) ?
                           |dest_client_count[k$dest_id]| : 0;
        if ( dest_pop_n + 0.0 >= popular_dest_threshold * 0.5 )
            {
            conf -= common_ja3_popularity_penalty;
            add indicators["common_fingerprint_to_popular_dest"];
            }
        }

    # Client population context — useful for analyst triage even when
    # not affecting confidence. By definition any flow that reaches here
    # has fewer than popular_dest_threshold clients (else the destination
    # would have been marked popular and triage_skip would have fired),
    # but we tag the actual count so analysts can see "this destination
    # is contacted by 1 client, ever" — a strong qualitative signal.
    if ( k$dest_id in dest_client_count )
        {
        local n_clients = |dest_client_count[k$dest_id]|;
        if ( n_clients == 1 )
            add indicators["single_client_destination"];
        else if ( n_clients <= popular_dest_threshold )
            add indicators[fmt("rare_destination_%d_clients", n_clients)];
        }

    # ---- Fan-out prevalence gate (new C2 is 1:1) ----
    # A destination contacted by many internal hosts is a shared service, not
    # a single-host C2. Hard-drop past the fan-out cutoff; otherwise scale
    # confidence down as the client count rises. A 1:1 beacon is untouched.
    local fo_n = dest_client_n(k$dest_id);
    if ( fo_n >= fanout_hard_drop )
        return;
    local fo_pen = fanout_penalty(k$dest_id);
    if ( fo_pen > 0.0 )
        {
        conf -= fo_pen;
        add indicators[fmt("fanout_%d_clients", fo_n)];
        }

    # Tasking / exfil bursts.
    if ( tasks >= 2 ) { conf += 0.05; add indicators["server_payload_bursts"]; }
    if ( exfil >= 2 ) { conf += 0.10; add indicators["client_upload_bursts"]; }

    # ---- Emerging first-contact corroboration ----
    # If we marked this flow's first contact as C2-shaped (suspect cert /
    # no-SNI Go stack to a rare dest) and it has now confirmed as a genuine
    # beacon, add a small corroborating bonus. This rewards witnessing the
    # staging phase without ever having alerted on it standalone.
    if ( st$emerging_shape )
        {
        conf += emerging_shape_bonus;
        add indicators["emerging_shape_confirmed"];
        }

    # ---- Threat-intel corroboration ----
    # If the destination (IP or SNI) matches an operator Intel-framework hit,
    # strengthen the (already behaviourally-confirmed) beacon. Intel alone
    # never fires — this only escalates a real detection.
    if ( intel_corroboration_enabled )
        {
        local intel_desc = "";
        local last_dest = st?$last_resp_h ? st$last_resp_h : k$orig;
        intel_desc = intel_hit_for_dest(last_dest);
        if ( intel_desc == "" && st$sni != "" && st$sni != "(empty)" )
            intel_desc = intel_hit_for_domain(st$sni);
        if ( intel_desc != "" )
            {
            conf += intel_corroboration_bonus;
            add indicators[fmt("intel_hit:%s", intel_desc)];
            }
        }

    # ---- Host-correlation escalation (conservative) ----
    # These bonuses apply ONLY to a flow that is already independently
    # suspicious (>= host_escalation_floor). They lift a borderline C2 over
    # the line; they never manufacture an alert from a benign flow.
    if ( conf >= host_escalation_floor )
        {
        # Fingerprint pivot: this flow reuses a TLS fingerprint previously
        # seen on a confirmed C2 (e.g. a loader -> Cobalt Strike handoff that
        # reuses the same TLS stack). We do not claim the fingerprint is
        # malicious — only that it co-occurred with confirmed C2 and is rare
        # enough to be worth tracking. Requires the flow to already look
        # suspicious, so a benign shared-stack collision cannot trigger it.
        if ( is_tracked_c2_fingerprint(st$ja3, st$ja4, k$orig) )
            {
            conf += fingerprint_pivot_bonus;
            add indicators["rare_fingerprint_pivot"];
            }

        # Host compromise state: this host already produced a high-confidence
        # C2 alert. A further suspicious channel from it is very likely part
        # of the same intrusion (multi-C2 / staging / exfil).
        if ( is_host_compromised(k$orig) )
            {
            conf += host_compromise_bonus;
            add indicators["compromised_host_activity"];
            }

        # Stage transition: this host received a payload/tasking DOWNLOAD
        # burst inside a confirmed C2 very recently (payload_staged_window),
        # and now THIS channel has independently confirmed as C2. That
        # ordered sequence — payload pulled, then a new C2 stands up — is the
        # loader/next-stage transition (e.g. -> Sliver). The burst never
        # alerted on its own; it only strengthens a channel the behaviour has
        # already confirmed. We also require this not to be the very same
        # flow that carried the burst (that is just a payload update within
        # one C2, already annotated via payloads=N).
        if ( is_payload_staged(k$orig) && st$payload_count == 0 )
            {
            conf += payload_stage_transition_bonus;
            add indicators["stage_transition"];
            }
        }

    if ( conf < alert_confidence )
        return;

    if ( st$via_proxy )
        add indicators["via_proxy"];

    # ---- Beacon-exfil / bulk-transfer escalation ----
    # The flow is a confirmed beacon. If it has ALSO moved a large,
    # one-directional volume of data, that is a materially worse event
    # (exfiltration, or payload/tooling staging) than the beacon alone.
    # We check the lifetime byte totals (not the capped window) and the
    # PCR skew. This runs only inside a confirmed beacon, so bulk transfer
    # to benign destinations never reaches it.
    local tot_o    = st$total_orig_bytes;
    local tot_r    = st$total_resp_bytes;
    local dominant = tot_o > tot_r ? tot_o : tot_r;
    local is_upload = tot_o > tot_r;
    # flow_pcr was already computed earlier in this function (pure-download
    # suppression, above) from the same totals — reuse it rather than
    # redeclaring, which Zeek rejects as a duplicate local in one scope.
    local pcr_abs_skew = flow_pcr < 0 ? -flow_pcr : flow_pcr;

    if ( dominant >= exfil_min_bytes && pcr_abs_skew >= exfil_min_pcr_skew )
        {
        if ( exfil_separate_alert )
            {
            local ex_conf = exfil_base_confidence +
                            (is_upload ? exfil_upload_bonus : 0.0);
            if ( ex_conf > 1.0 ) ex_conf = 1.0;

            local ex_ind: set[string] = copy(indicators);
            add ex_ind[is_upload ? "bulk_upload_exfil" : "bulk_download_payload"];
            add ex_ind["beacon_confirmed_channel"];

            local dir_s = is_upload ? "upload/exfil" : "download/payload";
            local ex_details = fmt(
                "%sbeacon-exfil dir=%s orig=%d resp=%d pcr=%.2f int=%.1fs resump=%.0f%%",
                st$via_proxy ? "[via-proxy] " : "",
                dir_s, tot_o, tot_r, flow_pcr, med, res_ratio * 100.0);

            local ex_uid = "";
            for ( xu in st$uids ) { ex_uid = xu; break; }
            local ex_resp_h = st?$last_resp_h ? st$last_resp_h : k$orig;
            emit(SSL_BEACON_EXFIL, ex_conf, k$orig, ex_resp_h, resp_p, st,
                 ex_details, ex_ind, ex_uid, INNER_UNKNOWN);
            }
        else
            {
            add indicators[is_upload ? "bulk_upload_exfil" :
                                       "bulk_download_payload"];
            }
        }

    local hb_size = mode_count(st$resp_size_window);

    # ---- Exfil escalation ladder (SSL_C2_EXFIL_ESCALATION) ----
    # Layered on top of SSL_BEACON_EXFIL. Tracks CUMULATIVE UPLOAD on this
    # confirmed C2 and re-fires at escalating volume milestones (decade rule),
    # plus a slow-drain time re-fire while actively exfiltrating. Upload-only.
    # Runs only here — inside a confirmed beacon — so a benign large upload is
    # never subject to it.
    if ( exfil_ladder_enabled && is_upload &&
         flow_pcr >= exfil_min_pcr_skew )
        {
        local up_total = tot_o;
        local now_rung = exfil_rung_for(up_total);

        local fire_exfil = F;
        local reflag = F;

        # New volume rung crossed since we last alerted for this flow.
        if ( now_rung > st$exfil_rung )
            fire_exfil = T;

        # Slow-drain: already past the initial trip and still actively
        # exfiltrating, but no new rung — re-fire on the timer.
        else if ( now_rung >= 1 && exfil_reflag_interval > 0sec &&
                  st$exfil_last_alert != double_to_time(0) &&
                  network_time() - st$exfil_last_alert >= exfil_reflag_interval )
            { fire_exfil = T; reflag = T; }

        if ( fire_exfil )
            {
            local xf_ind: set[string] = copy(indicators);
            add xf_ind["c2_exfiltration"];
            add xf_ind["beacon_confirmed_channel"];
            if ( reflag )
                add xf_ind["exfil_ongoing"];

            local xf_details = fmt(
                "%sc2-exfil cum_upload=%s rung=%d milestone=%s pcr=%.2f dur=%.0fs%s",
                st$via_proxy ? "[via-proxy] " : "",
                human_bytes(up_total), now_rung,
                human_bytes(exfil_rung_threshold(now_rung)),
                flow_pcr, interval_to_double(st$last_seen - st$first_seen),
                reflag ? " (ongoing)" : "");

            local xf_uid = "";
            for ( xfu in st$uids ) { xf_uid = xfu; break; }
            local xf_resp_h = st?$last_resp_h ? st$last_resp_h : k$orig;

            emit(SSL_C2_EXFIL_ESCALATION, exfil_ladder_confidence,
                 k$orig, xf_resp_h, resp_p, st, xf_details, xf_ind,
                 xf_uid, INNER_UNKNOWN);

            st$exfil_rung       = now_rung;
            st$exfil_last_alert = network_time();
            }
        }

    # ---- Payload-staging: download burst inside a CONFIRMED C2 ----
    # We are past the alert gate, so this flow is a confirmed beacon. Look for
    # a DOWNLOAD (server->client) burst whose size is consistent with a
    # payload/tasking pull: either >= the absolute floor, or (for a tiny-
    # cadence beacon) many times larger than this channel's own heartbeat
    # baseline. Download direction only — uploads are exfil, handled above.
    # This annotates evidence and sets a short host marker; it never changed
    # whether this beacon fired. The confirmed-C2 gate above is the FP safety
    # net: benign TLS updaters are never confirmed beacons, so never reach here.
    if ( payload_staging_enabled )
        {
        local base_hb = hb_size > 0 ? hb_size : median_count(st$resp_size_window);
        local burst_dl = 0;
        local wi = 0;
        local wn = |st$resp_size_window|;
        while ( wi < wn )
            {
            local sz = st$resp_size_window[wi];
            local is_abs = sz >= payload_min_download_bytes;
            local is_rel = base_hb > 0 &&
                           sz >= payload_relative_min_bytes &&
                           (sz + 0.0) >= (base_hb + 0.0) * payload_baseline_multiple;
            if ( ( is_abs || is_rel ) && sz > burst_dl )
                burst_dl = sz;
            ++wi;
            }

        if ( burst_dl > 0 )
            {
            st$payload_count += 1;
            if ( burst_dl > st$payload_max_dl )
                st$payload_max_dl = burst_dl;

            # Forensic per-burst detail (reporting only — no detection effect).
            # Dedup consecutive identical sizes (the same burst re-seen in the
            # rolling window on the next eval). Record size + approx seconds
            # into the channel, capped so a frequently-updated long-lived
            # beacon can't grow the list unbounded.
            if ( burst_dl != st$payload_last_size )
                {
                st$payload_total_dl += burst_dl;
                local secs_in = interval_to_double(network_time() - st$first_seen);
                if ( |st$payload_bursts| < payload_burst_detail_cap )
                    st$payload_bursts += fmt("%s@%.0fs",
                                             human_bytes(burst_dl), secs_in);
                st$payload_last_size = burst_dl;
                }

            # Evidence + a modest confidence nudge on THIS C2 (it already
            # fired; this just strengthens/annotates it).
            if ( burst_dl >= payload_min_download_bytes )
                conf += payload_staged_bonus;
            else
                conf += payload_staged_bonus_weak;
            add indicators["payload_download_burst"];

            # Short-lived host marker for stage-transition corroboration of a
            # NEW channel that confirms shortly after.
            mark_payload_staged(k$orig);
            }
        }

    local det_cat = is_pinned ? SSL_RESUMPTION_PINNED_BEACON : SSL_PERIODIC_BEACON;

    # Build the forensic payload-burst detail: each recorded burst as
    # "<size>@<secs-in>", plus a rollup for any beyond the cap.
    local payload_detail = "";
    if ( st$payload_count > 0 )
        {
        local blist = "";
        local bi = 0;
        while ( bi < |st$payload_bursts| )
            {
            blist = blist == "" ? st$payload_bursts[bi] :
                                  fmt("%s,%s", blist, st$payload_bursts[bi]);
            ++bi;
            }
        payload_detail = fmt(" payloads=%d payload_bursts=[%s]",
                             st$payload_count, blist);
        # If more distinct bursts occurred than we listed, roll them up.
        if ( st$payload_count > |st$payload_bursts| )
            payload_detail = fmt("%s (+%d more, total=%s)",
                                 payload_detail,
                                 st$payload_count - |st$payload_bursts|,
                                 human_bytes(st$payload_total_dl));
        }

    local details = fmt(
        "%scnt=%d hb_sz=%d pdens=%.0f%% tasks=%d exfil=%d%s jit=%.0f%% int=%.1fs resump=%.0f%% sleeps=%d",
        st$via_proxy ? "[via-proxy] " : "",
        st$total_seen, hb_size,
        peak_density(st$resp_size_window) * 100.0,
        tasks, exfil, payload_detail,
        jitter * 100.0, med, res_ratio * 100.0, sleep_count);

    local rep_uid = "";
    for ( u in st$uids ) { rep_uid = u; break; }

    local resp_h = st?$last_resp_h ? st$last_resp_h : k$orig;

    # Escalation is expressed as an INDICATOR, not by replacing the category.
    # The category must always name the actual C2 behaviour we detected
    # (periodic beacon, resumption-pinned beacon, tunnel, reverse-flow RAT)
    # so the detection type is unambiguous. Host-correlation escalation
    # (already-compromised host, or a rare-fingerprint pivot) is added as a
    # supporting indicator on top of that category.
    if ( "compromised_host_activity" in indicators ||
         "rare_fingerprint_pivot" in indicators )
        add indicators["host_c2_escalation"];

    emit(det_cat, conf, k$orig, resp_h, resp_p, st, details, indicators,
         rep_uid, INNER_UNKNOWN);

    # Arm host-compromise correlation on a high-confidence detection.
    if ( conf >= host_compromise_entry_confidence )
        mark_host_compromised(k$orig, st$ja3, st$ja4);

    st$last_alert     = network_time();
    st$last_alert_cat = det_cat;
    flow_state[k]     = st;
    }

# ====================================================================
# SECTION 5 — LONG-CONNECTION / TUNNEL EVALUATION
# ====================================================================
#
# Examines a single long-lived connection for covert channel properties.
# Hooked from LongConnection::long_conn_found and connection_state_remove.

function evaluate_tunnel(c: connection)
    {
    if ( triage_skip(c) )       return;
    if ( ! c?$ssl )             return;
    if ( ! c$ssl?$established || ! c$ssl$established ) return;

    local sni = "(empty)";
    if ( c$ssl?$server_name && c$ssl$server_name != "" )
        sni = c$ssl$server_name;

    local via_proxy = is_proxy_destination(c$id$resp_h);

    local dur = c?$duration ? interval_to_double(c$duration) : 0.0;
    if ( dur < interval_to_double(long_conn_duration) ) return;

    local orig_b = c?$orig && c$orig?$size ? c$orig$size : 0;
    local resp_b = c?$resp && c$resp?$size ? c$resp$size : 0;
    local orig_p = c?$orig && c$orig?$num_pkts ? c$orig$num_pkts : 0;

    if ( orig_p < tunnel_min_orig_pkts ) return;

    local ppm = (orig_p + 0.0) / dur * 60.0;

    local total = orig_b + resp_b;
    local bps   = (total + 0.0) / dur;
    local avg_pkt = (orig_b + 0.0) / (orig_p + 0.0);

    # ---- Bidirectionality gate ----
    # Require the server actually responded — same as beacon detector.
    # Accept ja3s/ja4s OR a meaningful response-byte count (the ServerHello
    # may have been missed on a busy sensor / resumed sessions carry no
    # fresh fingerprint). Without the byte fallback a real C2 tunnel whose
    # handshake we missed would be a false negative.
    local ja3s_val = (c?$ssl && c$ssl?$ja3s) ? c$ssl$ja3s : "";
    local ja4s_val = (c?$ssl && c$ssl?$ja4s) ? c$ssl$ja4s : "";
    local server_responded = (ja3s_val != "" && ja3s_val != "-") ||
                             (ja4s_val != "" && ja4s_val != "-") ||
                             (resp_b >= bidirectional_min_resp_bytes);
    if ( require_bidirectional && ! server_responded )
        return;

    local indicators: set[string] = set();

    # Base confidence is LOW — must earn the alert through genuine signals.
    # low_bps + tiny_avg_pkt alone are NOT sufficient: push notification
    # sockets, telemetry channels, and XMPP keepalives match both criteria.
    local conf = 0.30;

    if ( via_proxy )
        add indicators["via_proxy"];

    # ---- Throughput / framing character ----
    # PREVIOUSLY these were hard drops (return). That created false
    # negatives: an active operator doing screen-view or file-transfer over
    # the tunnel exceeds the bps/avg_pkt ceilings, and a slow persistent
    # channel falls below the ppm floor. We now KEEP the flow and simply
    # award (or withhold) the low-and-slow bonuses. High-throughput or
    # large-packet tunnels can still alert via cert/inner-proto/PCR signals.
    local low_and_slow = (bps <= tunnel_max_bps && avg_pkt <= tunnel_max_avg_pkt_size);

    if ( ppm < tunnel_min_ppm )
        # Very slow channel — not disqualifying (persistent C2 can be slow),
        # but tag it so analysts see the cadence.
        add indicators["very_slow_cadence"];

    # ---- Web-traffic suppression ----
    # h2/http/1.1 ALPN means this is a web-protocol keepalive — not a C2
    # tunnel. Android FCM, Edge telemetry and Google push all show h2.
    local alpn_str = (c?$ssl && c$ssl?$next_protocol) ? c$ssl$next_protocol : "";
    local flow_seen_web = is_web_alpn(alpn_str);
    if ( ! flow_seen_web && c?$ssl && c$ssl?$ja4 )
        {
        local ja4_alpn = ja4_alpn_field(c$ssl$ja4);
        if ( ja4_alpn == "h2" || ja4_alpn == "h1" || ja4_alpn == "h0" )
            flow_seen_web = T;
        }
    if ( flow_seen_web )
        {
        conf -= web_alpn_penalty;
        add indicators["web_alpn_observed"];
        }

    # ---- Certificate-based signals (skipped for intercepted flows) ----
    # For a confirmed proxy-intercepted flow the cert/validation belong to
    # the proxy, so cert signals are meaningless. Detect interception on
    # this connection and, if confirmed, skip cert signals and add a small
    # behavioural credit to compensate (same rationale as the beacon path).
    local tun_intercepted = F;
    if ( via_proxy && proxy_mode == PROXY_INTERCEPTING && c?$ssl )
        {
        local tun_iss = (c$ssl?$issuer) ? c$ssl$issuer : "";
        local tun_j3s = (c$ssl?$ja3s) ? c$ssl$ja3s : "";
        local tun_j4s = (c$ssl?$ja4s) ? c$ssl$ja4s : "";
        if ( is_proxy_ca_issuer(tun_iss) ||
             is_proxy_server_fp(tun_j3s, tun_j4s) )
            tun_intercepted = T;
        if ( ! tun_intercepted && c$ssl?$cert_chain_fps &&
             |c$ssl$cert_chain_fps| > 0 )
            {
            for ( tfpi in c$ssl$cert_chain_fps )
                if ( is_proxy_ca_fingerprint(c$ssl$cert_chain_fps[tfpi]) )
                    { tun_intercepted = T; break; }
            }
        }

    local sni_match = (c?$ssl && c$ssl?$sni_matches_cert) ? c$ssl$sni_matches_cert : F;
    local issuer = (c?$ssl && c$ssl?$issuer) ? c$ssl$issuer : "";

    if ( tun_intercepted )
        {
        conf += proxy_intercept_behaviour_credit;
        add indicators["proxy_intercepted"];
        }
    else
        {
        # ---- Valid cert + matching SNI penalty ----
        if ( sni_match && c?$ssl && c$ssl?$validation_status &&
             c$ssl$validation_status == "ok" )
            {
            conf -= valid_cert_match_penalty;
            add indicators["valid_cert_match"];
            }

        # ---- Genuine suspicion signals ----
        if ( has_suspect_issuer(issuer) )
            { conf += 0.25; add indicators["suspect_issuer"]; }

        if ( c?$ssl && c$ssl?$validation_status &&
             ("self signed" in c$ssl$validation_status ||
              "expired"     in c$ssl$validation_status) )
            { conf += 0.15; add indicators["bad_cert_validation"]; }

        if ( ! sni_match && sni != "(empty)" && sni != "" &&
             c?$ssl && c$ssl?$issuer && c$ssl$issuer != "" )
            { conf += cert_sni_mismatch_bonus; add indicators["cert_sni_mismatch"]; }
        }

    # no_sni applies regardless of interception (SNI is the client's).
    if ( sni == "(empty)" || sni == "" )
        { conf += 0.10; add indicators["no_sni"]; }

    # ---- TLS 1.3 + no ALPN = Go TLS stack (Sliver, Cobalt Strike-Go, etc.) ----
    # A persistent long-lived TLS 1.3 channel with no ALPN is characteristic
    # of Go-based C2 frameworks opening one connection and keeping it alive.
    # Applies to tunnel/long-conn path same as beacon path.
    local tls_ver = (c?$ssl && c$ssl?$version) ? c$ssl$version : "";
    local alpn_for_tls13 = (c?$ssl && c$ssl?$ja4) ? ja4_alpn_field(c$ssl$ja4) : "";
    if ( alpn_for_tls13 == "00" &&
         (tls_ver == "TLSv13" || tls_ver == "TLS13") )
        { conf += 0.15; add indicators["tls13_no_alpn"]; }

    # Low BPS and tiny packets are weak supporting signals — not sufficient alone.
    if ( bps < 200.0 )
        { conf += 0.15; add indicators["very_low_bps"]; }

    if ( avg_pkt < 200.0 )
        { conf += 0.10; add indicators["tiny_avg_pkt"]; }

    # ---- High-throughput active session (FN defence) ----
    # Previously bps > tunnel_max_bps was a hard drop. But a hands-on-keyboard
    # operator doing screen-view, file staging, or ransomware deployment over
    # the tunnel produces high throughput and large packets. Rather than
    # discard, we tag it — combined with a suspicious cert / inner-proto /
    # PCR signal this still alerts. This closes the "active operator" gap.
    if ( ! low_and_slow )
        add indicators["high_throughput_session"];

    # ---- SPL cadence analysis ----
    local spt_jitter = -1.0;
    local spt_med    = 0.0;
    if ( c?$spl && c$spl?$orig_spt && |c$spl$orig_spt| >= 4 )
        {
        local spt: vector of double = vector();
        local i = 1;
        while ( i < |c$spl$orig_spt| ) { spt += c$spl$orig_spt[i]; ++i; }
        if ( |spt| >= 3 )
            {
            spt_med = median(spt);
            if ( spt_med > 0.0 )
                {
                spt_jitter = mad(spt, spt_med) / spt_med;
                # Tightened to 20% jitter (was 30%) to better exclude cloud
                # push channels whose retransmit intervals are somewhat regular.
                if ( spt_jitter < 0.20 && spt_med > 1.0 )
                    { conf += 0.20; add indicators["uniform_keepalive_cadence"]; }
                }
            }
        }

    # Upload-dominant PCR: C2 commands go out, results come back.
    # Push/telemetry is download-heavy or balanced.
    local p = pcr(orig_b, resp_b);
    if ( p > 0.30 && orig_b > resp_b * 2 )
        { conf += 0.15; add indicators["upload_dominant_pcr"]; }

    # ---- Inner protocol assessment ----
    local ipr = assess_inner_protocol(c);
    local inner = ipr$proto;
    for ( ind in ipr$indicators ) add indicators[ind];

    if ( inner == INNER_FIXED_FRAME || inner == INNER_SMALL_UNIFORM )
        conf += 0.10;
    if ( inner == INNER_NONSTANDARD_ALPN )
        conf += 0.15;

    # ---- Interactive reverse-shell shapes (SPL-independent) ----
    # These catch a hands-on-keyboard shell that the SPL silence-gap logic
    # in evaluate_reverse_flow would miss (a busy operator types steadily,
    # so there is no long idle gap). They rely only on duration + byte
    # asymmetry, so they work without the SPL analyzer.

    # Shape 1 — long-lived idle keep-alive. The socket is held open for
    # hours but almost nothing moves: an interactive shell waiting for the
    # operator. Very low throughput over a very long duration.
    if ( dur >= interval_to_double(shell_idle_min_duration) &&
         bps <= shell_idle_max_bps )
        {
        conf += 0.20;
        add indicators["long_lived_idle_shell"];
        }

    # Shape 2 — reverse asymmetry. Normal web is small-request / big-response
    # (negative PCR). An interactive reverse-shell inverts this: the client
    # streams command output (steady outbound) while the server sends only
    # the short typed command strings (tiny inbound). We require a sustained
    # connection with meaningful outbound, tiny absolute inbound, and
    # client-out >= server-in.
    #
    # BUT an immediate, sustained, HIGH-RATE upload with tiny inbound is not a
    # shell — it is a media/WebRTC/backup upload (the dominant live false
    # positive: MSEdge WebRTC health-app uploads to cloud). A real interactive
    # shell is LOW-AND-SLOW (keystroke-paced), so its throughput is low. We
    # therefore additionally require the flow to be low-rate (bps within the
    # idle-shell envelope) — a fast upload stream is rejected here.
    if ( dur >= interval_to_double(shell_asym_min_duration) &&
         resp_b <= shell_asym_max_inbound_bytes &&
         orig_b >= shell_asym_min_outbound_bytes &&
         orig_b >= resp_b &&
         ( ! reject_immediate_upload ||
           orig_b < immediate_upload_min_bytes ||
           bps <= shell_idle_max_bps ) )
        {
        conf += 0.25;
        add indicators["reverse_asymmetry_shell"];
        }

    if ( conf < alert_confidence ) return;

    # ---- Fan-out prevalence gate ----
    # A long-lived channel to a destination contacted by many internal hosts
    # is a shared service (cloud/CDN/telemetry), not single-host C2. This is
    # the dominant live false-positive class for tunnels.
    local t_dest = dest_identity_for(sni, c$id$resp_h, via_proxy);
    if ( dest_client_n(t_dest) >= fanout_hard_drop )
        return;
    local t_fo = fanout_penalty(t_dest);
    if ( t_fo > 0.0 )
        {
        conf -= t_fo;
        add indicators[fmt("fanout_%d_clients", dest_client_n(t_dest))];
        if ( conf < alert_confidence ) return;
        }

    local det_cat = (inner == INNER_FIXED_FRAME || inner == INNER_SMALL_UNIFORM)
                ? SSL_TUNNEL_INSIDE_TLS
                : SSL_TUNNEL_KEEPALIVE;

    # An interactive-shell shape is semantically a server-driven RAT, not a
    # passive keep-alive tunnel — report it as such so the SOC sees the
    # correct behaviour class.
    if ( "reverse_asymmetry_shell" in indicators ||
         "long_lived_idle_shell" in indicators )
        det_cat = SSL_REVERSE_FLOW_RAT;

    local details = fmt(
        "%spkts=%d avg_pkt=%.0f bps=%.0f dur=%.1fmin spt_jit=%s pcr=%.2f issuer=%s alpn=%s inner=%s",
        via_proxy ? "[via-proxy] " : "",
        orig_p, avg_pkt, bps, dur / 60.0,
        spt_jitter < 0.0 ? "?" : fmt("%.0f%%", spt_jitter * 100.0),
        p,
        has_suspect_issuer(issuer) ? "suspect" : "ok",
        alpn_str == "" ? "-" : alpn_str,
        det_cat == SSL_TUNNEL_INSIDE_TLS ? "fixed_frame" : "keepalive");

    emit_from_conn(det_cat, conf, c, sni, via_proxy, details, indicators, inner);
    }

# ====================================================================
# SECTION 7 — REVERSE-FLOW / RAT DETECTION
# ====================================================================
#
# Pattern: client is idle, server sends a small payload (command), client
# responds with a larger payload (result/exfil). Detected by:
#   * Positive PCR (client uploads more than server sends)
#   * Large mid-flow silence gap in originator timing (client was idle)
#   * Subsequent upload burst after the silence
#
# IMPORTANT: upload-dominant PCR and a silence gap ALONE are not
# sufficient. Legitimate healthcare SaaS, log-upload agents (Azure MMA,
# Splunk UF, etc.) and form-submission apps all exhibit this shape.
# We require additional suspicion signals — cert anomalies, dest rarity,
# or prior beacon evidence — before reaching alert threshold.

function evaluate_reverse_flow(c: connection)
    {
    if ( triage_skip(c) )       return;
    if ( ! c?$ssl )             return;
    if ( ! c$ssl?$established || ! c$ssl$established ) return;
    if ( ! c?$duration )        return;

    local dur = interval_to_double(c$duration);
    if ( dur < 30.0 || dur > interval_to_double(long_conn_duration) )
        return;

    local orig_b = c?$orig && c$orig?$size ? c$orig$size : 0;
    local resp_b = c?$resp && c$resp?$size ? c$resp$size : 0;
    if ( orig_b + resp_b < 500 ) return;

    local p = pcr(orig_b, resp_b);
    if ( p < reverse_flow_pcr_threshold ) return;

    # Bidirectionality — server must have responded.
    local ja3s_val = (c?$ssl && c$ssl?$ja3s) ? c$ssl$ja3s : "";
    local ja4s_val = (c?$ssl && c$ssl?$ja4s) ? c$ssl$ja4s : "";
    if ( require_bidirectional &&
         (ja3s_val == "" || ja3s_val == "-") &&
         (ja4s_val == "" || ja4s_val == "-") )
        return;

    # Require SPL inter-packet timing for the silence-gap detection.
    if ( ! c?$spl || ! c$spl?$resp_spt || ! c$spl?$orig_spt )
        return;
    if ( |c$spl$orig_spt| < 4 || |c$spl$resp_spt| < 4 )
        return;

    # Find the maximum inter-packet gap in the originator's timeline.
    local max_gap = 0.0;
    local i = 1;
    while ( i < |c$spl$orig_spt| )
        {
        if ( c$spl$orig_spt[i] > max_gap )
            max_gap = c$spl$orig_spt[i];
        ++i;
        }
    if ( max_gap < interval_to_double(reverse_silent_gap) )
        return;

    local sni = "(empty)";
    if ( c$ssl?$server_name && c$ssl$server_name != "" )
        sni = c$ssl$server_name;
    local via_proxy = is_proxy_destination(c$id$resp_h);
    local dest_id   = dest_identity_for(sni, c$id$resp_h, via_proxy);

    local indicators: set[string] = set();
    add indicators["upload_dominant_pcr"];
    add indicators["mid_flow_silence_then_burst"];
    if ( via_proxy )
        add indicators["via_proxy"];

    local issuer = (c?$ssl && c$ssl?$issuer) ? c$ssl$issuer : "";

    # Base confidence is LOW — PCR + silence alone match too many
    # legitimate upload patterns (healthcare SaaS, log agents, form apps).
    local conf = 0.30;

    # ---- Web-traffic suppression ----
    local alpn_str = (c?$ssl && c$ssl?$next_protocol) ? c$ssl$next_protocol : "";
    local flow_seen_web = is_web_alpn(alpn_str);
    if ( ! flow_seen_web && c?$ssl && c$ssl?$ja4 )
        {
        local ja4_a = ja4_alpn_field(c$ssl$ja4);
        if ( ja4_a == "h2" || ja4_a == "h1" || ja4_a == "h0" )
            flow_seen_web = T;
        }
    if ( flow_seen_web )
        {
        conf -= web_alpn_penalty;
        add indicators["web_alpn_observed"];
        }

    # ---- Valid cert + matching SNI penalty ----
    local sni_match = (c?$ssl && c$ssl?$sni_matches_cert) ? c$ssl$sni_matches_cert : F;
    if ( sni_match && c?$ssl && c$ssl?$validation_status &&
         c$ssl$validation_status == "ok" )
        {
        conf -= valid_cert_match_penalty;
        add indicators["valid_cert_match"];
        }

    # ---- Inner-protocol: LIKELY_HTTPS means this is just a web upload ----
    local ipr = assess_inner_protocol(c);
    local inner = ipr$proto;
    for ( ind in ipr$indicators ) add indicators[ind];
    if ( inner == INNER_LIKELY_HTTPS )
        {
        conf -= 0.20;
        add indicators["inner_looks_like_https"];
        }

    # ---- Destination popularity penalty ----
    # When multiple clients upload to the same server, it is a shared
    # application (SaaS, monitoring agent). A real RAT operator has
    # exactly one or two victims uploading to their infrastructure.
    if ( dest_id in dest_client_count &&
         |dest_client_count[dest_id]| >= 3 )
        {
        conf -= 0.20;
        add indicators["popular_upload_dest"];
        }

    # ---- Genuine suspicion signals ----
    if ( has_suspect_issuer(issuer) )
        { conf += 0.25; add indicators["suspect_issuer"]; }

    if ( sni == "(empty)" || sni == "" )
        { conf += 0.10; add indicators["no_sni"]; }

    if ( c?$ssl && c$ssl?$validation_status &&
         ("self signed" in c$ssl$validation_status ||
          "expired"     in c$ssl$validation_status) )
        { conf += 0.15; add indicators["bad_cert_validation"]; }

    if ( ! sni_match && sni != "(empty)" && sni != "" &&
         c?$ssl && c$ssl?$issuer && c$ssl$issuer != "" )
        { conf += cert_sni_mismatch_bonus; add indicators["cert_sni_mismatch"]; }

    # ---- Cross-detector beacon-history bonus ----
    # If the beacon detector has already been tracking connections from
    # this originator to the same destination, the RAT pattern is
    # substantially more credible — it means repeated contact, not a
    # single upload event. Check flow_state for any entry with this
    # (orig_h, dest_id) pair regardless of JA3.
    local ja3_val = primary_fp(
        (c?$ssl && c$ssl?$ja3) ? c$ssl$ja3 : "",
        (c?$ssl && c$ssl?$ja4) ? c$ssl$ja4 : "");
    local fk: FlowKey = [$orig = c$id$orig_h, $dest_id = dest_id,
                          $ja3  = ja3_val];
    if ( fk in flow_state && flow_state[fk]$total_seen >= beacon_min_count )
        {
        conf += 0.20;
        add indicators["prior_beacon_history"];
        }

    # Upload very dominance and silence length are now weak supporting
    # signals rather than primary ones.
    if ( orig_b > resp_b * 4 ) { conf += 0.10; add indicators["extreme_upload_ratio"]; }
    if ( max_gap > 120.0 )     { conf += 0.05; add indicators["long_silence"]; }

    if ( conf < alert_confidence ) return;

    local details = fmt(
        "%spcr=%.2f orig=%d resp=%d silent_gap=%.0fs dur=%.0fs",
        via_proxy ? "[via-proxy] " : "",
        p, orig_b, resp_b, max_gap, dur);

    emit_from_conn(SSL_REVERSE_FLOW_RAT, conf, c, sni, via_proxy,
                   details, indicators, inner);
    }

# ====================================================================
# SECTION 8 — TRUSTED-PIVOT RARE-FINGERPRINT DETECTION
# ====================================================================
#
# Tracks, per (sni, ja3) pair, the set of clients that have used that
# fingerprint against that host. A fingerprint used by very few distinct
# clients is characteristic of bespoke tooling routing C2 through a
# legitimate front (Azure FD, Cloudflare Workers, Dropbox, etc.).

function note_pivot(c: connection)
    {
    if ( ! c?$ssl ) return;
    if ( ! c$ssl?$server_name || c$ssl$server_name == "" ) return;
    if ( ! c$ssl?$ja3 || c$ssl$ja3 == "" ) return;
    local sni = to_lower(c$ssl$server_name);
    if ( ! is_sni_trusted_pivot(sni) ) return;
    local pfp = primary_fp(c$ssl$ja3, c$ssl?$ja4 ? c$ssl$ja4 : "");
    local k: PivotKey = [$sni = sni, $ja3 = pfp];
    if ( k !in pivot_ja3_clients ) pivot_ja3_clients[k] = set();
    add pivot_ja3_clients[k][c$id$orig_h];
    }

function evaluate_pivot(c: connection)
    {
    if ( triage_skip(c) )    return;
    if ( ! c?$ssl )          return;
    if ( ! c$ssl?$established || ! c$ssl$established ) return;
    if ( ! c$ssl?$server_name || c$ssl$server_name == "" ) return;
    if ( ! c$ssl?$ja3 || c$ssl$ja3 == "" ) return;

    local sni = to_lower(c$ssl$server_name);
    if ( ! is_sni_trusted_pivot(sni) ) return;

    local via_proxy = is_proxy_destination(c$id$resp_h);
    local pfp = primary_fp(c$ssl$ja3, c$ssl?$ja4 ? c$ssl$ja4 : "");
    local k: FlowKey = [$orig    = c$id$orig_h,
                        $dest_id = dest_identity_for(sni, c$id$resp_h, via_proxy),
                        $ja3     = pfp];
    if ( k !in flow_state ) return;
    local st = flow_state[k];
    if ( st$total_seen < pivot_min_conns ) return;

    # STRONG behavioural gate: living-off-trusted-sites C2 must actually
    # BEACON or TUNNEL to the trusted domain. Ordinary cloud/API chatter to
    # azureedge/cloudfront/etc. — even from a client with a rare fingerprint
    # — is not C2 and must not fire. Requiring a genuine beacon/tunnel shape
    # (the same bar the beacon detector uses) removes that false-positive
    # class. This only ADDS a requirement, so it cannot increase FPs, and it
    # is what makes this detector reliable rather than "spoke to a CDN".
    if ( ! has_beacon_or_tunnel_shape(st) )
        return;

    if ( st$last_alert != double_to_time(0) &&
         network_time() - st$last_alert < alert_cooldown )
        return;

    local pk: PivotKey = [$sni = sni, $ja3 = pfp];
    if ( pk !in pivot_ja3_clients ) return;
    if ( |pivot_ja3_clients[pk]| > pivot_max_ja3_clients ) return;

    # Suppress when Zeek has confirmed cert chain and SNI both valid.
    # A valid CA-chain cert that matches the SNI on an azureedge/cloudfront
    # destination is an overwhelmingly legitimate CDN request. The JA3 rarity
    # in a small capture or from a rarely-used client is not meaningful in
    # that context — in a live 30k-host network this JA3 would be common.
    # Malicious pivot-abuse uses the CDN as a front: the cert belongs to the
    # CDN and the SNI matches it, but the real C2 content is hidden behind it.
    # This suppression means the pivot detector fires only when the cert is
    # NOT validly covering the SNI (e.g. domain-fronting with mismatched cert).
    if ( st$sni_matches_cert == "T" && st$cert_validation == "ok" )
        return;

    local indicators: set[string] = set();
    add indicators["rare_ja3_to_trusted_pivot"];
    if ( via_proxy ) add indicators["via_proxy"];
    if ( st$sni_matches_cert == "F" ) add indicators["cert_sni_mismatch"];

    local details = fmt("rare_ja3_clients=%d sni=%s conns=%d ja3=%s",
                        |pivot_ja3_clients[pk]|, sni,
                        st$total_seen, c$ssl$ja3);

    emit(SSL_TRUSTED_PIVOT_RARE_FP, 0.75,
         c$id$orig_h, c$id$resp_h, c$id$resp_p,
         st, details, indicators, c$uid, INNER_UNKNOWN);

    st$last_alert     = network_time();
    st$last_alert_cat = SSL_TRUSTED_PIVOT_RARE_FP;
    flow_state[k]     = st;
    }

# ====================================================================
# SECTION 9 — STATE MAINTENANCE
# ====================================================================

function update_flow_state(c: connection): FlowKey
    {
    local sni = "";
    if ( c?$ssl && c$ssl?$server_name )
        sni = c$ssl$server_name;
    local via_proxy = is_proxy_destination(c$id$resp_h);
    # Prefer SNI, then the plaintext CONNECT host (authoritative for
    # proxied HTTPS and resilient to Encrypted Client Hello), then IP.
    local chost = (c$uid in connect_host_by_uid) ?
                  connect_host_by_uid[c$uid] : "";
    local dest_id   = dest_identity_full(sni, chost, c$id$resp_h, via_proxy);
    # The FlowKey's fingerprint slot uses the PRIMARY fingerprint (JA4 when
    # present, else JA3) so a beacon groups stably across GREASE/order
    # variation. The individual ja3/ja4 are still stored separately on the
    # FlowState for reporting. (Field is named $ja3 for historical reasons;
    # it now carries the primary fp.)
    local cur_ja3 = (c?$ssl && c$ssl?$ja3) ? c$ssl$ja3 : "";
    local cur_ja4 = (c?$ssl && c$ssl?$ja4) ? c$ssl$ja4 : "";
    local ja3 = primary_fp(cur_ja3, cur_ja4);

    local k: FlowKey = [$orig = c$id$orig_h, $dest_id = dest_id, $ja3 = ja3];

    # Note this client/dest pair so popularity is recomputed even when
    # ssl_established didn't fire (e.g. SSL aborted late in the handshake
    # but enough bytes flowed to cross min_track_bytes). The check at
    # the start of connection_state_remove handles the popular case for
    # *new* flows; this call ensures the counter keeps advancing.
    note_dest_client(dest_id, c$id$orig_h);

    # If the destination became popular as a result of this update,
    # evict_state_for_dest has already deleted any prior state. Drop
    # this update entirely — there is nothing left to track for this
    # destination.
    if ( is_dest_popular(dest_id) )
        return k;

    # Active abandonment of stale low-frequency flows.
    # If this flow has been tracked for longer than track_abandon_after
    # but never accumulated enough samples to look like a beacon, it's
    # legitimate browsing. Wipe it and start fresh — if it really IS a
    # very-slow beacon, the sparse_state path will catch it separately.
    if ( k in flow_state )
        {
        local existing = flow_state[k];
        if ( existing$total_seen < beacon_min_count &&
             c$start_time - existing$first_seen > track_abandon_after )
            {
            delete flow_state[k];
            }
        }

    if ( k !in flow_state )
        {
        local fresh: FlowState;
        fresh$first_seen = c$start_time;
        flow_state[k] = fresh;
        }

    local st = flow_state[k];

    # Always update the lightweight counters and last-seen.
    st$total_seen   += 1;
    st$last_seen     = c$start_time;
    st$last_resp_h   = c$id$resp_h;
    st$via_proxy     = via_proxy;

    if ( sni != "" && sni != "(empty)" )
        st$sni = sni;

    # ---- CONNECT-host correlation (proxied HTTPS) ----
    # If the client issued a plaintext CONNECT for this uid, record the
    # real destination host. Authoritative even when SNI is absent (ECH).
    if ( c$uid in connect_host_by_uid )
        st$connect_host = connect_host_by_uid[c$uid];

    # Capture TLS metadata on every connection — cheap, and useful even
    # during the grace period in case the flow does eventually beacon.
    # The rolling-window updates below are gated behind the grace check.
    if ( c?$ssl )
        {
        if ( c$ssl?$version ) st$tls_version = c$ssl$version;

        # ---- Interception detection (INTERCEPTING proxy mode) ----
        # Positively confirm the flow was inspected by OUR proxy CA so we
        # (a) do not treat the proxy's re-signed cert as attacker
        # self-signing, and (b) know cert signals are unreliable for this
        # flow. Matching is by issuer DN, cert fingerprint, or the proxy's
        # consistent server fingerprint. Sticky once set.
        if ( via_proxy && proxy_mode == PROXY_INTERCEPTING )
            {
            local iss = (c$ssl?$issuer) ? c$ssl$issuer : "";
            local j3s = (c$ssl?$ja3s) ? c$ssl$ja3s : "";
            local j4s = (c$ssl?$ja4s) ? c$ssl$ja4s : "";
            local matched_intercept = is_proxy_ca_issuer(iss) ||
                                      is_proxy_server_fp(j3s, j4s);
            # Cert-fingerprint match is optional: the cert_chain_fps field
            # is only present when a cert-fingerprint policy is loaded. Guard
            # it so the module works with or without that policy.
            if ( ! matched_intercept && c$ssl?$cert_chain_fps &&
                 |c$ssl$cert_chain_fps| > 0 )
                {
                for ( fpi in c$ssl$cert_chain_fps )
                    if ( is_proxy_ca_fingerprint(c$ssl$cert_chain_fps[fpi]) )
                        { matched_intercept = T; break; }
                }
            if ( matched_intercept )
                st$proxy_intercepted = T;
            }

        # ---- Certificate validation capture (mode-aware) ----
        # For a CONFIRMED-intercepted flow the cert is the proxy's re-signed
        # cert — its issuer/validation/SNI-match say nothing about the real
        # upstream, so we skip cert capture and rely on behaviour.
        #
        # Note we key this on the CONFIRMED flag (st$proxy_intercepted),
        # not merely on via_proxy. A proxied flow in intercepting mode that
        # does NOT match our CA is notable: either interception was bypassed
        # (some malware pins certs / uses non-CONNECT tunneling) or the proxy
        # passed the real cert through. In that case we DO keep the cert
        # signals — they may be the real upstream's.
        local skip_cert_signals = st$proxy_intercepted;
        if ( ! skip_cert_signals )
            {
            if ( c$ssl?$validation_status &&
                 c$ssl$validation_status != "-" &&
                 c$ssl$validation_status != "(empty)" )
                st$cert_validation = c$ssl$validation_status;
            if ( c$ssl?$issuer && c$ssl$issuer != "-" )
                st$cert_issuer = c$ssl$issuer;
            if ( c$ssl?$subject && c$ssl$subject != "-" )
                st$cert_subject = c$ssl$subject;
            }

        if ( c$ssl?$ja3 ) st$ja3  = c$ssl$ja3;
        if ( c$ssl?$ja4 ) st$ja4  = c$ssl$ja4;

        # ---- Server-fingerprint capture (mode-aware) ----
        # Keep ja3s/ja4s as a real per-server identity UNLESS the flow is
        # confirmed intercepted (then they are the proxy's). Non-intercepting
        # proxies and direct connections both yield real server fingerprints.
        local keep_server_fp = ! st$proxy_intercepted;
        if ( keep_server_fp )
            {
            if ( c$ssl?$ja3s && c$ssl$ja3s != "" && c$ssl$ja3s != "-" )
                { st$ja3s = c$ssl$ja3s; st$server_seen = T; }
            if ( c$ssl?$ja4s && c$ssl$ja4s != "" && c$ssl$ja4s != "-" )
                { st$ja4s = c$ssl$ja4s; st$server_seen = T; }
            }

        # Zeek's built-in SAN-aware match. Once set "F" (mismatch), keep
        # it — the cert is the cert; subsequent resumed sessions don't
        # change that. Once set "T" (match), keep that too.
        # Skip entirely for confirmed-intercepted flows (proxy cert).
        if ( ! skip_cert_signals && c$ssl?$sni_matches_cert )
            {
            if ( c$ssl$sni_matches_cert )
                {
                # Only upgrade to T if not already F (mismatch wins).
                if ( st$sni_matches_cert != "F" )
                    st$sni_matches_cert = "T";
                }
            else
                st$sni_matches_cert = "F";
            }
        if ( c$ssl?$next_protocol && c$ssl$next_protocol != "-" &&
             c$ssl$next_protocol != "" )
            {
            st$alpn = c$ssl$next_protocol;

            # Sticky web-ALPN flag — once set, never reset.
            # Resumed sessions don't carry ALPN, so we have to remember.
            if ( is_web_alpn(c$ssl$next_protocol) )
                {
                st$seen_web_alpn = T;

                # This client+cipher set has demonstrably done HTTPS.
                # Bump the network-wide counter so other flows from
                # the same JA4 cipher set are recognised as browser-like.
                if ( c$ssl?$ja4 )
                    note_browser_ja4(c$ssl$ja4);
                }
            }

        # The JA4 ALPN field embedded in the JA4 string itself is more
        # reliable than the negotiated next_protocol for resumed flows.
        # If the JA4's first segment encodes an HTTP ALPN, the client
        # offered it — strong "this is a browser" signal even without
        # observing the server reply.
        if ( c$ssl?$ja4 )
            {
            local ja4_alpn = ja4_alpn_field(c$ssl$ja4);
            # JA4 ALPN encoding: "h2", "h1" (= http/1.1), "h0" (= http/1.0)
            # "00" means client offered no ALPN — NOT a web indicator.
            if ( ja4_alpn == "h2" || ja4_alpn == "h1" || ja4_alpn == "h0" )
                {
                st$seen_web_alpn = T;
                note_browser_ja4(c$ssl$ja4);
                }
            }
        }

    # ---- Grace period ----
    # For the first flow_grace_count connections we do NOT populate the
    # rolling window. This means a one-shot or two-shot connection (the
    # vast majority of legitimate browsing) never carries the heavyweight
    # window state. Once the counter exceeds flow_grace_count the window
    # starts filling normally.
    if ( st$total_seen <= flow_grace_count )
        {
        flow_state[k] = st;
        return k;
        }

    # Roll the window.
    if ( |st$ts_window| >= beacon_window_size )
        {
        st$ts_window        = st$ts_window[1:];
        st$orig_size_window = st$orig_size_window[1:];
        st$resp_size_window = st$resp_size_window[1:];
        st$resumed_window   = st$resumed_window[1:];
        }

    local orig_b:    count = (c?$orig && c$orig?$size) ? c$orig$size : 0;
    local resp_b:    count = (c?$resp && c$resp?$size) ? c$resp$size : 0;
    local was_resumed: bool = (c?$ssl && c$ssl?$resumed && c$ssl$resumed);

    # ---- Bidirectionality via response bytes (FN defence) ----
    # server_seen is normally set when we capture a ja3s/ja4s. But on a
    # busy sensor the ServerHello may be missed on the first handshakes,
    # and resumed sessions never carry a fresh ja3s. If the server sent
    # back a meaningful number of bytes, it demonstrably responded — that
    # is bidirectional communication regardless of whether we fingerprinted
    # it. Without this, a real C2 whose ServerHello we missed would be
    # permanently excluded by the require_bidirectional gate (false negative).
    if ( resp_b >= bidirectional_min_resp_bytes )
        st$server_seen = T;

    st$ts_window        += c$start_time;
    st$orig_size_window += orig_b;
    st$resp_size_window += resp_b;
    st$resumed_window   += was_resumed;

    st$total_orig_bytes += orig_b;
    st$total_resp_bytes += resp_b;

    if ( |st$uids| < 32 )
        add st$uids[c$uid];

    flow_state[k] = st;
    return k;
    }


# ====================================================================
# SECTION 10 — EVENT HANDLERS
# ====================================================================

# ssl_established — update JA3 popularity and pivot tracking.
# Fires when the TLS handshake completes successfully.
#
# NOTE: this handler does NOT use triage_skip directly because that
# function includes the popularity check, which would create a
# bootstrap deadlock (no destination could ever become popular). Instead
# we apply the cheap allowlist filters individually, then call
# note_dest_client for everything that survives. note_dest_client
# itself short-circuits cheaply for already-popular destinations.
event Intel::match(s: Intel::Seen, items: set[Intel::Item]) &priority = -5
    {
    # Record operator-provided intel hits for CORROBORATION only. We never
    # alert from an intel hit directly (a stale or benign reputation lookup
    # would be a false positive) — the beacon/tunnel/reverse-flow detectors
    # consult this state and escalate a behavioural detection whose
    # destination also has an intel hit.
    local desc = "";
    for ( it in items )
        {
        if ( it?$meta && it$meta?$desc )
            { desc = it$meta$desc; break; }
        }

    local domain = "";
    if ( s?$indicator_type && s$indicator_type == Intel::DOMAIN && s?$indicator )
        domain = s$indicator;

    # Resolve the destination address from the connection if present.
    if ( s?$conn )
        note_intel_hit(s$conn$id$resp_h, domain, desc);
    else if ( s?$host )
        note_intel_hit(s$host, domain, desc);
    else if ( domain != "" )
        # Domain-only hit (e.g. DNS request) with no usable address — still
        # record it under the domain key for SNI-based correlation.
        note_intel_hit(0.0.0.0, domain, desc);
    }

event ssl_established(c: connection) &priority = -5
    {
    # Direction / scope gate — outbound only (see triage_skip).
    if ( c2_require_outbound && ! is_outbound_flow(c) )
        return;

    # Cheap allowlist filters first — but NOT the popularity check.
    if ( is_orig_trusted(c$id$orig_h) )       return;
    if ( is_dest_trusted(c$id$resp_h) )       return;
    if ( is_proxy_destination(c$id$orig_h) )  return;
    # Operator allowlist entries are ABSOLUTE — see the note in triage_skip.
    if ( c?$ssl && c$ssl?$server_name &&
         is_sni_fully_safe(c$ssl$server_name) )
        return;

    # Track per-destination client population (the 5-host rule).
    # This is what feeds is_dest_popular(); without this call here, no
    # destination could ever cross the popularity threshold.
    note_dest_client(dest_identity(c), c$id$orig_h);

    # JA3 popularity and pivot tracking still apply (JA3 retained for
    # reporting / JA3-keyed intel).
    if ( c?$ssl && c$ssl?$ja3 )
        note_ja3_client(c$ssl$ja3, c$id$orig_h);

    # Primary-fingerprint (JA4-preferred) client tracking — the rarity
    # baseline the detectors consult. Stable across GREASE/order, so browsers
    # collapse to one bucket instead of a rare-looking long tail.
    local pfp = primary_fp(c$ssl?$ja3 ? c$ssl$ja3 : "",
                           c$ssl?$ja4 ? c$ssl$ja4 : "");
    if ( pfp != "" )
        note_fp_client(pfp, c$id$orig_h);

    note_pivot(c);

    # ssl_established fires when the handshake completes — the server has
    # sent its ServerHello, so ja3s MUST be available. Mark the flow as
    # bidirectional. We also do this in update_flow_state, but doing it
    # here means even flows that never close (long-lived connections) get
    # server_seen = T as soon as the handshake completes.
    if ( ! c?$ssl ) return;
    local sni = c$ssl?$server_name ? c$ssl$server_name : "";
    local via_proxy = is_proxy_destination(c$id$resp_h);
    local dest_id = dest_identity_for(sni, c$id$resp_h, via_proxy);
    local ja3 = primary_fp(c$ssl?$ja3 ? c$ssl$ja3 : "",
                           c$ssl?$ja4 ? c$ssl$ja4 : "");
    local fk: FlowKey = [$orig = c$id$orig_h, $dest_id = dest_id, $ja3 = ja3];
    if ( fk in flow_state )
        {
        local st = flow_state[fk];
        if ( c$ssl?$ja3s && c$ssl$ja3s != "" && c$ssl$ja3s != "-" )
            st$server_seen = T;
        if ( c$ssl?$ja4s && c$ssl$ja4s != "" && c$ssl$ja4s != "-" )
            st$server_seen = T;
        flow_state[fk] = st;
        }
    }

# LongConnection hook — fires as long flows cross duration thresholds.
# Provides early-warning tunnel detection without waiting for flow close.
event LongConnection::long_conn_found(c: connection)
    {
    evaluate_tunnel(c);
    }

# Main entry point — runs at flow close for short/medium flows.
# note_emerging_shape — record (internal only) that a flow's first-contact
# shape resembles a C2 check-in. This NEVER emits an alert. A single flow,
# or a first contact, is the weakest possible C2 signal: the strong signal
# is behaviour over time (beaconing / tunnel / reverse-flow). This marker is
# consumed by those evaluators, where it contributes a small confidence
# bonus ONLY once real behaviour has independently confirmed. It exists so
# that a genuine implant whose staging phase we witnessed is scored slightly
# higher when it does start beaconing — without ever alerting on the noisy
# first-contact population (Azure, Cloudflare, RDP to internal DCs, etc.).
function note_emerging_shape(c: connection, k: FlowKey, st: FlowState)
    {
    # Only look at genuinely-young flows; older flows are the beacon path's.
    if ( st$total_seen > flow_grace_count + 1 )
        return;
    if ( ! st$server_seen )
        return;
    if ( st$emerging_shape )
        return;   # already marked

    # Strong cert-level anomaly, OR a no-SNI/no-ALPN TLS1.3 Go stack. These
    # are the shapes benign first-contact rarely has — but note that even
    # these are TOO COMMON to alert on alone (self-signed internal services,
    # RDP, etc.), which is exactly why this only sets an internal marker.
    local suspicious = F;

    if ( has_suspect_issuer(st$cert_issuer) )
        suspicious = T;

    if ( st$cert_validation != "" && st$cert_validation != "ok" &&
         st$cert_validation != "-" )
        {
        if ( "self signed"       in st$cert_validation ||
             "expired"           in st$cert_validation ||
             "signature failure" in st$cert_validation )
            suspicious = T;
        }

    local alpn_field = ja4_alpn_field(st$ja4);
    if ( (st$sni == "" || st$sni == "(empty)") &&
         (alpn_field == "00" || alpn_field == "") &&
         st$tls_version == "TLSv13" )
        suspicious = T;

    if ( ! suspicious )
        return;

    # Rare destination only (a popular dest is not first-contact C2).
    local dest_id = k$dest_id;
    local n_clients = (dest_id in dest_client_count) ?
                      |dest_client_count[dest_id]| : 0;
    if ( n_clients > popular_dest_threshold )
        return;

    st$emerging_shape = T;
    flow_state[k]     = st;
    }

event connection_state_remove(c: connection) &priority = -5
    {
    if ( triage_skip(c) )           return;

    if ( ! c?$ssl )                 return;
    if ( below_track_floor(c) )     return;

    # Long flows → tunnel evaluator (different analysis path).
    if ( c?$duration && c$duration >= long_conn_duration )
        {
        evaluate_tunnel(c);
        return;
        }

    # Medium flows: check for reverse-flow (RAT) shape.
    evaluate_reverse_flow(c);

    # Update per-flow beacon state.
    local k  = update_flow_state(c);

    # update_flow_state early-returns WITHOUT creating state when this update
    # tipped the destination over popular_dest_threshold: note_dest_client()
    # calls evict_state_for_dest(), which deletes every flow_state entry for
    # that destination, and update_flow_state then returns k with nothing
    # tracked. Indexing flow_state[k] here unguarded raises a Zeek reporter
    # error once per destination per popularity flip. The destination is now
    # popular (a shared service, not single-host C2), so there is nothing left
    # to evaluate — bail out.
    if ( k !in flow_state )
        return;

    local st = flow_state[k];

    # Periodic beacon evaluation.
    if ( st$total_seen >= beacon_min_count )
        evaluate_beacon(k, st, c$id$resp_p);

    # Emerging / pre-beacon C2 evaluation — first-contact shape before a
    # flow has enough samples to be a beacon. Only meaningful early in a
    # flow's life; the beacon path takes over once samples accumulate.
    if ( emerging_c2_enabled && st$total_seen < beacon_alert_min_count )
        note_emerging_shape(c, k, st);

    # Pivot evaluation (requires flow_state to already exist).
    evaluate_pivot(c);
    }

# zeek_done — emit any pending flows from offline PCAP analysis.
event zeek_done()
    {
    for ( k, st in flow_state )
        {
        if ( st$total_seen >= beacon_alert_min_count &&
             st$last_alert == double_to_time(0) )
            evaluate_beacon(k, st, 443/tcp);
        }
    }
