# C2_SSL — shared types, the c2_detections_ssl log stream, and helpers.

@load base/frameworks/logging
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/ssl

module C2_SSL;

# ------------------------------------------------------------------
# SPL package shim
# ------------------------------------------------------------------
@ifndef ( SPL::Info )
module SPL;
export {
    type Info: record {
        orig_spl: vector of count  &optional;
        resp_spl: vector of count  &optional;
        orig_spt: vector of double &optional;
        resp_spt: vector of double &optional;
    };
}
redef record connection += { spl: SPL::Info &optional; };
@endif

# ------------------------------------------------------------------
# Long-connections package shim
# ------------------------------------------------------------------
@ifndef ( LongConnection::long_conn_found )
module LongConnection;
export {
    global long_conn_found: event(c: connection);
}
@endif

module C2_SSL;

export {
    redef enum Log::ID += { LOG };

    # Notice type raised when generate_notices = T.
    # By default notices are disabled — enable only after tuning.
    redef enum Notice::Type += {
        C2_Detected,  # Fired for every c2_detections_ssl.log entry when
                      #< C2_SSL::generate_notices = T. Suppressed by default.
    };

    # Detection categories.
    type Category: enum {
        SSL_PERIODIC_BEACON,          # Repeated full-handshake beaconing
        SSL_RESUMPTION_PINNED_BEACON, # Session-resumption pinned (no cert exchange)
        SSL_TUNNEL_KEEPALIVE,         # Long-lived TLS with keep-alive cadence
        SSL_TUNNEL_INSIDE_TLS,        # TLS-in-TLS or custom framed protocol
        SSL_REVERSE_FLOW_RAT,         # Server-driven RAT command-then-exfil
        SSL_BEACON_EXFIL,             # Confirmed beacon dest moving bulk data (exfil/payload)
        SSL_C2_EXFIL_ESCALATION,      # Escalating cumulative exfiltration on a confirmed C2 (volume ladder / slow-drain)
        SSL_HOST_C2_ESCALATION,       # (deprecated as a category — escalation is now the 'host_c2_escalation' indicator on the real C2 category; retained for compatibility)
        SSL_EMERGING_C2,              # (internal-state category — first-contact shape; never emitted standalone)
        SSL_TRUSTED_PIVOT_RARE_FP,    # Rare client fingerprint to abusable CDN
        SSL_LONG_CONN_ANOMALY,        # Long-conn with suspicious properties
        SSL_NONSTANDARD_INNER_PROTO,  # Non-HTTPS protocol tunnelled inside TLS
    };

    # Inner protocol hints — what we think is running inside the TLS tunnel.
    type InnerProto: enum {
        INNER_UNKNOWN,       # Insufficient data or looks like normal HTTPS
        INNER_LIKELY_HTTPS,  # Consistent with HTTP/2 or HTTP/1.x
        INNER_FIXED_FRAME,   # Fixed-width framing (SSH, RDP, custom binary)
        INNER_SMALL_UNIFORM, # Very small, very uniform packets (heartbeat/keepalive C2)
        INNER_BINARY_BURST,  # Irregular large bursts typical of file-transfer C2
        INNER_NONSTANDARD_ALPN, # ALPN advertised a non-HTTPS protocol
    };

    # Log record written to c2_detections_ssl.log.
    type Info: record {
        ts:                 time        &log;
        category:           Category    &log;
        confidence:         double      &log;
        orig_h:             addr        &log;
        resp_h:             addr        &log;
        resp_p:             port        &log;

        # SNI or "(empty)" when absent.
        sni:                string      &log &default = "";

        # True when resp_h is a configured web proxy. Analysts: the real
        # destination is sni; ja3s/ja4s belong to the proxy, not upstream.
        via_proxy:          bool        &log &default = F;

        # True when the flow was confirmed intercepted by a declared
        # interception CA. The cert/ja3s/ja4s are the proxy's; detection
        # for this flow was behaviour-driven, not cert-driven.
        proxy_intercepted:  bool        &log &default = F;

        # Real destination host from the http.log CONNECT (when available).
        # Authoritative even when SNI is absent. Empty if no CONNECT seen.
        connect_host:       string      &log &default = "";

        # Human-readable signal summary for the analyst.
        details:            string      &log &default = "";

        # Number of contributing connections in the sample window.
        sample_count:       count       &log &default = 0;

        total_orig_bytes:   count       &log &default = 0;
        total_resp_bytes:   count       &log &default = 0;
        duration_seen:      interval    &log &default = 0sec;
        pcr:                double      &log &default = 0.0;

        # TLS context.
        tls_version:        string      &log &default = "";
        cert_issuer:        string      &log &default = "";
        cert_validation:    string      &log &default = "";

        # ALPN negotiated protocol (e.g. "h2", "http/1.1", or something else).
        alpn:               string      &log &default = "";

        # Inner-protocol assessment — what we think is tunnelled inside TLS.
        inner_proto:        InnerProto  &log &default = INNER_UNKNOWN;

        # Fingerprints. ja3s/ja4s are blanked when via_proxy=T.
        ja3:                string      &log &default = "";
        ja3s:               string      &log &default = "";
        ja4:                string      &log &default = "";
        ja4s:               string      &log &default = "";

        # A representative uid for pivoting into ssl/conn/x509 logs.
        sample_uid:         string      &log &default = "";

        # Free-form indicator tags.
        indicators:         set[string] &log &default = set();
    };

    global log_policy: Log::PolicyHook;
    global log_c2_ssl: event(rec: Info);

    # ------------------------------------------------------------------
    # State types.
    # ------------------------------------------------------------------

    type FlowKey: record {
        orig:    addr;
        dest_id: string;  # SNI (lowercased) or dotted-IP string
        ja3:     string;  # JA3 client fingerprint
    };

    type FlowState: record {
        first_seen:         time              &default = double_to_time(0);
        last_seen:          time              &default = double_to_time(0);
        last_alert:         time              &default = double_to_time(0);
        last_alert_cat:     Category          &optional;

        ts_window:          vector of time    &default = vector();
        orig_size_window:   vector of count   &default = vector();
        resp_size_window:   vector of count   &default = vector();
        resumed_window:     vector of bool    &default = vector();

        total_seen:         count             &default = 0;
        total_orig_bytes:   count             &default = 0;
        total_resp_bytes:   count             &default = 0;

        last_resp_h:        addr              &optional;
        sni:                string            &default = "";
        tls_version:        string            &default = "";
        cert_issuer:        string            &default = "";
        cert_subject:       string            &default = "";
        cert_validation:    string            &default = "";
        alpn:               string            &default = "";

        # Tri-state record of Zeek's built-in c$ssl$sni_matches_cert,
        # which uses x509_check_cert_hostname() — checks CN AND all SAN
        # entries — and correctly handles wildcards. Modern certs put
        # actual coverage in SAN (e.g. messenger.com cert has CN=*.facebook.com
        # but SAN=messenger.com), so a CN-only check produces FPs.
        #
        #   "T" — Zeek confirmed the SNI matches the cert (CN or SAN).
        #   "F" — Zeek confirmed mismatch. Strong C2 indicator.
        #   ""  — never observed (no SNI sent, or no cert seen yet).
        sni_matches_cert:   string            &default = "";

        # Sticky flag: T if this flow has EVER been seen offering or
        # negotiating an HTTP-family ALPN (h2 / http/1.1 / etc.).
        # Once T, never reset — even resumed sessions that don't
        # carry ALPN themselves keep the flag set. This is the core
        # web-traffic discriminator.
        seen_web_alpn:      bool              &default = F;

        ja3:                string            &default = "";
        ja3s:               string            &default = "";
        ja4:                string            &default = "";
        ja4s:               string            &default = "";

        uids:               set[string]       &default = set();
        via_proxy:          bool              &default = F;

        # True once this flow has been positively confirmed as intercepted
        # by a declared interception CA (issuer / fingerprint / server-fp
        # match). When T, the certificate and JA3S/JA4S on the flow are the
        # PROXY's, not the real upstream — cert-based signals are therefore
        # NOT applied, and detection relies on behaviour. Sticky.
        proxy_intercepted:  bool              &default = F;

        # Real destination host from the plaintext http.log CONNECT request
        # (proxied HTTPS). Authoritative when present — survives even when
        # SNI is absent (e.g. Encrypted Client Hello). Populated by
        # correlating http.log CONNECT entries by connection uid.
        connect_host:       string            &default = "";

        # True once we have seen at least one server fingerprint (ja3s or
        # ja4s) for this flow. Only set when the server has genuinely
        # responded — blocked/dropped connections never set this.
        server_seen:        bool              &default = F;

        # Internal-only marker: the flow's FIRST-CONTACT shape looked like a
        # possible C2 check-in (suspect/self-signed cert, or no-SNI+no-ALPN
        # Go stack, to a rare destination). This is a WEAK signal — it never
        # produces an alert on its own. It only CONTRIBUTES a small bonus if
        # the flow later confirms as a real beacon/tunnel/reverse-flow. This
        # is the "emerging C2" concept demoted from an alert to internal
        # tracking, per the principle that C2 signal is behaviour over time.
        emerging_shape:     bool              &default = F;

        # Count and sizes of payload/tasking DOWNLOAD bursts observed inside
        # this (confirmed) C2 channel — evidence only, surfaced as payloads=N
        # in the alert details. See the payload-staging correlator.
        payload_count:      count             &default = 0;
        payload_max_dl:     count             &default = 0;

        # Bounded, forensic list of observed payload-download bursts on this
        # confirmed C2 channel: each entry is "<bytes>@<approx-secs-into-
        # channel>". Capped (payload_burst_detail_cap) so a long-lived beacon
        # with many updates cannot grow it unbounded; beyond the cap only the
        # running count/total are kept. Reporting only — never affects
        # detection. The time is the OBSERVATION time (now - first_seen), an
        # approximation of when the burst crossed, not an exact packet time.
        payload_bursts:     vector of string   &default = vector();
        payload_last_size:  count             &default = 0;
        payload_total_dl:   count             &default = 0;

        # Exfil escalation ladder state. exfil_rung is the highest ladder rung
        # index already alerted for this flow (0 = none). exfil_last_alert is
        # when we last emitted an exfil-escalation, for the slow-drain re-fire.
        exfil_rung:         count             &default = 0;
        exfil_last_alert:   time              &default = double_to_time(0);
    };


    type PivotKey: record {
        sni: string;
        ja3: string;
    };

    # ------------------------------------------------------------------
    # State tables.
    # ------------------------------------------------------------------

    global flow_state: table[FlowKey] of FlowState
        &create_expire = flow_state_expiry;


    global ja3_clients: table[string] of set[addr]
        &create_expire = ja3_pop_expiry;

    # Primary-fingerprint client tracking. Keyed on the PRIMARY fingerprint
    # (JA4 when available, else JA3). This is the rarity/popularity baseline
    # the detectors consult. JA4 is preferred because it excludes GREASE and
    # normalises cipher/extension order, so the SAME client yields a STABLE
    # hash — whereas JA3 includes GREASE and is order-sensitive, making
    # browsers look artificially "rare" and polluting the rarity signal. JA3
    # tracking above is retained for JA3-keyed intel and reporting.
    global fp_clients: table[string] of set[addr]
        &create_expire = ja3_pop_expiry;

    global pivot_ja3_clients: table[PivotKey] of set[addr]
        &create_expire = pivot_state_expiry;

    # JA4 cipher-hash → number of times observed alongside an HTTP-family
    # ALPN. Keyed by the second segment of JA4 (the cipher hash, e.g.
    # "d83cc789557e"). When this counter is high, the cipher set is
    # "browser-like" — i.e. has been seen doing real HTTPS — and
    # subsequent flows from the same cipher hash get a confidence
    # penalty even when those particular flows don't show ALPN.
    #
    # This is the key fuzzy-fingerprint defence: the JA4 cipher segment
    # stays stable across SNI / extension order / session resumption,
    # so once we've seen Chrome's ciphers do real HTTPS, we recognise
    # Chrome's ciphers wherever they appear.
    global browser_ja4_ciphers: table[string] of count
        &create_expire = ja3_pop_expiry
        &default = 0;

    # Network-wide per-destination client count. Keyed by dest_id
    # (lowercased SNI or dotted-IP string). When this set exceeds
    # popular_dest_threshold, the destination is marked popular and
    # tracking for it stops aggressively.
    global dest_client_count: table[string] of set[addr]
        &create_expire = popular_dest_expiry;

    # Set of dest_id strings known to be "popular". Membership in this
    # set short-circuits all tracking for that destination. Refreshed
    # by note_dest_client on every connection — so an actively-used
    # destination stays popular indefinitely.
    # NOTE: &write_expire (NOT &create_expire). &create_expire times from
    # INSERTION and is never refreshed by reads or writes, so an actively-used
    # popular destination would silently expire and fall back into the tracked
    # candidate pool — with its dest_client_count already deleted, it would
    # have to re-earn popularity from zero. That produces a periodic,
    # network-wide false-positive window every popular_dest_expiry.
    # &write_expire is refreshed on write, so the `add` in note_dest_client
    # genuinely extends the lifetime and a busy destination stays popular for
    # as long as it keeps being hit.
    global popular_dests: set[string]
        &write_expire = popular_dest_expiry;

    # ------------------------------------------------------------------
    # Public helpers.
    # ------------------------------------------------------------------

    global dest_identity: function(c: connection): string;
    global dest_identity_for: function(sni: string, resp_h: addr,
                                        via_proxy: bool): string;
    global dest_identity_full: function(sni: string, connect_host: string,
                                         resp_h: addr, via_proxy: bool): string;
    global median: function(v: vector of double): double;
    global mad: function(v: vector of double, med: double): double;

    # Quartile-based robust skewness of a double vector (Bowley). Used as a
    # symmetry check on beacon inter-arrival deltas, complementing the
    # MAD/median dispersion measure. Returns 0.0 (symmetric / no evidence)
    # for degenerate or too-small inputs.
    global bowley_skewness: function(v: vector of double): double;
    global quantile_sorted: function(s: vector of double, q: double): double;
    global iqr_spread: function(v: vector of double): double;
    global iat_entropy: function(gaps: vector of double, bin_frac: double): double;
    global lag1_autocorr: function(x: vector of double): double;
    global mode_count: function(v: vector of count): count;
    global peak_density: function(v: vector of count): double;
    global median_count: function(v: vector of count): count;
    global sum_count: function(v: vector of count): count;
    global variance_double: function(v: vector of double,
                                      mean: double): double;
    global pcr: function(orig_b: count, resp_b: count): double;
    global ts_gaps: function(ts: vector of time): vector of double;
    global note_ja3_client: function(ja3: string, client: addr);
    global ja3_client_count: function(ja3: string): count;

    # Primary fingerprint of a flow: JA4 when present, else JA3. All rarity
    # and tracking logic keys on this so browsers stay stable (JA4 excludes
    # GREASE / normalises order). Falls back to JA3 when the JA4 field is
    # empty (e.g. the FoxIO JA4 plugin isn't loaded on the sensor).
    global primary_fp: function(ja3: string, ja4: string): string;

    # Record / count clients for the PRIMARY fingerprint (see fp_clients).
    global note_fp_client: function(fp: string, client: addr);
    global fp_client_count: function(fp: string): count;

    # JA4 structured analytics (decompose the readable prefix).
    #   ja4_prefix:  the leading segment before the first "_"
    #                (e.g. "t13d1516h2" — proto/TLSver/SNI/#ciphers/#exts/ALPN).
    #   ja4_is_browser_shape: T if the JA4 prefix matches the typical browser
    #                envelope (modern TLS, SNI present, HTTP ALPN, cipher/ext
    #                counts in the browser range). Used to DEMOTE rarity for
    #                browser-class fingerprints even when the exact hash is
    #                rare (GREASE residue / a new browser build). NEVER used to
    #                suppress behavioural detection — malware can wear a
    #                browser shape (injection, mimicry), so timing/shape
    #                detection is always independent of this.
    global ja4_prefix: function(ja4: string): string;
    global ja4_is_browser_shape: function(ja4: string): bool;

    # Exfil escalation ladder helpers.
    #   exfil_rung_for(bytes): the rung INDEX for a cumulative upload volume.
    #     0 = below the initial trip; 1 = crossed the initial trip; then each
    #     decade contributes 9 rungs (1x..9x the decade base). Monotonic:
    #     a larger volume always yields a >= index.
    #   exfil_rung_threshold(idx): the byte value at which rung idx trips
    #     (for reporting "crossed 2 GB").
    global exfil_rung_for: function(total_upload: count): count;
    global exfil_rung_threshold: function(rung: count): count;
    global human_bytes: function(n: count): string;

    # Record this client/destination pair. If the count for the
    # destination crosses popular_dest_threshold, mark the destination
    # popular and evict any per-flow state for it.
    global note_dest_client: function(dest_id: string, client: addr);

    # Distinct internal-client count for a destination (0 if popular/evicted).
    global dest_client_n: function(dest_id: string): count;

    # Fan-out confidence penalty for a destination: 0.0 for a 1:1 (single
    # client) flow, rising as more internal hosts contact the same dest.
    # Used to scale down confidence on shared-service destinations that are
    # not single-host C2. Returns a POSITIVE number to subtract from conf.
    global fanout_penalty: function(dest_id: string): double;

    # True if this destination has been marked popular.
    global is_dest_popular: function(dest_id: string): bool;

    # Delete every flow_state entry for this dest_id.
    # Called when a destination crosses the popularity threshold.
    global evict_state_for_dest: function(dest_id: string);

    # True if the given ALPN string is HTTP-family (h2, http/1.1, etc.).
    # Comparison is case-insensitive and treats the Zeek unset markers
    # ("-", "(empty)", "") as not-web.
    global is_web_alpn: function(alpn: string): bool;

    # Extract the second segment (cipher hash, 12 hex chars) from a
    # JA4 string. Returns "" if the string isn't well-formed JA4.
    # Example: "t12d1909h2_d83cc789557e_2dae41c691ec" → "d83cc789557e".
    global ja4_cipher_segment: function(ja4: string): string;

    # Cipher+extension hash tail of a JA4 (2nd_3rd components). Reflects the
    # client TLS stack; stable across SNI-presence/count changes. Used for
    # payload-handoff correlation.
    global ja4_cipher_ext_tail: function(ja4: string): string;

    # Extract the last 2 chars of the first segment of a JA4 string —
    # these encode the first ALPN value the client offered. "h2", "h1",
    # "00" (no ALPN), "dt" (DoT), etc. Returns "" if not parseable.
    global ja4_alpn_field: function(ja4: string): string;

    # Bump the browser-like cipher counter. Called whenever we see a
    # flow with both a JA4 and an HTTP ALPN — that's a positive signal
    # that this cipher set belongs to a real HTTPS-capable client.
    global note_browser_ja4: function(ja4: string);

    # True if the given JA4's cipher segment has been observed alongside
    # an HTTP ALPN at least browser_ja4_min_observations times. Used to
    # detect "this is a browser doing TLS, not malware".
    global is_browser_ja4: function(ja4: string): bool;

    # ------------------------------------------------------------------
    # Host compromise correlation state (multi-C2 / payload-transition).
    # ------------------------------------------------------------------
    # All node-local and in-memory with automatic time-decay. No disk
    # persistence (resets on restart) — consistent with a conservative,
    # dependency-free design.

    # Hosts that have produced a high-confidence C2 alert, with the time
    # their compromised state expires. Auto-expires via &create_expire.
    global compromised_hosts: table[addr] of time
        &create_expire = 6hr;

    # Fingerprints (ja3, ja4, and JA4 cipher-tail) OBSERVED ON confirmed
    # high-confidence C2 flows, network-wide. Value is the arming host.
    #
    # NOTE ON NAMING: these are "tracked" fingerprints, not "malicious" ones.
    # We cannot attribute maliciousness to a TLS fingerprint: a rare JA3 seen
    # on a C2 could equally be a particular version of PowerShell, rundll3
    # or another LOLBIN being abused, or an uncommon-but-benign client. What
    # we CAN say is "this exact fingerprint was seen on something we
    # confidently detected as C2, and here it is again" — useful for tracking
    # and corroboration, not for calling the fingerprint itself bad. Arming is
    # also gated on rarity (fingerprint_arm_max_hosts) precisely because a
    # common fingerprint is almost certainly shared benign software.
    global tracked_c2_fingerprints: table[string] of addr
        &create_expire = 12hr;

    # Mark a host compromised (called on a high-confidence alert). Records
    # the fingerprints of the flow so later handoffs can be correlated.
    global mark_host_compromised: function(host: addr, ja3: string,
                                            ja4: string);

    # True if the host is currently in compromised state.
    global is_host_compromised: function(host: addr): bool;

    # True if a ja3/ja4 matches a fingerprint previously seen on a confirmed
    # C2 (a "tracked" fingerprint — see the naming note above). Not an
    # assertion that the fingerprint is malicious.
    global is_tracked_c2_fingerprint: function(ja3: string, ja4: string,
                                                host: addr): bool;

    # ------------------------------------------------------------------
    # Payload-staging state (in-TLS download burst -> stage transition).
    # ------------------------------------------------------------------
    # A host that just received a payload/tasking download burst INSIDE a
    # confirmed C2. Value is the time the marker expires (short window). Used
    # to corroborate a NEW channel that confirms as C2 shortly after — the
    # "download a next stage, then a new C2 appears" transition. Never causes
    # an alert on its own.
    global payload_staged_hosts: table[addr] of time
        &create_expire = 2min;

    # Record that a payload burst occurred on this host (marker with expiry).
    global mark_payload_staged: function(host: addr);

    # True if the host received a payload burst within payload_staged_window.
    global is_payload_staged: function(host: addr): bool;

    # ------------------------------------------------------------------
    # Threat-intel corroboration state.
    # ------------------------------------------------------------------
    # Intel-framework hits (from the operator's own Intel feeds, written to
    # intel.log) are recorded here keyed by the destination they involve.
    # An intel hit ALONE never produces a C2 alert — a stale or benign
    # reputation lookup would be a false positive. Instead it CORROBORATES a
    # behavioural detection: a confirmed beacon/tunnel/reverse-flow whose
    # destination also has an intel hit is escalated. Auto-expires.
    global intel_hit_dests: table[addr] of string
        &create_expire = 12hr;

    # Also key by SNI/domain string, since intel hits are often on the
    # domain (DNS request / SSL SNI) rather than the resolved IP.
    global intel_hit_domains: table[string] of string
        &create_expire = 12hr;

    # Record an intel hit (called from the Intel::match handler).
    global note_intel_hit: function(dest: addr, domain: string, desc: string);

    # Corroboration lookups for the detectors.
    global intel_hit_for_dest: function(dest: addr): string;
    global intel_hit_for_domain: function(domain: string): string;
}

# ------------------------------------------------------------------
# Log stream registration.
# ------------------------------------------------------------------

event zeek_init() &priority = 5
    {
    Log::create_stream(C2_SSL::LOG, [
        $columns = Info,
        $ev      = log_c2_ssl,
        $path    = "c2_detections_ssl",
        $policy  = log_policy
    ]);
    }

# ------------------------------------------------------------------
# Helper implementations.
# ------------------------------------------------------------------

function dest_identity_for(sni: string, resp_h: addr,
                            via_proxy: bool): string
    {
    if ( sni != "" && sni != "(empty)" )
        return to_lower(sni);
    if ( via_proxy )
        return fmt("proxy:%s", resp_h);
    return fmt("%s", resp_h);
    }

# Connect-host-aware variant: prefer SNI, then the plaintext CONNECT host
# (authoritative for proxied HTTPS, survives Encrypted Client Hello), then
# fall back to the proxy/IP identity. Used wherever a real-destination
# identity is wanted for proxied flows.
function dest_identity_full(sni: string, connect_host: string,
                             resp_h: addr, via_proxy: bool): string
    {
    if ( sni != "" && sni != "(empty)" )
        return to_lower(sni);
    if ( connect_host != "" && connect_host != "(empty)" )
        return to_lower(connect_host);
    if ( via_proxy )
        return fmt("proxy:%s", resp_h);
    return fmt("%s", resp_h);
    }

function dest_identity(c: connection): string
    {
    local sni = "";
    if ( c?$ssl && c$ssl?$server_name )
        sni = c$ssl$server_name;
    local via_proxy = is_proxy_destination(c$id$resp_h);
    return dest_identity_for(sni, c$id$resp_h, via_proxy);
    }

function median(v: vector of double): double
    {
    local n = |v|;
    if ( n == 0 )
        return 0.0;
    local s: vector of double = copy(v);
    sort(s);
    if ( n % 2 == 1 )
        return s[n / 2];
    return (s[n / 2 - 1] + s[n / 2]) / 2.0;
    }

function mad(v: vector of double, med: double): double
    {
    local n = |v|;
    if ( n == 0 )
        return 0.0;
    local devs: vector of double = vector();
    local i = 0;
    while ( i < n )
        {
        local d = v[i] - med;
        if ( d < 0.0 ) d = -d;
        devs += d;
        ++i;
        }
    return median(devs);
    }

# quantile_sorted — linear-interpolation quantile of an ALREADY-SORTED
# double vector. q in [0,1]. Used for Bowley skewness quartiles.
function quantile_sorted(s: vector of double, q: double): double
    {
    local n = |s|;
    if ( n == 0 )
        return 0.0;
    if ( n == 1 )
        return s[0];
    # Position on [0, n-1] and linear interpolation between neighbours.
    local pos = q * (n - 1);
    local lo = double_to_count(floor(pos));
    local hi = lo + 1;
    if ( hi >= n )
        return s[n - 1];
    local frac = pos - lo;
    return s[lo] + (s[hi] - s[lo]) * frac;
    }

# iqr_spread — the absolute inter-quartile spread (P75 - P25) of a double
# vector, in the vector's own units (seconds, for inter-arrival gaps).
#
# This is the spread of the MIDDLE 50% of the samples, which explicitly
# discards the top and bottom quartiles. Its purpose here is robustness to
# the specific reality of long-lived C2 sessions: an operator waking a beacon
# to run a command injects a few very long inter-arrival gaps (and network
# stalls inject a few very short ones). Those live in the outer quartiles, so
# they do NOT affect the IQR — whereas they can still move MAD if the outlier
# cluster is large enough. Used as a qualifier/forensic metric, not as an
# independent confidence axis (the jitter ratio already scores regularity —
# this confirms whether apparent jitter is bounded/proportionate rather than
# genuine irregularity; see iqr_proportionate_max in config.zeek).
#
# Returns 0.0 for fewer than 4 samples (quartiles need a minimum spread of
# points to be meaningful), which callers treat as "no evidence".
function iqr_spread(v: vector of double): double
    {
    local n = |v|;
    if ( n < 4 )
        return 0.0;
    local s: vector of double = copy(v);
    sort(s);
    local q1 = quantile_sorted(s, 0.25);
    local q3 = quantile_sorted(s, 0.75);
    return q3 - q1;
    }

# bowley_skewness — quartile-based (robust) skewness of a double vector.
#
#   skew = (Q1 + Q3 - 2*Q2) / (Q3 - Q1)
#
# Range is [-1, 1]. Zero means a symmetric distribution; positive means a
# right (long high-side) tail, negative a left tail. RITA uses this on beacon
# inter-arrival deltas: a genuine beacon has a SYMMETRIC delta distribution
# (skew ~ 0), even when jittered, whereas bursty human/app traffic that
# merely clusters tends to have a lopsided tail. Bowley is chosen over
# moment skewness because quartiles are robust to a few outlier sleep gaps,
# consistent with the MAD/median approach used elsewhere here.
#
# Returns 0.0 (treated as "symmetric / no evidence") when there are too few
# samples or the interquartile range is degenerate, so callers can gate on
# sample count and never divide by zero.
function bowley_skewness(v: vector of double): double
    {
    local n = |v|;
    if ( n < 4 )
        return 0.0;
    local s: vector of double = copy(v);
    sort(s);
    local q1 = quantile_sorted(s, 0.25);
    local q2 = quantile_sorted(s, 0.50);
    local q3 = quantile_sorted(s, 0.75);
    local iqr = q3 - q1;
    if ( iqr <= 0.0 )
        # All mass between Q1 and Q3 is identical — perfectly regular timing.
        # That is maximally symmetric, so skew is zero.
        return 0.0;
    local sk = (q1 + q3 - 2.0 * q2) / iqr;
    # Clamp for numerical safety (Bowley is bounded [-1,1] analytically).
    if ( sk > 1.0 )  sk = 1.0;
    if ( sk < -1.0 ) sk = -1.0;
    return sk;
    }

# iat_entropy — Shannon entropy (in bits) of inter-arrival times, using
# RELATIVE binning. Measures the PREDICTABILITY of the timing: a low value
# means a few time-buckets dominate (a scheduler firing on a cadence); a high
# value means the gaps are spread unpredictably (human/app traffic).
#
# BINNING IS EVERYTHING, and it must be RELATIVE, not absolute. The bin width
# is a fraction of the MEDIAN gap (bin_frac * median), so the measure is
# SCALE-INVARIANT: a 5-second beacon and a 3600-second beacon with the same
# proportional jitter yield the same entropy. A fixed absolute bin cannot do
# this — it would read a fast beacon as perfectly regular and an identically
# jittered slow beacon as pure chaos, which is exactly the trap this avoids.
#
# H = -Σ p_i * log2(p_i) over the occupied bins, where p_i is the fraction of
# gaps that fall in bin i. Zeek has ln() but not log2, so log2(x)=ln(x)/ln(2).
#
# This is used ONLY as a confirmation signal (see entropy_* in config.zeek):
# a clearly-low entropy CONFIRMS a beacon is predictable; a high entropy earns
# NOTHING (never a penalty, never a gate), so a conservative threshold cannot
# cause false negatives in the detector — only fewer confirmations.
#
# Returns a high sentinel (999.0) for fewer than the minimum samples or a
# degenerate median, so callers treat "no evidence" as "not predictable" and
# simply decline to confirm.
function iat_entropy(gaps: vector of double, bin_frac: double): double
    {
    local n = |gaps|;
    if ( n < 8 || bin_frac <= 0.0 )
        return 999.0;
    local med = median(gaps);
    if ( med <= 0.0 )
        return 999.0;
    local binsize = med * bin_frac;
    if ( binsize <= 0.0 )
        return 999.0;

    # Bucket the gaps into relative bins and count occupancy.
    local counts: table[count] of count = table();
    local i = 0;
    while ( i < n )
        {
        local b = double_to_count(floor(gaps[i] / binsize + 0.5));
        if ( b !in counts ) counts[b] = 0;
        counts[b] += 1;
        ++i;
        }

    local ln2 = ln(2.0);
    local h = 0.0;
    for ( k, cnt in counts )
        {
        local p = (cnt + 0.0) / (n + 0.0);
        if ( p > 0.0 )
            h += p * (ln(p) / ln2);
        }
    return -h;
    }

# lag1_autocorr — lag-1 autocorrelation of a double vector, in [-1, 1].
#
#   r1 = Σ (x_i - μ)(x_{i-1} - μ)  /  Σ (x_i - μ)²
#
# Measures how each interval relates to its immediate predecessor:
#   r1 ~ -1 : strong ALTERNATING (period-2) structure — short,long,short,long.
#             This is a patterned-sleep evasion (a known Cobalt Strike-style
#             profile technique): it inflates MAD/variance so the flow looks
#             irregular, while being perfectly mechanical. MAD, jitter and
#             entropy are all blind to it — they see "high spread" and nothing
#             more. Lag-1 autocorrelation sees the hidden order.
#   r1 ~  0 : independent gaps — random jitter OR a perfectly constant beacon.
#             (So this NEVER rewards a plain or randomly-jittered beacon; those
#             are already handled by the jitter tiers and entropy.)
#   r1 ~ +1 : trending / monotonic drift (creeping sleep). Deliberately NOT
#             treated as a signal here — slow drift is as often benign as not,
#             and rewarding it risks false positives. Only STRONG-NEGATIVE r1
#             is used, and only ever as corroboration.
#
# Note this is specifically a PERIOD-2 detector: longer-period patterns
# (5,10,15,...) do not produce a strong negative r1 and are out of scope.
#
# Returns 0.0 (no evidence) for fewer than 4 samples or a degenerate
# (zero-variance) series, so callers treat it as "no pattern".
function lag1_autocorr(x: vector of double): double
    {
    local n = |x|;
    if ( n < 4 )
        return 0.0;
    local mu = 0.0;
    local i = 0;
    while ( i < n ) { mu += x[i]; ++i; }
    mu = mu / n;

    local num = 0.0;
    local den = 0.0;
    i = 0;
    while ( i < n )
        {
        local d = x[i] - mu;
        den += d * d;
        if ( i >= 1 )
            num += d * (x[i - 1] - mu);
        ++i;
        }
    if ( den <= 0.0 )
        return 0.0;
    local r = num / den;
    if ( r > 1.0 )  r = 1.0;
    if ( r < -1.0 ) r = -1.0;
    return r;
    }

function mode_count(v: vector of count): count
    {
    local n = |v|;
    if ( n == 0 )
        return 0;
    local freq: table[count] of count = table();
    local i = 0;
    while ( i < n )
        {
        if ( v[i] !in freq ) freq[v[i]] = 0;
        freq[v[i]] += 1;
        ++i;
        }
    local best: count = 0;
    local best_n: count = 0;
    for ( k, cnt in freq )
        if ( cnt > best_n ) { best = k; best_n = cnt; }
    return best;
    }

# Peak Density Ratio — how DOMINANT the most common size is, as a fraction of
# all samples (max_count / total). This upgrades the bare mode (which only
# says WHICH size is most common) into a measure of HOW concentrated the size
# distribution is. Rationale: attackers jitter TIMING freely, but an idle C2
# check-in is inherently a fixed size, so a high peak density (e.g. >= 0.80)
# is a strong "mechanical heartbeat" signal that survives timing evasion —
# it rescues a beacon whose jitter has pushed it just past the timing gate.
# Returns 0.0 for an empty window. O(n), same single pass as mode_count.
function peak_density(v: vector of count): double
    {
    local n = |v|;
    if ( n == 0 )
        return 0.0;
    local freq: table[count] of count = table();
    local i = 0;
    while ( i < n )
        {
        if ( v[i] !in freq ) freq[v[i]] = 0;
        freq[v[i]] += 1;
        ++i;
        }
    local best_n: count = 0;
    for ( k, cnt in freq )
        if ( cnt > best_n ) best_n = cnt;
    return (best_n + 0.0) / (n + 0.0);
    }

function sum_count(v: vector of count): count
    {
    local total: count = 0;
    local i = 0;
    while ( i < |v| ) { total += v[i]; ++i; }
    return total;
    }

function median_count(v: vector of count): count
    {
    # Median of a count vector, via a simple copy-and-sort. Used for the
    # beacon payload-size profile (C2 check-in sizing vs bulk transfer).
    local n = |v|;
    if ( n == 0 )
        return 0;
    local s: vector of count = copy(v);
    # Insertion sort (windows are small — beacon_window_size default 50).
    local i = 1;
    while ( i < n )
        {
        local key = s[i];
        local j = i;
        while ( j > 0 && s[j - 1] > key )
            { s[j] = s[j - 1]; --j; }
        s[j] = key;
        ++i;
        }
    if ( n % 2 == 1 )
        return s[n / 2];
    return (s[n / 2 - 1] + s[n / 2]) / 2;
    }

function variance_double(v: vector of double, mean: double): double
    {
    local n = |v|;
    if ( n < 2 )
        return 0.0;
    local sum_sq = 0.0;
    local i = 0;
    while ( i < n )
        {
        local diff = v[i] - mean;
        sum_sq += diff * diff;
        ++i;
        }
    return sum_sq / (n + 0.0);
    }

function pcr(orig_b: count, resp_b: count): double
    {
    local o = orig_b + 0.0;
    local r = resp_b + 0.0;
    local denom = o + r;
    if ( denom == 0.0 ) return 0.0;
    return (o - r) / denom;
    }

function ts_gaps(ts: vector of time): vector of double
    {
    local out: vector of double = vector();
    local n = |ts|;
    if ( n < 2 ) return out;
    local i = 1;
    while ( i < n )
        {
        out += interval_to_double(ts[i] - ts[i-1]);
        ++i;
        }
    return out;
    }

function note_ja3_client(ja3: string, client: addr)
    {
    if ( ja3 == "" ) return;
    if ( ja3 !in ja3_clients )
        {
        if ( |ja3_clients| >= ja3_popularity_cap )
            return;
        ja3_clients[ja3] = set();
        }
    add ja3_clients[ja3][client];
    }

function ja3_client_count(ja3: string): count
    {
    if ( ja3 == "" || ja3 !in ja3_clients )
        return 0;
    return |ja3_clients[ja3]|;
    }

function primary_fp(ja3: string, ja4: string): string
    {
    # Prefer JA4 (GREASE-excluded, order-normalised, stable per client).
    # Fall back to JA3 when JA4 is absent (FoxIO plugin not loaded).
    if ( ja4 != "" && ja4 != "-" && ja4 != "(empty)" )
        return ja4;
    if ( ja3 != "" && ja3 != "-" && ja3 != "(empty)" )
        return ja3;
    return "";
    }

function note_fp_client(fp: string, client: addr)
    {
    if ( fp == "" ) return;
    if ( fp !in fp_clients )
        {
        if ( |fp_clients| >= ja3_popularity_cap )
            return;
        fp_clients[fp] = set();
        }
    add fp_clients[fp][client];
    }

function fp_client_count(fp: string): count
    {
    if ( fp == "" || fp !in fp_clients )
        return 0;
    return |fp_clients[fp]|;
    }

function ja4_prefix(ja4: string): string
    {
    # Leading segment before the first "_": proto/TLSver/SNI/#ciph/#ext/ALPN.
    if ( ja4 == "" || ja4 == "-" )
        return "";
    local parts = split_string(ja4, /_/);
    if ( |parts| < 1 )
        return "";
    return parts[0];
    }

function ja4_is_browser_shape(ja4: string): bool
    {
    # Classify by the READABLE JA4 prefix, not the hash. Modern browsers
    # cluster tightly: TLS 1.2/1.3, SNI present ("d"), an HTTP ALPN (h2/h1),
    # and cipher/extension counts in a characteristic range. A fingerprint
    # whose PREFIX matches this envelope is almost certainly a browser even
    # if its exact hash is "rare" (GREASE residue, a new build). This lets us
    # demote rarity for browser-class fingerprints.
    #
    # Prefix layout: t|q  <2-char TLSver>  d|i  <2-digit #ciphers>
    #                <2-digit #extensions>  <2-char ALPN>
    # e.g. "t13d1516h2" = TLS1.3, SNI present, 15 ciphers, 16 exts, h2.
    local p = ja4_prefix(ja4);
    if ( |p| < 10 )
        return F;

    # proto: t (TLS over TCP) — QUIC ("q") browsers exist but we keep this
    # conservative and only classify TCP-TLS browser shapes here.
    if ( p[0] != "t" )
        return F;

    # TLS version chars (positions 1-2): "12" or "13" for modern browsers.
    local ver = p[1:3];
    if ( ver != "12" && ver != "13" )
        return F;

    # SNI present: browsers always send SNI for HTTPS ("d").
    if ( p[3] != "d" )
        return F;

    # ALPN: the last two chars of the prefix. Browsers negotiate HTTP:
    # "h2" or "h1". No-ALPN ("00") is NOT browser-shape (Go/malware stacks).
    local alpn = p[|p| - 2:];
    if ( alpn != "h2" && alpn != "h1" )
        return F;

    return T;
    }

# ------------------------------------------------------------------
# Popularity tracking — the "5-host rule".
# ------------------------------------------------------------------
#
# A destination contacted by more than popular_dest_threshold distinct
# clients across the network is, by definition, not running a single
# isolated C2 implant. We mark it popular and stop tracking it.
#
# This is the most powerful FP killer in the framework: it catches the
# long tail of legitimate niche services (regional news sites, vendor
# portals, CRM/HR/finance SaaS) without requiring any pre-curated list.

function evict_state_for_dest(dest_id: string)
    {
    # Two-pass deletion: collect keys then delete. Modifying a Zeek
    # table while iterating is undefined behaviour.
    local victims: vector of FlowKey = vector();
    for ( k in flow_state )
        if ( k$dest_id == dest_id )
            victims += k;
    for ( i in victims )
        delete flow_state[victims[i]];
    }

function note_dest_client(dest_id: string, client: addr)
    {
    if ( dest_id == "" )
        return;

    # Refresh the popular marker if already known. popular_dests is declared
    # with &write_expire, so this re-add is a WRITE and genuinely extends the
    # lifetime — an actively-used destination stays popular for as long as
    # it's hit. (This only works because of &write_expire: &create_expire
    # would time from insertion and ignore this refresh entirely.)
    if ( dest_id in popular_dests )
        {
        add popular_dests[dest_id];
        return;
        }

    if ( dest_id !in dest_client_count )
        dest_client_count[dest_id] = set();
    add dest_client_count[dest_id][client];

    if ( |dest_client_count[dest_id]| > popular_dest_threshold )
        {
        add popular_dests[dest_id];
        evict_state_for_dest(dest_id);
        # Reclaim memory from the per-dest set — once popular, we no
        # longer care about which clients hit it.
        delete dest_client_count[dest_id];
        }
    }

function is_dest_popular(dest_id: string): bool
    {
    return dest_id in popular_dests;
    }

function dest_client_n(dest_id: string): count
    {
    # A popular (evicted) dest reports a high count so callers treat it as
    # heavily shared even though the per-client set was reclaimed.
    if ( dest_id in popular_dests )
        return popular_dest_threshold + 1;
    if ( dest_id !in dest_client_count )
        return 0;
    return |dest_client_count[dest_id]|;
    }

function fanout_penalty(dest_id: string): double
    {
    local n = dest_client_n(dest_id);
    if ( n < fanout_penalty_start )
        return 0.0;
    # Linear in the number of clients beyond the (start - 1) baseline: the
    # 2nd client subtracts one unit, 3rd two units, etc.
    local over = n - (fanout_penalty_start - 1);
    return (over + 0.0) * fanout_penalty_per_client;
    }

# ----------------------------------------------------------------------
# Web / JA4 helpers.
# ----------------------------------------------------------------------

function is_web_alpn(alpn: string): bool
    {
    if ( alpn == "" || alpn == "-" || alpn == "(empty)" )
        return F;
    local lc = to_lower(alpn);
    return lc in web_alpn_values;
    }

function ja4_cipher_segment(ja4: string): string
    {
    # JA4 format: "t12d1909h2_d83cc789557e_2dae41c691ec"
    # Split on "_" and return the second component (index 1).
    if ( ja4 == "" || ja4 == "-" )
        return "";
    local parts = split_string(ja4, /_/);
    if ( |parts| < 2 )
        return "";
    return parts[1];
    }

function ja4_cipher_ext_tail(ja4: string): string
    {
    # Return the cipher + extension hash tail: the 2nd and 3rd JA4
    # components joined, i.e. everything after the protocol/SNI/ALPN
    # prefix. Example: "t12d1909h2_d83cc789557e_2dae41c691ec"
    #   -> "d83cc789557e_2dae41c691ec".
    # This is the part that reflects the client's TLS stack (cipher suites,
    # extensions, sigalgs) and is stable across SNI-presence and count
    # changes that alter the prefix and the JA3.
    if ( ja4 == "" || ja4 == "-" )
        return "";
    local parts = split_string(ja4, /_/);
    if ( |parts| < 3 )
        return "";
    return fmt("%s_%s", parts[1], parts[2]);
    }

function ja4_alpn_field(ja4: string): string
    {
    # First segment ends with two characters that encode the first
    # offered ALPN. Format: t<ver><sni-flag><ciphers><exts><alpn>
    # Example: "t12d1909h2" → "h2",  "t12d190700" → "00",
    #          "t13d1516h1" → "h1",  "t12i190600" → no alpn-marker (00 omitted)
    if ( ja4 == "" || ja4 == "-" )
        return "";
    local parts = split_string(ja4, /_/);
    if ( |parts| < 1 )
        return "";
    local first = parts[0];
    if ( |first| < 2 )
        return "";
    return first[|first| - 2:];
    }

function note_browser_ja4(ja4: string)
    {
    local cipher = ja4_cipher_segment(ja4);
    if ( cipher == "" )
        return;
    if ( cipher !in browser_ja4_ciphers )
        browser_ja4_ciphers[cipher] = 0;
    browser_ja4_ciphers[cipher] += 1;
    }

function is_browser_ja4(ja4: string): bool
    {
    local cipher = ja4_cipher_segment(ja4);
    if ( cipher == "" )
        return F;
    if ( cipher !in browser_ja4_ciphers )
        return F;
    return browser_ja4_ciphers[cipher] >= browser_ja4_min_observations;
    }


# ----------------------------------------------------------------------
# Host compromise correlation implementations.
# ----------------------------------------------------------------------

function mark_host_compromised(host: addr, ja3: string, ja4: string)
    {
    # Record / refresh compromised state with a fresh expiry.
    compromised_hosts[host] = network_time() + host_compromise_window;

    # Record this flow's fingerprints as TRACKED (seen on a confirmed C2) so a
    # later handoff (same TLS stack, new destination) can be correlated — BUT
    # ONLY if the fingerprint is not network-common. A JA3/JA4 shared by more
    # than a few distinct hosts is a shared OS/library TLS stack (PowerShell,
    # .NET, WinHTTP, a browser) used by both malware and legitimate software.
    # Recording a common fingerprint causes exactly the false positive we must
    # avoid — a later BENIGN flow (e.g. to Yahoo) that happens to share the
    # stack would be escalated. We skip fingerprints seen on >=
    # fingerprint_arm_max_hosts distinct hosts. We do NOT claim the fingerprint
    # is malicious — only that it co-occurred with confirmed C2.
    #
    # NOTE: this gate is ONLY about fingerprint-pivot ARMING. It never
    # affects behavioural C2 detection — a beacon/tunnel/reverse-flow is
    # detected on its timing/PCR/duration regardless of how common its JA3
    # is, because malware can spoof ciphers, use a common backend, or inject
    # into a browser.
    # JA3 is recorded for JA3-keyed intel/reporting, gated on JA3 client
    # rarity. Note JA3's GREASE/order noise makes this rarity weaker, which is
    # exactly why JA4 (below) is the primary tracking key.
    if ( ja3 != "" && ja3 != "-" && ja3 != "(empty)" &&
         ja3_client_count(ja3) < fingerprint_arm_max_hosts )
        tracked_c2_fingerprints[ja3] = host;

    # JA4 is the PRIMARY tracked fingerprint. Skip it when it is a browser
    # SHAPE (prefix envelope) or has been seen on too many hosts — either
    # signals shared benign software that must not be armed. JA4's GREASE-
    # exclusion and order-normalisation make this rarity/shape judgement far
    # more reliable than JA3's.
    if ( ja4 != "" && ja4 != "-" && ja4 != "(empty)" &&
         ! ja4_is_browser_shape(ja4) &&
         ! is_browser_ja4(ja4) &&
         fp_client_count(ja4) < fingerprint_arm_max_hosts )
        {
        tracked_c2_fingerprints[ja4] = host;
        # Also arm the JA4 cipher+extension TAIL (the two hash segments,
        # without the leading protocol/SNI/ALPN prefix). Malware reuses its
        # TLS stack across payloads: a loader and the C2 it hands off to
        # often share the cipher/extension hashes even when SNI presence
        # (i/d) and counts change — which alters the full JA4 and the JA3.
        # The tail survives that. Stored under a "tail:" prefix so it never
        # collides with a full-fingerprint match. Only armed when the JA4 is
        # not a known browser stack.
        local tail = ja4_cipher_ext_tail(ja4);
        if ( tail != "" )
            tracked_c2_fingerprints[fmt("tail:%s", tail)] = host;
        }
    }

function is_host_compromised(host: addr): bool
    {
    if ( host !in compromised_hosts )
        return F;
    # Defensive: &create_expire handles decay, but double-check the window
    # in case the option was lowered at runtime.
    if ( network_time() > compromised_hosts[host] )
        {
        delete compromised_hosts[host];
        return F;
        }
    return T;
    }

function is_tracked_c2_fingerprint(ja3: string, ja4: string, host: addr): bool
    {
    local hit_host: addr;
    local found = F;
    local tail_only = F;

    # Exact full-fingerprint match (JA3 or JA4) — strong, low-FP.
    if ( ja3 != "" && ja3 != "-" && ja3 in tracked_c2_fingerprints )
        { hit_host = tracked_c2_fingerprints[ja3]; found = T; }
    else if ( ja4 != "" && ja4 != "-" && ja4 in tracked_c2_fingerprints )
        { hit_host = tracked_c2_fingerprints[ja4]; found = T; }
    else
        {
        # Cipher+extension TAIL match — catches payload handoffs that reuse
        # the malware TLS stack but change SNI presence / counts (so the full
        # JA4 and the JA3 differ). The tail can collide with benign software
        # sharing a TLS library, so a tail-only hit is treated as WEAKER: it
        # only counts when the originating host is ALREADY compromised. This
        # is what lets us flag the loader->C2 handoff without FPs on benign
        # apps that happen to share a cipher suite.
        local tail = ja4_cipher_ext_tail(ja4);
        if ( tail != "" )
            {
            local tkey = fmt("tail:%s", tail);
            if ( tkey in tracked_c2_fingerprints )
                { hit_host = tracked_c2_fingerprints[tkey]; found = T; tail_only = T; }
            }
        }

    if ( ! found )
        return F;

    # Tail-only matches require the querying host to be compromised.
    if ( tail_only && ! is_host_compromised(host) )
        return F;

    # Network-wide policy: any host's malicious fingerprint counts.
    if ( fingerprint_pivot_network_wide )
        return T;

    # Per-host policy: only escalate if THIS host armed the fingerprint.
    return hit_host == host;
    }

# ----------------------------------------------------------------------
# Threat-intel corroboration implementations.
# ----------------------------------------------------------------------

function note_intel_hit(dest: addr, domain: string, desc: string)
    {
    intel_hit_dests[dest] = desc;
    if ( domain != "" && domain != "-" )
        intel_hit_domains[to_lower(domain)] = desc;
    }

function intel_hit_for_dest(dest: addr): string
    {
    if ( dest in intel_hit_dests )
        return intel_hit_dests[dest];
    return "";
    }

function intel_hit_for_domain(domain: string): string
    {
    if ( domain == "" )
        return "";
    local d = to_lower(domain);
    if ( d in intel_hit_domains )
        return intel_hit_domains[d];
    return "";
    }

# ----------------------------------------------------------------------
# Payload-staging correlator implementations.
# ----------------------------------------------------------------------

function mark_payload_staged(host: addr)
    {
    payload_staged_hosts[host] = network_time() + payload_staged_window;
    }

function is_payload_staged(host: addr): bool
    {
    if ( host !in payload_staged_hosts )
        return F;
    if ( network_time() > payload_staged_hosts[host] )
        {
        delete payload_staged_hosts[host];
        return F;
        }
    return T;
    }

# ----------------------------------------------------------------------
# Exfil escalation ladder implementations.
# ----------------------------------------------------------------------
#
# The ladder is a self-scaling decade rule. Rung 0 means "below the initial
# trip". Rung 1 is the initial trip (exfil_ladder_initial, e.g. 30 MB).
# Rungs >= 2 follow the decade rule starting at exfil_ladder_decade_base
# (e.g. 100 MB): within each order of magnitude there are 9 rungs at
# 1x..9x the decade base (100..900 MB, then 1..9 GB, then 10..90 GB, ...).

function exfil_rung_for(total_upload: count): count
    {
    if ( total_upload < exfil_ladder_initial )
        return 0;
    # At or above the initial trip: rung 1 minimum.
    if ( total_upload < exfil_ladder_decade_base )
        return 1;

    # Walk decades upward, counting the 1x..9x steps crossed. Bounded loop
    # (a handful of decades covers MB..EB), so this always terminates.
    local rung = 1;
    local base = exfil_ladder_decade_base;
    local guard = 0;
    while ( guard < 12 )   # up to ~10^12 * base, far beyond any real transfer
        {
        # Within this decade, steps are at 1*base .. 9*base; the 10th point
        # (10*base) is the base of the next decade.
        local step = 1;
        while ( step <= 9 )
            {
            if ( total_upload >= base * step )
                rung += 1;
            else
                return rung;
            ++step;
            }
        base = base * 10;
        ++guard;
        }
    return rung;
    }

function exfil_rung_threshold(rung: count): count
    {
    if ( rung == 0 )
        return 0;
    if ( rung == 1 )
        return exfil_ladder_initial;
    # Rung 2 -> 1*decade_base, rung 3 -> 2*decade_base, ... every 9 rungs the
    # decade multiplies by 10.
    local idx = rung - 2;          # 0-based index into the decade steps
    local decade = idx / 9;        # which decade (0,1,2,...)
    local step = (idx % 9) + 1;    # 1..9 within the decade
    local base = exfil_ladder_decade_base;
    local d = 0;
    while ( d < decade )
        {
        base = base * 10;
        ++d;
        }
    return base * step;
    }

function human_bytes(n: count): string
    {
    if ( n >= 1000000000000 )
        return fmt("%.1fTB", (n + 0.0) / 1000000000000.0);
    if ( n >= 1000000000 )
        return fmt("%.1fGB", (n + 0.0) / 1000000000.0);
    if ( n >= 1000000 )
        return fmt("%.0fMB", (n + 0.0) / 1000000.0);
    if ( n >= 1000 )
        return fmt("%.0fKB", (n + 0.0) / 1000.0);
    return fmt("%dB", n);
    }
