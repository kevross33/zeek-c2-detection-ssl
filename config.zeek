# C2_SSL — tunable thresholds.
#
# Every threshold in the framework lives here. Operators redef in local.zeek.
# Defaults are tuned for low FP on a noisy 30k-user / 40k-device network.

module C2_SSL;

export {
    # ------------------------------------------------------------------
    # Triage filters — applied before any state is allocated.
    # ------------------------------------------------------------------

    # Connections shorter than this are ignored entirely.
    option min_track_duration: interval = 0.05sec;

    # Min total bytes (orig+resp) before we track a flow.
    option min_track_bytes: count = 200;

    # Connection states we consider "real enough" to analyse.
    option valid_conn_states: set[string] = {
        "SF",    # Normal establish + termination
        "S1",    # Established, not terminated (short window)
        "S2", "S3",
        "RSTO",  # Originator aborted (real traffic exchanged)
        "RSTR",  # Responder aborted (ditto)
    };

    # ------------------------------------------------------------------
    # Beacon detector.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Deployment profile.
    # ------------------------------------------------------------------
    #
    # PRODUCTION (default): tuned for live deployment on a busy network.
    # Calibrated to catch real C2 (false negatives are the priority) while
    # staying tractable at scale. The count/observation gates are jointly
    # satisfiable across the beacon intervals seen in practice (see the
    # note on beacon_alert_min_count below).
    #
    # SANDBOX: relaxed time/sample gates for SHORT offline PCAPs from
    # malware-traffic-analysis or sandboxes — alert on as few as 8
    # connections, 5 minutes of observation. Load ONLY for PCAP replay:
    #   @load c2-detection-ssl/sandbox
    #
    # All individual thresholds below can still be redef'd to override
    # the profile defaults — this is just a convenience starting point.
    #
    # DEFAULT IS PRODUCTION. The values below are calibrated for a live
    # sensor on a large (tens-of-thousands of endpoints) network, biased
    # toward catching real C2 (false negatives are the priority) while
    # staying tractable at scale. For replaying short offline PCAPs (a few
    # minutes of capture), load the sandbox profile which relaxes the
    # time/sample gates:  @load c2-detection-ssl/sandbox
    type DeploymentProfile: enum { SANDBOX_PROFILE, PRODUCTION_PROFILE };
    option deployment_profile: DeploymentProfile = PRODUCTION_PROFILE;

    # ------------------------------------------------------------------
    # Direction / scope — OUTBOUND C2 ONLY.
    # ------------------------------------------------------------------
    #
    # This package detects OUTBOUND command-and-control from compromised
    # INTERNAL clients (internal originator -> external responder). It does
    # NOT analyse inbound connections: external -> internal flows are things
    # like RDP brute-force, inbound scanning, or someone connecting TO an
    # internal service, which are a different problem handled elsewhere.
    # Without this filter, inbound RDP-over-TLS (regular keep-alives, a
    # self-signed server cert, no SNI) trips the beacon detector — a false
    # positive, because the "beacon" is really an external host hammering an
    # internal RDP server.
    #
    # Internal is determined by Zeek's Site::local_nets (if the operator has
    # configured it) OR the c2_internal_nets set below, whichever matches —
    # so the package works whether or not local_nets is set on the sensor.

    # Master switch. When T, only outbound (internal->external) flows are
    # analysed. Set F only if you specifically want to analyse inbound or
    # east-west flows (not recommended for the current C2 scope).
    option c2_require_outbound: bool = T;

    # Networks considered INTERNAL for the direction test, in addition to
    # anything in Site::local_nets. Defaults cover RFC1918 and CGNAT. If your
    # internal estate uses public IP space, add those ranges here.
    option c2_internal_nets: set[subnet] = {
        10.0.0.0/8,
        172.16.0.0/12,
        192.168.0.0/16,
        100.64.0.0/10,     # CGNAT (RFC 6598)
        169.254.0.0/16,    # link-local
        127.0.0.0/8,       # loopback
        [fc00::]/7,        # IPv6 unique-local
        [fe80::]/10,       # IPv6 link-local
    };

    # Also treat internal->internal (east-west) as out of scope by default:
    # the current focus is outbound C2 egress, not lateral tunnels. When F,
    # a flow whose responder is also internal is dropped. Set T to also
    # analyse east-west flows (e.g. to catch an internal pivot/relay), at the
    # cost of more surface. Only consulted when c2_require_outbound = T.
    option c2_analyse_east_west: bool = F;

    # Minimum connections before we compute periodicity.
    option beacon_min_count: count = 6;

    # Hard floor for any beacon alert to fire.
    #
    # Calibrated for production: high enough to reject coincidental
    # periodicity, low enough that a beacon of ANY interval can actually
    # reach it within the observation window. NOTE the interaction with
    # beacon_min_observation_duration: requiring, say, 30 samples within a
    # 30-minute window would make any beacon slower than ~60s impossible
    # to detect (a false-negative hole). 12 samples over 15 minutes admits
    # beacons up to ~75s interval, and slower beacons still qualify via the
    # resumption-pinned path (pinning_min_count) which does not require the
    # full sample count. Raise toward 20-30 ONLY if a specific noisy source
    # demands it, and raise the observation window in step.
    option beacon_alert_min_count: count = 12;

    # Minimum wall-clock duration that the flow must have been observed
    # for before any beacon alert can fire. This is the dominant
    # time-based confidence gate: even a perfect-shape beacon with 50
    # samples in 90 seconds (a sandbox replay) will not alert until it
    # has been seen for at least this long. It catches the "web app
    # generating a handful of keep-alives in a few minutes" FP shape.
    #
    # Production default 15 min: long enough to filter transient app
    # chatter, short enough that a genuine minutes-interval beacon clears
    # it. Must stay consistent with beacon_alert_min_count (see note above)
    # so the two gates are jointly satisfiable across the beacon intervals
    # you actually see.
    option beacon_min_observation_duration: interval = 15min;

    # Rolling window cap — how many recent connections we keep per flow.
    option beacon_window_size: count = 50;


    # Max jitter (MAD/median) for a non-pinned flow to qualify as a
    # TIGHT beacon. 0.30 = 30% deviation. Classic beacons sit < 0.15.
    option beacon_max_jitter: double = 0.30;

    # Upper jitter bound for the JITTERED beacon tier. Modern C2
    # (Cobalt Strike, Sliver, Havoc, Brute Ratel) deliberately jitters
    # beacon intervals — CS default is 0-37%, operators set 20-50% —
    # specifically to defeat tight-periodicity detection. Flows between
    # beacon_max_jitter and this bound are still pursued as probable
    # beacons (with a higher sample requirement and reduced but non-zero
    # time score) rather than discarded. This is the primary defence
    # against jitter-based evasion. Raising it catches more evasive C2
    # at the cost of more marginal flows to score.
    option beacon_jittered_max: double = 0.60;

    # Minimum sample count for a JITTERED (not tight) beacon to alert.
    # Higher than beacon_alert_min_count because a jittered flow needs
    # more observations to distinguish real timer-with-jitter from
    # coincidental spacing. Only applies to the jittered tier.
    option beacon_jittered_min_count: count = 12;

    # Jitter above which a NON-PINNED flow is conclusively abandoned as
    # "not a beacon" (memory reclaim). Set above beacon_jittered_max so
    # the jittered tier is never abandoned prematurely. Only flows beyond
    # even the jittered band, unpinned, and well-sampled are dropped.
    option beacon_chaotic_threshold: double = 0.70;

    # ------------------------------------------------------------------
    # Timing-symmetry (Bowley skewness) — complements the jitter/dispersion
    # measure above. Jitter (MAD/median) asks "how spread are the intervals?";
    # skewness asks "are they spread SYMMETRICALLY?". A genuine beacon — even
    # a deliberately-jittered one — has a symmetric inter-arrival distribution
    # (skew ~ 0). Bursty human/app traffic that merely clusters tends to have
    # a lopsided (high-magnitude) skew. This is the approach RITA uses.
    # ------------------------------------------------------------------

    # Enable the Bowley-skewness symmetry term. When on, a confirmed beacon's
    # time_score is nudged up when its interval distribution is symmetric and
    # nudged down when it is strongly asymmetric.
    option beacon_skew_enabled: bool = T;

    # Minimum number of interval samples before the skewness term is applied.
    # Bowley skew is noisy on small samples, so we require a healthy window
    # (quartiles need enough points to be stable). Below this, skew is ignored
    # and scoring falls back to the jitter tiers alone.
    option beacon_skew_min_samples: count = 10;

    # |skew| at or below this is considered "symmetric" and earns the full
    # symmetry bonus. A perfect beacon sits near 0.
    option beacon_skew_symmetric_max: double = 0.30;

    # |skew| at or above this is considered strongly asymmetric (lopsided
    # timing tail) and earns the symmetry penalty.
    option beacon_skew_asymmetric_min: double = 0.60;

    # Confidence added to a beacon whose timing is symmetric (|skew| low).
    # Small — this corroborates regularity, it does not create detections.
    option beacon_skew_symmetric_bonus: double = 0.10;

    # Confidence subtracted from a beacon whose timing is strongly asymmetric.
    # Applied only to NON-pinned beacons: resumption pinning is itself a
    # C2-defining signal that should not be second-guessed by timing shape
    # (a pinned channel with sleeps can be legitimately skewed), and honouring
    # the false-negative priority means we don't penalise a pinned beacon.
    option beacon_skew_asymmetric_penalty: double = 0.15;

    # Connections closer than this are collapsed into one "burst".
    option beacon_burst_collapse: interval = 1sec;

    # Gap longer than this is a "sleep" event.
    option beacon_sleep_threshold: interval = 30min;

    # Session-resumption pinning thresholds.
    # A resumption-pinned flow (many TLS session resumptions to the same
    # destination) is one of the strongest C2 signals, so we do NOT demand
    # a large count here — that would blind us to exactly the beacons we
    # most want. 8 resumptions is enough to distinguish a pinned C2 channel
    # from incidental resumption while still catching it early. The pinned
    # path is also how slower beacons (that can't reach beacon_alert_min_count
    # within the observation window) still alert.
    option pinning_min_count: count = 8;
    option pinning_min_ratio: double = 0.80;

    # Strong-pinning threshold: the sample count at which resumption
    # pinning is considered strong enough on its own to satisfy the
    # observation-duration gate (see the gate in detect.zeek). A flow that
    # has resumed the same TLS session this many times, at pinning_min_ratio
    # or above, is beacon-shaped regardless of how short the capture window
    # is. Benign resumed web traffic (chunked media, some CDNs) can reach
    # high resumption counts too, but it carries h2 ALPN and valid certs,
    # so the web-ALPN and valid-cert suppressors keep it below threshold —
    # this only lets the gate be bypassed, it does not force an alert.
    # Set high enough that a couple of coincidental resumptions never
    # qualifies; 20 is well clear of normal short-lived pinning.
    option pinning_strong_count: count = 20;

    # ------------------------------------------------------------------
    # Beacon-exfil / bulk-transfer detector.
    # ------------------------------------------------------------------
    #
    # Fires SSL_BEACON_EXFIL when a flow that ALREADY qualifies as a beacon
    # (this detector runs only after the beacon gate has passed) also moves
    # a large, directionally-skewed volume of data. The beacon context is
    # what makes a large transfer suspicious: bulk transfer on its own is
    # far too common (backups, updates, sync, video) to alert on, but a
    # low-jitter / resumption-pinned beacon to a suspect-cert destination
    # that suddenly moves megabytes is the classic "beacon then exfil" or
    # "beacon then payload/tooling delivery" pattern.
    #
    # Direction:
    #   upload-heavy  (orig >> resp) -> likely EXFILTRATION (data leaving)
    #   download-heavy(resp >> orig) -> likely PAYLOAD / tooling staging
    # Both fire; upload is weighted slightly higher (data loss is worse).

    # Minimum bytes in the dominant direction before a beacon flow is
    # considered a bulk transfer. 5 MB is well above beacon keep-alive
    # volume (a 32s beacon moving 2 KB/beat for an hour is ~230 KB) while
    # low enough to catch meaningful exfil/staging early.
    option exfil_min_bytes: count = 5000000;

    # Minimum |PCR| skew for the transfer to count as one-directional bulk
    # movement rather than balanced interactive traffic. 0.60 means one
    # side is at least ~4x the other.
    option exfil_min_pcr_skew: double = 0.60;

    # Confidence for a beacon-exfil alert. High because the beacon gate has
    # already established the destination is C2-shaped; the bulk transfer
    # is a severity escalation, not a fresh detection from scratch.
    option exfil_base_confidence: double = 0.80;

    # Extra confidence when the bulk direction is UPLOAD (exfiltration),
    # added on top of exfil_base_confidence.
    option exfil_upload_bonus: double = 0.10;

    # When T, a beacon flow that also trips the exfil test emits a SEPARATE
    # SSL_BEACON_EXFIL alert (recommended — distinct severity for the SOC).
    # When F, it only adds a large_transfer indicator to the beacon alert.
    option exfil_separate_alert: bool = T;

    # ------------------------------------------------------------------
    # Exfiltration escalation ladder (SSL_C2_EXFIL_ESCALATION).
    # ------------------------------------------------------------------
    #
    # Layered ON TOP of SSL_BEACON_EXFIL (which fires once at exfil_min_bytes,
    # ~5 MB, as the first "something is leaving"). This ladder tracks the
    # CUMULATIVE UPLOAD on a CONFIRMED C2 channel and re-fires at escalating
    # volume milestones so the SOC sees a large or ongoing exfiltration grow
    # in real time. Upload-only — downloads are payload-staging, handled
    # separately. Only ever evaluated inside a confirmed beacon/tunnel, so a
    # benign large upload (backup, cloud sync, video) — never a confirmed C2 —
    # cannot reach it.
    #
    # The ladder is a self-scaling DECADE rule: an initial trip at
    # exfil_ladder_initial, then within each order of magnitude it fires at
    # ten evenly-spaced points (step = decade / 10):
    #   30 MB (initial); 100,200..900 MB; 1,2..9 GB; 10,20..90 GB; ...
    # Each rung fires at most once (highest rung crossed is tracked per flow).
    # This never spams: as volume grows, alerts get proportionally sparser.

    option exfil_ladder_enabled: bool = T;

    # Initial cumulative-upload trip for the escalation ladder.
    option exfil_ladder_initial: count = 30000000;   # 30 MB

    # The decade ladder starts here; below this, only the initial trip fires.
    # First full decade base (fires at 1x..9x this within the decade).
    option exfil_ladder_decade_base: count = 100000000;  # 100 MB

    # Confidence for an exfil-escalation alert. High — the C2 gate has already
    # confirmed the channel; this is a severity escalation on a known-bad flow.
    option exfil_ladder_confidence: double = 0.90;

    # Slow-drain re-fire: while a confirmed C2 is ACTIVELY exfiltrating and
    # already past the initial trip, re-emit at most this often even if no new
    # volume rung was crossed — so a continuous slow drain still re-alerts.
    # Set to 0sec to disable the time-based re-fire (volume rungs only).
    option exfil_reflag_interval: interval = 10min;

    # ------------------------------------------------------------------
    # Host compromise correlation (multi-C2 / payload-transition tracking).
    # ------------------------------------------------------------------
    #
    # Once a host produces a HIGH-confidence C2 alert, an intrusion is rarely
    # a single flow — it is a chain (loader -> Cobalt Strike -> recon -> exfil
    # -> ransomware). This block lets a confirmed detection inform subsequent
    # analysis of the SAME host, catching payload transitions (e.g. BumbleBee
    # handing off to Cobalt Strike on a different destination / SNI).
    #
    # Design is deliberately CONSERVATIVE: this state only ESCALATES flows
    # that are ALREADY independently suspicious. It never turns a benign flow
    # into an alert. Benign browsing from a flagged host stays quiet.

    # A host enters "compromised" state only when it produces an alert at or
    # above this confidence. Set HIGH (0.90) so only near-certain detections
    # arm the escalation — a marginal 0.70 alert must not cascade.
    option host_compromise_entry_confidence: double = 0.90;

    # How long a host stays in compromised state after its last high-confidence
    # alert. Shorter = more conservative (less stale state). Refreshed on each
    # new qualifying alert.
    option host_compromise_window: interval = 6hr;

    # Confidence added to a NEW flow from a compromised host — but ONLY when
    # that flow already scores at/above host_escalation_floor on its own. This
    # lifts borderline-suspicious flows over the line; it does nothing to
    # benign flows.
    option host_compromise_bonus: double = 0.15;

    # Minimum independent (pre-bonus) confidence a flow must reach before the
    # host_compromise_bonus or fingerprint_pivot_bonus can apply. Guarantees
    # escalation only touches already-suspicious flows.
    option host_escalation_floor: double = 0.45;

    # ------------------------------------------------------------------
    # Fingerprint-pivot correlation.
    # ------------------------------------------------------------------
    #
    # Malware reuses its TLS stack: a loader and the C2 it hands off to often
    # share a JA3/JA4 client fingerprint even when the destination and SNI
    # change. We record fingerprints seen on CONFIRMED (>= entry confidence)
    # C2 flows and give a bonus when the same host reuses one against a new
    # destination — provided the new flow is already independently suspicious.

    # Bonus for a flow whose JA3/JA4 matches a fingerprint previously seen on a
    # high-confidence C2 alert. Subject to host_escalation_floor.
    option fingerprint_pivot_bonus: double = 0.20;

    # Track malicious fingerprints network-wide (any host), not just per-host.
    # When T, a fingerprint seen on a confirmed C2 on host A also escalates a
    # suspicious flow using it on host B. Conservative: still requires the
    # flow to be independently suspicious. Off = per-host correlation only.
    option fingerprint_pivot_network_wide: bool = T;

    # How long a recorded malicious fingerprint remains armed.
    option fingerprint_pivot_window: interval = 12hr;

    # Maximum number of distinct hosts a JA3/JA4 may be seen on before it is
    # considered too common to ARM as a malicious-pivot fingerprint. This is
    # separate from (and stricter than) common_ja3_client_floor, which
    # governs scoring penalties. The rationale: a fingerprint seen on more
    # than a few hosts is shared software (PowerShell, .NET, WinHTTP, a
    # browser) and is a poor handoff indicator — arming it would escalate a
    # later BENIGN flow that merely shares the stack. IMPORTANT: this only
    # affects fingerprint-PIVOT arming. It never suppresses a behavioural C2
    # detection — malware can spoof JA3, use a common backend, or inject
    # into a browser, so timing/PCR/duration detection is independent of
    # fingerprint commonality.
    option fingerprint_arm_max_hosts: count = 3;

    # ------------------------------------------------------------------
    # SNI / cert masquerade guard.
    # ------------------------------------------------------------------
    #
    # Domain-fronting-adjacent evasion: a flow presents a first-party SNI
    # (e.g. client.wns.windows.com) on attacker infrastructure. Withhold the
    # allowlist free pass ONLY when the certificate is visible and demonstrably
    # does NOT cover the claimed SNI and does not validate. A genuine
    # first-party connection always has a valid, matching cert, so this never
    # fires on real Microsoft/O365 traffic.
    option masquerade_guard_enabled: bool = T;

    # ------------------------------------------------------------------
    # Emerging / pre-beacon C2 (early warning).
    # ------------------------------------------------------------------
    #
    # Detects the FIRST-CONTACT shape of a C2 implant before it settles into
    # periodic beaconing (the initial metadata check-in / staging phase). This
    # is where fast intrusions live — initial-access-to-handoff is now measured
    # in seconds. Deliberately low base confidence: BELOW alert_confidence, so
    # ------------------------------------------------------------------
    # Emerging / first-contact tracking (INTERNAL STATE ONLY).
    # ------------------------------------------------------------------
    #
    # The first contact of a possible C2 implant (suspect/self-signed cert,
    # or no-SNI + no-ALPN Go stack, to a rare destination) is recorded as an
    # internal marker on the flow. It NEVER produces an alert on its own — a
    # single first-contact flow is the weakest possible C2 signal and firing
    # on it generates unacceptable false positives (Azure, Cloudflare, RDP to
    # internal DCs all look like this). The marker only contributes a small
    # confidence bonus IF the flow later confirms as a real beacon / tunnel /
    # reverse-flow, i.e. once behaviour over time corroborates it. This keeps
    # the value of witnessing the staging phase without the FP noise.
    option emerging_c2_enabled: bool = T;

    # Confidence bonus applied to a confirmed beacon/tunnel/reverse-flow that
    # was previously marked with the emerging first-contact shape. Small — it
    # is corroboration, not a detection in its own right.
    option emerging_shape_bonus: double = 0.10;

    # ------------------------------------------------------------------
    # Threat-intel corroboration.
    # ------------------------------------------------------------------
    #
    # Bonus applied to a CONFIRMED behavioural detection (beacon / tunnel /
    # reverse-flow) whose destination IP or SNI also matches an operator
    # Intel-framework hit (intel.log). An intel hit NEVER fires an alert on
    # its own — it only strengthens a detection the behaviour already earned.
    # This makes an intel-listed beacon page with high confidence while a
    # bare intel lookup with no C2 behaviour stays silent.
    option intel_corroboration_bonus: double = 0.20;
    option intel_corroboration_enabled: bool = T;

    # ------------------------------------------------------------------
    # Payload-staging correlator (in-TLS download burst -> stage transition).
    # ------------------------------------------------------------------
    #
    # Inside a CONFIRMED beacon/tunnel, watch for a DOWNLOAD burst (server->
    # client) whose size is consistent with an executable/payload being
    # pulled — a tasking or a staged next-stage tool (e.g. Sliver) delivered
    # over the existing TLS channel. We cannot see the bytes (encrypted), so
    # we infer it from the flow's download size profile.
    #
    # DISCIPLINE (this is a SECONDARY signal, never a detector):
    #   * The burst is only considered on an ALREADY-CONFIRMED C2 flow. A
    #     burst during connection setup / "hello" / before confirmation does
    #     NOT count — that would be FP-prone. The confirmed-C2 gate is also
    #     the entire FP safety net: benign software updates over TLS (Windows
    #     Update, browsers, AV) are NEVER confirmed C2 (valid cert, popular
    #     dest, h2 ALPN, allowlisted), so a burst on them is never recorded.
    #   * Download direction ONLY — uploads are exfil (SSL_BEACON_EXFIL owns
    #     that); we never conflate the two.
    #   * The burst NEVER alerts on its own. It (a) annotates the current C2's
    #     evidence (payloads=N, sizes=...) and (b) sets a SHORT-lived host
    #     marker. A NEW channel that appears within the marker window and then
    #     INDEPENDENTLY confirms as C2 gets a small corroboration + a
    #     stage_transition indicator. If no new channel confirms, nothing
    #     happens.

    option payload_staging_enabled: bool = T;

    # Absolute floor: a single download exchange at/above this size, inside a
    # small-cadence C2, is treated as a payload/tasking burst. Set to a
    # cautious normal-minimum-malware size — real payloads are usually larger,
    # and we would rather miss a tiny one than over-flag. ~20 KB.
    option payload_min_download_bytes: count = 20000;

    # Tiny-beacon relative path: if the channel's baseline heartbeat is very
    # small, a download this many times larger than the baseline median is
    # "huge" relative to the channel and flagged too — but at LOWER
    # confidence (payload_staged_bonus_weak). Guards against calling a normal
    # keep-alive a payload while still catching small payloads on tiny beacons.
    option payload_baseline_multiple: double = 10.0;

    # Minimum absolute size for the relative (tiny-beacon) path, so we never
    # flag a few-hundred-byte "burst" as a payload no matter the ratio.
    option payload_relative_min_bytes: count = 4000;

    # How long the host-level payload-staged marker persists. Deliberately
    # SHORT: a genuine execute-then-transition is quick. Waiting longer means
    # a later new channel could be anything unrelated (a different backdoor,
    # a PowerShell channel) and the link would be unreliable. < 1 minute.
    option payload_staged_window: interval = 45sec;

    # Corroboration bonus added to a NEW channel that INDEPENDENTLY confirms
    # as C2 within payload_staged_window of a payload burst on the same host.
    # Small — it strengthens a detection the behaviour already earned.
    option payload_stage_transition_bonus: double = 0.15;

    # Confidence weighting for the absolute vs relative (tiny-beacon) burst
    # when annotating the current C2. Evidence only; does not change whether
    # the current C2 fired.
    option payload_staged_bonus: double = 0.05;
    option payload_staged_bonus_weak: double = 0.02;

    # Max number of individual payload-download bursts listed in the alert
    # details (each as "<size>@<approx-secs-in>"). Beyond this, only a
    # "(+N more, total X)" rollup is shown, so a long-lived beacon that is
    # frequently updated cannot produce an unbounded details string. Reporting
    # only — no effect on detection.
    option payload_burst_detail_cap: count = 12;


    # Cooldown between alerts for the same flow.
    option alert_cooldown: interval = 30min;

    # ------------------------------------------------------------------
    # Popularity-based eviction (the "5-host rule").
    # ------------------------------------------------------------------
    #
    # Once more than this many distinct clients in the network have
    # connected to a destination (lowercased SNI or IP), it is marked
    # "popular" and:
    #   - any existing flow_state for it is deleted
    #   - future connections to it are not tracked at all
    #
    # Rationale: real C2 in a network is overwhelmingly likely
    # to involve very few infected clients (often one). Legitimate
    # destinations have many clients. A threshold of 5 catches both
    # small (single-malware) and double-infection cases while excluding
    # any moderately-used legitimate service.
    #
    # Note: this is independent of the M365 / safe-suffix bypass — those
    # don't even reach popularity tracking. This rule catches the long
    # tail of legitimate niche services that aren't pre-allowlisted.
    option popular_dest_threshold: count = 3;

    # ------------------------------------------------------------------
    # Fan-out prevalence gating (the "new C2 is 1:1" principle).
    # ------------------------------------------------------------------
    #
    # A newly-appearing C2 is almost always ONE internal host talking to ONE
    # external destination (1:1). A destination contacted by MANY internal
    # hosts is a shared service (cloud API, CDN, WebRTC/telemetry endpoint) —
    # by definition not a single-host C2. Live traffic on a large estate is
    # dominated by these N:1 fan-out flows to AWS/Azure/GCP, which is the main
    # false-positive source. Rather than a single hard cutoff, confidence is
    # scaled DOWN as the distinct-client count rises, so a 1:1 flow is scored
    # normally, a 2-3:1 flow must clear a higher bar, and a high-fan-out flow
    # is dropped. This accepts that a widespread infection (many hosts -> one
    # C2) will be under-scored — the package targets NEW C2 emergence (1:1),
    # not triage of an already-saturated network.

    # Distinct internal-client counts at/above which the fan-out penalty
    # applies, and the hard "definitely a shared service" cutoff. Defaults are
    # conservative: a 1:1 flow is never touched, and the hard drop only
    # triggers at a clear fan-out (many hosts to one dest) that cannot be a
    # single-host C2. Raise fanout_penalty_start / lower fanout_hard_drop only
    # if fan-out false positives persist.
    option fanout_penalty_start: count = 3;   # 3+ clients: begin penalising
    option fanout_hard_drop:     count = 6;   # 6+ clients: not single-host C2

    # Confidence penalty PER client above (fanout_penalty_start - 1). Kept
    # modest so a strong beacon seen on a couple of hosts (e.g. a small
    # cluster of early infections) can still surface on its behaviour.
    option fanout_penalty_per_client: double = 0.12;

    # ------------------------------------------------------------------
    # Immediate-upload rejection (C2 beacons low-and-slow first).
    # ------------------------------------------------------------------
    #
    # A real C2 channel establishes with low-and-slow keep-alive/beacon
    # traffic and only later moves bulk data (tasking, exfil, payload). A flow
    # whose activity is dominated by upload from the very start — with no
    # preceding beacon/keep-alive cadence — is a transfer (WebRTC/media
    # upload, backup, sync), not C2. The live reverse-asymmetry false
    # positives are exactly this: MSEdge WebRTC / health-app uploads to cloud.
    # We reject an upload-shaped flow UNLESS it was preceded by a genuine
    # beacon/keep-alive phase.

    option reject_immediate_upload: bool = T;

    # A flow is "upload-dominant from the start" if its upload PCR is at least
    # this and it has NOT yet shown beacon/tunnel cadence. Such a flow is not
    # treated as C2 (reverse-flow/tunnel) until/unless cadence appears.
    option immediate_upload_pcr: double = 0.30;

    # Minimum bytes before the immediate-upload test applies (tiny flows are
    # judged on cadence alone, not this shortcut).
    option immediate_upload_min_bytes: count = 100000;   # 100 KB

    # ------------------------------------------------------------------
    # (Short-session eviction was removed: keying eviction on a per-flow
    # duration/sample floor raced beacon formation — a forming beacon always
    # passes through a low-sample, modest-duration phase, so early eviction
    # could delete real beacons before they crossed threshold. The existing
    # track_abandon_after path already safely reclaims stale non-beacon flows
    # after a long window without that risk.)
    # ------------------------------------------------------------------

    # How long a destination stays marked "popular" after the last hit.
    # Refreshed on every connection, so an actively-used popular site
    # stays popular indefinitely.
    const popular_dest_expiry: interval = 24hr &redef;

    # ------------------------------------------------------------------
    # Active abandonment (stop tracking flows that aren't beacons).
    # ------------------------------------------------------------------
    #
    # After this many real-time minutes of tracking, if the flow has
    # fewer than beacon_min_count samples it is abandoned. Most browsing
    # is one-shot or low-frequency; abandoning frees memory quickly.
    option track_abandon_after: interval = 1hr;

    # early_jitter_sample_floor: minimum samples before the abandonment
    # check runs. A flow is only dropped as "not a beacon" once it has
    # this many samples AND its jitter exceeds beacon_chaotic_threshold
    # AND it is not resumption-pinned. This is deliberately conservative
    # so jittered C2 (30-60% jitter) is retained and scored, not dropped.
    option early_jitter_sample_floor: count = 10;

    # DEPRECATED: superseded by beacon_chaotic_threshold. Retained for
    # backward compatibility with existing local.zeek redefs. No longer
    # referenced by the detection logic.
    option early_jitter_threshold: double = 0.50;

    # ------------------------------------------------------------------
    # Grace period — don't enter heavy state on first-N connections.
    # ------------------------------------------------------------------
    #
    # A (client, dest, ja3) flow accumulates a lightweight counter for
    # the first flow_grace_count connections without populating the
    # rolling window. Most legitimate browsing is one or two connections
    # to a destination — those never need beacon analysis at all.
    # Setting this to 0 disables the grace period entirely.
    option flow_grace_count: count = 3;

    # ------------------------------------------------------------------
    # Connection-rate sanity at alert time.
    # ------------------------------------------------------------------
    #
    # Even a perfectly periodic flow with intervals greater than this
    # will not fire as a fast periodic beacon — a user checking a
    # service every 8 hours is not what we want to alert on as a beacon,
    # even if the cadence is very regular.
    option beacon_max_median_interval: interval = 6hr;

    # ------------------------------------------------------------------
    # Browser / common-fingerprint awareness (purely behavioural, no
    # signature matching). When the JA3 client fingerprint is shared by
    # many distinct hosts in the network, the originator is almost
    # certainly running a stock browser / OS update agent / standard
    # mail client. Combined with hitting any moderately-popular
    # destination, this strongly suggests legitimate traffic.
    # ------------------------------------------------------------------
    #
    # When the PRIMARY fingerprint (JA4 when present, else JA3) has been seen
    # from at least this many distinct clients in the network, it is treated
    # as a "common fingerprint". (Name kept as common_ja3_* for config
    # compatibility; it now applies to the JA4-preferred primary fingerprint,
    # whose GREASE-stability makes the count meaningful.)
    option common_ja3_client_floor: count = 10;

    # Confidence penalty applied when the primary fingerprint is common (or a
    # browser JA4 shape) AND the destination is popular at >=50% of
    # popular_dest_threshold. A defence against the "single host hits a site
    # that a few other hosts also hit" edge case (just below the popularity
    # rule). Only lowers an already-marginal score; never overrides a strong
    # behavioural beacon.
    option common_ja3_popularity_penalty: double = 0.30;

    # ------------------------------------------------------------------
    # Web-traffic detection (ALPN-based and JA4-derived).
    # ------------------------------------------------------------------
    #
    # Real C2 over TLS rarely negotiates HTTP/2 or HTTP/1.1 ALPN —
    # malware tooling using stock TLS libraries seldom sets ALPN, and
    # bespoke C2 protocols never do. Browsers, IoT devices doing real
    # HTTPS, and SaaS/web-app clients almost always do. Tracking ALPN
    # across the flow lifetime is therefore one of the strongest
    # discriminators between C2 and benign web traffic.
    #
    # Note that resumed TLS sessions don't carry a fresh ALPN
    # negotiation in ssl.log, so we capture ALPN at first sight and
    # remember it for the remainder of the flow.
    #
    # Set of ALPN values that indicate the flow is genuine web traffic.
    option web_alpn_values: set[string] = {
        "h2",       # HTTP/2 — overwhelmingly the most common
        "http/1.1", # legacy web
        "http/1.0", # very old web
        "h3",       # HTTP/3 (rare on 443/TCP but possible)
        "h2c",      # HTTP/2 cleartext (test environments)
    };

    # When a flow has shown one of the above ALPN values at any point
    # in its lifetime, this penalty is applied. 0.50 effectively
    # suppresses unless other strong indicators are present.
    option web_alpn_penalty: double = 0.50;

    # JA4 second segment (cipher hash) — when this segment has been
    # observed network-wide alongside an HTTP ALPN at least
    # browser_ja4_min_observations times, the client cipher set is
    # treated as "browser-capable" and an additional penalty applies.
    # This catches Chrome/Edge/Firefox JA4s that present the same
    # cipher set across all destinations, even when a particular
    # connection happens to omit ALPN (resumed sessions).
    option browser_ja4_min_observations: count = 5;
    option browser_ja4_penalty: double = 0.30;

    # ------------------------------------------------------------------
    # PCR-based web-download suppression.
    # ------------------------------------------------------------------
    #
    # A flow with an extremely negative PCR (mostly download, very
    # little upload) is consistent with content delivery and very
    # unlikely to be C2 — even RATs always upload some command
    # results. fbcdn.net and similar CDNs hit this threshold easily.
    option max_download_pcr: double = -0.95;
    option pure_download_penalty: double = 0.40;

    # ------------------------------------------------------------------
    # Beacon payload-size profile (C2 check-in vs bulk transfer).
    # ------------------------------------------------------------------
    #
    # A true C2 check-in is a SHORT, tightly-bound exchange: the implant
    # asks "any tasks?" and gets a small answer. The per-connection payload
    # sizes are small and bounded. Legitimate no-SNI / self-signed flows
    # that would otherwise look beacon-like — firmware updates, software
    # update pings, file drops, telemetry blobs — instead show BULK sizing:
    # large, sustained response payloads. Using the payload-size profile
    # cleanly separates the two.
    #
    # If the median response payload across the flow exceeds this many bytes,
    # the flow is treated as a bulk/transfer shape rather than a beacon
    # check-in, and beacon_bulk_payload_penalty is applied. Set high enough
    # to allow a chunky-but-real beacon (task delivery can be a few KB) but
    # low enough to catch firmware/update/file-drop bulk. A typical CS/beacon
    # heartbeat is well under 1 KB; a firmware chunk is tens of KB+.
    option beacon_max_checkin_payload: count = 4096;

    # Penalty applied when the flow's payload-size profile looks like bulk
    # transfer rather than a small C2 check-in. Not a hard drop — a strongly
    # pinned/tight beacon can still surface — but it removes the large FP
    # class of benign no-SNI bulk downloads that are periodic by coincidence
    # (update pollers, CDN chunk fetchers).
    option beacon_bulk_payload_penalty: double = 0.35;

    # Only apply the bulk-payload penalty when the flow lacks the corroborating
    # signals that would make a large-payload beacon genuinely suspicious
    # (suspect issuer, bad validation). A self-signed periodic flow with big
    # payloads is more interesting than a valid-cert one, so we do not penalise
    # the former as heavily. When T, the penalty is skipped if the flow already
    # has a suspect/self-signed cert.
    option beacon_bulk_penalty_skip_if_suspect_cert: bool = T;

    # ------------------------------------------------------------------
    # Certificate subject vs SNI mismatch.
    # ------------------------------------------------------------------
    #
    # When the certificate's CN (or any SAN) does not share a suffix
    # with the SNI, the operator has reused a cert for a different
    # hostname — extremely common in custom C2 (`CN=jquery.com` for
    # `zuppohealth.com`, `CN=localhost` for raw IPs, etc.). This is
    # one of the strongest single-signal C2 indicators.
    option cert_sni_mismatch_bonus: double = 0.25;

    # ------------------------------------------------------------------
    # Valid-cert-with-matching-SAN suppression.
    # ------------------------------------------------------------------
    #
    # When a flow has BOTH:
    #   * Zeek-validated CA chain (validation_status == "ok"), and
    #   * Zeek's SAN-aware sni_matches_cert == "T"
    # then we are very probably looking at a legitimate service. Real
    # C2 doing this would need a publicly-issued cert specifically for
    # the SNI being used — possible (Let's Encrypt) but rare, and even
    # then cheap-to-detect via destination popularity / single-client
    # indicators. Apply a penalty so this case has to clear a higher
    # bar (e.g. needs explicit suspicion signals like an unusual ALPN,
    # upload-dominant PCR, or strange beacon shape).
    option valid_cert_match_penalty: double = 0.30;

    # Reduced valid-cert penalty for beacons that are resumption-PINNED
    # or TIGHT-jittered. These are strong C2-defining behaviours, and a
    # free-CA certificate (Let's Encrypt / ZeroSSL) is trivial to obtain —
    # CobaltStrike and Sliver over Let's Encrypt is a dominant real-world
    # pattern. A cheap valid cert must not suppress a strong behavioural
    # beacon below threshold, so the penalty is much smaller in that case.
    # Set to 0.0 to make valid certs irrelevant for pinned/tight beacons
    # entirely; the default 0.10 keeps a small ranking effect while still
    # letting the beacon fire on behaviour alone.
    option valid_cert_match_penalty_strong_beacon: double = 0.10;

    # Behavioural credit awarded to a CONFIRMED proxy-intercepted beacon to
    # compensate for the loss of certificate signals (the cert is the
    # proxy's, so suspect-issuer / self-signed / cert-mismatch signals are
    # unavailable). Deliberately small: it must NOT push a flow over the
    # alert threshold on its own — a flow only reaches this code path after
    # already exhibiting beacon shape (timing/jitter gates passed), and the
    # web-ALPN and destination-popularity suppressors still apply. Its role
    # is to close the gap so a genuine beacon behind TLS inspection is not a
    # false negative purely because we cannot see the upstream cert.
    # Raise it if you find intercepted-proxy beacons sitting just under
    # threshold; lower it (or set 0.0) if it produces false positives.
    option proxy_intercept_behaviour_credit: double = 0.15;

    # ------------------------------------------------------------------
    # Tunnel / long-connection detector.
    # ------------------------------------------------------------------

    # Max bytes-per-second for a flow to qualify as tunnel-like.
    option tunnel_max_bps: double = 8000.0;

    # Max average originator packet size for tunnel classification.
    # Set high enough to include early LongConnection snapshots where the
    # TLS handshake data inflates average packet size. Bulk transfers that
    # are genuinely not C2 have avg_pkt >> 1400 (large content delivery).
    # A Sliver/Cobalt Strike persistent channel at 600s has avg_pkt ~600,
    # which must not be excluded. The old value of 600 caused a near-miss.
    option tunnel_max_avg_pkt_size: double = 1400.0;

    # Min packets-per-minute to be interesting.
    option tunnel_min_ppm: double = 2.0;

    # Min orig packets before we trust SPL-derived stats.
    option tunnel_min_orig_pkts: count = 8;

    # ------------------------------------------------------------------
    # Encrypted long-tunnel detector (SSL-independent / handshake-missed).
    # ------------------------------------------------------------------
    #
    # A persistent C2 tunnel that Zeek joined MID-STREAM has no ssl.log
    # record: the TLS handshake happened before the capture window (or a
    # Zeek/worker restart), so there is no SSL analyzer state. Every
    # SSL-based detector skips such a flow because it requires c$ssl. On a
    # 24/7 sensor this is the COMMON shape for an hours-long C2 tunnel
    # (e.g. Havoc over Microsoft Dev Tunnels), not an edge case — the
    # channel is persistent by design and predates any given window.
    #
    # This detector works from connection metrics alone (duration, bytes,
    # packets, port) and never touches SSL fields. To stay FP-safe without
    # an SNI or cert to reason about, it leans hard on destination rarity
    # and a small set of encrypted ports, plus the keep-alive / shell
    # shapes.

    # Enable the SSL-independent encrypted-tunnel detector.
    #
    # DEFAULT OFF. This path fires on flows that are NOT in ssl.log (no TLS
    # handshake seen) — i.e. non-TLS / custom-protocol traffic riding an
    # encrypted port. That is OUT OF SCOPE for the current TLS/SSL-focused
    # package and was the source of high-volume false positives on live
    # traffic (any long-lived non-TLS flow over 443 tripping it). The
    # capability is retained but disabled; it belongs with the future
    # multi-protocol C2 work (which will also need to pull JA4 from conn.log
    # for these non-ssl.log flows). Re-enable deliberately only in that
    # context. Leaving it off means the package considers ONLY real
    # TLS/SSL flows (those with an ssl.log record).
    option enc_tunnel_enabled: bool = F;

    # Minimum duration for an encrypted no-handshake flow to be considered.
    # Longer than long_conn_duration on purpose: without any TLS signal we
    # demand a genuinely persistent channel to justify alerting.
    option enc_tunnel_min_duration: interval = 20min;

    # Ports treated as "should have been TLS". A long-lived flow to one of
    # these with NO ssl.log record is the handshake-missed case we target.
    # (We do not alert on arbitrary long connections on random ports — that
    # is a different, noisier problem.)
    option enc_tunnel_ports: set[port] = { 443/tcp, 8443/tcp, 4443/tcp,
                                           9443/tcp, 993/tcp, 995/tcp };

    # A destination contacted by more than this many distinct clients is
    # treated as popular/benign infrastructure (streaming CDN, SaaS) and is
    # NOT alerted on by this detector. Persistent single-client tunnels are
    # the target. Deliberately strict (small) because SSL-less alerting has
    # less corroborating evidence.
    option enc_tunnel_max_dest_clients: count = 2;

    # Base confidence for an encrypted long-tunnel detection. Moderate:
    # duration + rarity + encrypted-port + no-handshake is suggestive but
    # (lacking cert/JA3/SNI) carries less evidence than the SSL path, so it
    # sits at threshold and leans on the shape bonuses (keep-alive / reverse
    # asymmetry) to clear it.
    option enc_tunnel_base_confidence: double = 0.55;

    # Max throughput (bytes/sec) for the keep-alive shape. A real interactive
    # or beaconing tunnel is low-rate; bulk transfer is not this detector's
    # target (and would be noisy).
    option enc_tunnel_max_bps: double = 4000.0;

    # Minimum total bytes exchanged before an encrypted no-handshake flow can
    # alert. Without a handshake we have no cert/SNI/JA3 to corroborate, so a
    # NEAR-SILENT long connection (a few hundred bytes over an hour) carries
    # too little evidence — and benign dormant cloud keep-alives (M365/Azure
    # push channels that Zeek joined mid-stream after a restart/rebalance)
    # look exactly like that. A real tunnel carries at least some
    # command/response traffic. Set above the near-idle noise floor but well
    # below a genuine control channel's volume: the Havoc dev-tunnel sample
    # moved 9-18 KB, whereas a dormant keep-alive moved <1 KB. An idle shell
    # that later sees operator interaction accumulates bytes and then fires,
    # so this does not blind us to interactive shells — it only withholds the
    # alert while the evidence is too thin to distinguish from benign idle.
    option enc_tunnel_min_bytes: count = 4000;

    # ------------------------------------------------------------------
    # Reverse-flow / RAT detector.
    # ------------------------------------------------------------------

    # PCR threshold above which we consider a flow upload-dominant.
    option reverse_flow_pcr_threshold: double = 0.10;

    # Mid-flow silent gap that suggests server-driven command delivery.
    option reverse_silent_gap: interval = 5sec;

    # Min client-to-server size ratio after a server burst.
    option reverse_min_response_ratio: double = 2.0;

    # ------------------------------------------------------------------
    # Interactive reverse-shell shapes (SPL-independent).
    # ------------------------------------------------------------------
    #
    # The primary reverse-flow detector above relies on SPL inter-packet
    # timing to spot the "server sends command → client bursts result"
    # rhythm. A continuous interactive shell may not have those long
    # silences (a busy operator types steadily), so these two additional
    # shapes catch it from connection-level byte/duration metrics alone,
    # requiring no SPL analyzer.

    # Shape 1 — long-lived idle keep-alive. An interactive shell holds the
    # socket open indefinitely while waiting for the operator, so the
    # connection duration stretches into hours but very few bytes move
    # relative to that lifetime. A flow whose duration exceeds this AND
    # whose throughput is below shell_idle_max_bps is a candidate.
    option shell_idle_min_duration: interval = 30min;
    option shell_idle_max_bps: double = 8.0;

    # Shape 2 — reverse asymmetry. Normal web = small client request, large
    # server response. An interactive reverse-shell inverts this: the client
    # streams stdout/command output (steady outbound) while the server drops
    # tiny inbound payloads (the short typed command strings). We look for a
    # sustained connection where client-out ≥ server-in (equilibrium or
    # reverse) AND the inbound side is small in absolute terms.
    #
    # Minimum duration for the reverse-asymmetry shape to be considered
    # (short flows are too noisy).
    option shell_asym_min_duration: interval = 5min;

    # The server→client (inbound) total must be below this many bytes for
    # the "tiny inbound / typed commands" signal. Interactive command
    # strings are small; a real download would blow past this immediately.
    option shell_asym_max_inbound_bytes: count = 16384;

    # The client→server (outbound) total must be at least this many bytes —
    # the shell is actually producing output, not just idling. Keeps the
    # asymmetry shape distinct from the idle-keepalive shape.
    option shell_asym_min_outbound_bytes: count = 4096;

    # Base confidence for an interactive-shell shape. Moderate — these are
    # behavioural and specific, but (like all reverse-flow) can match some
    # legitimate long-poll / streaming-upload patterns, so they lean on the
    # suppressors (web-ALPN, valid-cert, trusted dest) below.
    # Base confidence for an interactive-shell shape. The shapes contribute
    # inline bonuses within evaluate_tunnel; this value is reserved for future
    # standalone use and documents the intended weighting.
    option shell_base_confidence: double = 0.55;

    # ------------------------------------------------------------------
    # Trusted-pivot detector.
    # ------------------------------------------------------------------

    # Rare JA3 threshold — <= this many clients network-wide = suspicious.
    option pivot_max_ja3_clients: count = 2;

    # Min connections before a pivot alert fires.
    option pivot_min_conns: count = 3;

    # ------------------------------------------------------------------
    # Inner-protocol / non-HTTPS tunnel detection.
    # ------------------------------------------------------------------

    # When SPL packet-size variance is below this value (bytes^2) relative
    # to a non-TLS record-size distribution, we suspect a non-HTTPS inner
    # protocol. TLS app-data records for HTTPS vary widely; a protocol with
    # fixed-width framing (SSH, RDP, custom binary) is much tighter.
    option inner_proto_size_variance_max: double = 2000.0;

    # Minimum distinct packet sizes in the originator SPL for the variance
    # analysis to be meaningful — too few samples = inconclusive.
    option inner_proto_min_spl_pkts: count = 12;

    # Maximum ratio of largest to median originator packet size that still
    # suggests fixed-framing. HTTP/2 and HTTPS have very wide ratios (small
    # headers vs large bodies); tunnelled binary protocols are tighter.
    option inner_proto_max_size_ratio: double = 4.0;

    # If the ALPN negotiated (from c$ssl$next_protocol) is NOT one of
    # these standard HTTPS/HTTP values, it is flagged as unusual.
    option known_https_alpn: set[string] = {
        "h2",          # HTTP/2
        "http/1.1",    # HTTP/1.1
        "http/1.0",    # HTTP/1.0
        "",            # No ALPN extension (common, not suspicious alone)
        "-",           # Zeek unset
    };

    # ------------------------------------------------------------------
    # Confidence scoring.
    # ------------------------------------------------------------------

    # Alert threshold (0.0 – 1.0).
    option alert_confidence: double = 0.70;

    # ------------------------------------------------------------------
    # Zeek Notice integration.
    # ------------------------------------------------------------------
    #
    # When generate_notices = T, every log entry also raises a Zeek
    # Notice. By default this is DISABLED so operators can tune the
    # detection thresholds and inspect c2_detections_ssl.log without
    # triggering alerting pipelines until they are confident in the
    # signal quality. The log is ALWAYS written regardless of this flag.
    #
    # To enable notices after tuning:
    #   redef C2_SSL::generate_notices = T;
    option generate_notices: bool = F;

    # ------------------------------------------------------------------
    # Bidirectionality gate — require server response.
    # ------------------------------------------------------------------
    #
    # Real C2 involves a server that actually replies — it has a TLS
    # server-hello and therefore a ja3s/ja4s fingerprint. Blocked or
    # firewall-dropped connections never complete a handshake, never
    # exchange real data, and therefore never generate a server
    # fingerprint. This gate eliminates a major FP class:
    # "malware repeatedly failing to reach its C2 through a firewall"
    # which looks beacon-shaped but has no real communication.
    #
    # When T: flow_state must have seen at least one ja3s/ja4s before
    # any beacon alert fires. Default T — strongly recommended.
    option require_bidirectional: bool = T;

    # Response-byte fallback for the bidirectionality gate.
    # server_seen is normally set by capturing a ja3s/ja4s. But the
    # ServerHello may be missed on a busy sensor, and resumed TLS
    # sessions never carry a fresh server fingerprint. If the responder
    # sent back at least this many bytes across a connection, the server
    # demonstrably replied — that satisfies the bidirectionality gate
    # even without a captured fingerprint. This prevents a false
    # negative on real C2 whose ServerHello we happened to miss.
    # Set low: a TLS ServerHello + cert alone is ~2-4KB, and even a
    # bare beacon ack is a few hundred bytes. 256 bytes is a safe floor
    # that a firewall-blocked / RST connection will never reach.
    option bidirectional_min_resp_bytes: count = 256;

    # ------------------------------------------------------------------
    # Machine-driven traffic gate.
    # ------------------------------------------------------------------
    #
    # Human-initiated connections (browsing, interactive sessions) are
    # characterised by high inter-arrival variance: people think, click,
    # navigate at irregular intervals. Malware beacons are driven by a
    # timer and have very low variance.
    #
    # This gate requires that the beacon's inter-arrival pattern cannot
    # plausibly be explained by human interaction. Specifically: if the
    # median inter-arrival time is below machine_driven_min_interval,
    # the flow is clearly machine-driven (no human clicks at 2s intervals
    # for hours). If above, the jitter must still be low enough to rule
    # out casual human browsing.
    #
    # Note: the reverse-flow detector (SSL_REVERSE_FLOW_RAT) is the
    # right detector for interactive C2 sessions where a human operator
    # on the outside is typing commands. That detector is NOT gated here
    # because it uses PCR shape rather than timing regularity.
    #
    # Connections with median interval below this are always
    # considered machine-driven (no human triggers at sub-second rate).
    option machine_driven_min_interval: interval = 0.5sec;

    # ------------------------------------------------------------------
    # RDP-over-TLS suppression.
    # ------------------------------------------------------------------
    #
    # RDP traffic tunnelled over TLS exhibits fixed-framing patterns
    # that look suspicious to the inner-protocol detector, and may also
    # beacon-shape when an RDP client repeatedly reconnects. This is a
    # legitimate use case in many organisations (staff WFH, partner
    # access, clinical system access).
    #
    # Add the destination IP ranges for your KNOWN LEGITIMATE RDP
    # targets (trusted partner hosts, jump-box subnets, etc.) here.
    # Connections to these subnets are still tracked for beacon shape
    # but INNER_FIXED_FRAME is not treated as an uplift indicator, and
    # the pivot detector ignores them. Do NOT add broad RFC1918 ranges —
    # lateral C2 over RDP is in scope.
    #
    # Example:
    #   redef C2_SSL::trusted_rdp_dest_subnets += { 203.0.113.0/24 };
    option trusted_rdp_dest_subnets: set[subnet] = {};

    # Standard RDP ports. Connections on these ports to
    # trusted_rdp_dest_subnets are suppressed.
    option rdp_ports: set[port] = { 3389/tcp };

    # ------------------------------------------------------------------
    # State expiry.
    # ------------------------------------------------------------------

    const flow_state_expiry: interval = 6hr &redef;
    option ja3_popularity_cap: count = 1000000;
    const ja3_pop_expiry: interval = 24hr &redef;
    const pivot_state_expiry: interval = 7day &redef;

    # ------------------------------------------------------------------
    # Long-connection event hookup.
    # ------------------------------------------------------------------

    option long_conn_duration: interval = 10min;
}


# ----------------------------------------------------------------------
# Deployment profile activation.
#
# The `option` type cannot be changed by plain assignment — only by
# `redef` at parse time, or `Config::set_value` at runtime. Since we
# want thresholds in place before any traffic arrives, redef is correct.
#
# PRODUCTION IS THE DEFAULT — the values above are already the production
# profile. Nothing needs to be loaded for live use.
#
# For SHORT offline PCAP replay, relax the gates with the sandbox profile:
#   @load c2-detection-ssl/sandbox
#
# To restate/pin production values explicitly (idempotent):
#   @load c2-detection-ssl/production
# ----------------------------------------------------------------------
