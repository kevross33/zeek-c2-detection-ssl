# C2 Detection — SSL/TLS module

####################
WHILE THIS IS IN DEVELOPMENT. I APPRECIATE ALL FEEDBACK THAT COULD ENHANCE THIS PACKAGE (Especially decreasing any false negatives/positives or increasing performance further).

NOTE: While I provided much of the detection logic and extensively tested everything including looking at code, it was written with the assistance of LLMs due to its scale and complexity and to allow the detections to be created at pace. I have tested this both against malicious traffic PCAPs as well as run against large scale enterprise traffic. local-exclusions file will allow you to tune out any local false positives but often they are genuine tunnels of some description even if legitimate and I have not seen a beaconing false positive yet (although it should be assumed there will be. 

This ultimately is a work in progress and false negatives will look to be eliminated over time where approrpriate but it is limited to detecting long connections (beaconing/tunnels). One other benefit of this package is it will take intel hits into consideration but only as a minor indicator but this could provide intel confirmation i.e threatfox C2 indicator hit where beaconign is seen. It does not require intel however to detect C2 and can even detect some cases or legitimate service C2.

Another note is it does support definition of web proxies. The correct positioning of a sensor for this between the client and the web proxy so we can see the true client as well as potential fingerprinting. This however is only partially at the moment and only client to Internet has been fully tested in network.

The following zeek packages are required/recommended (JA4 for fingerprinting and spl-spt for packet timing are essential):

zeek/corelight/zeek-long-connections
zeek/salesforce/ja3
zeek/foxio/ja4
zeek/micrictor/spl-spt

The intention is that this will eventually become a zkg installable package. You are free to use this package for testing purposes.

####################

Behavioural detection of command-and-control over SSL/TLS for Zeek 7 and 8.
Designed for noisy enterprise networks (tens of thousands users & devices, mixed PC/IoT etc).

False positives are the dominant operational cost. The framework is designed
to be conservative by default: delayed, high-confidence alerts are preferable
to noisy low-confidence ones.

Some examples of detections (it will not detect everything, layer against failure of a single detection technique or solution i.e utilise RITA for additional beaconing detection from Zeek data).

https://www.malware-traffic-analysis.net/2023/10/16/index.html
<img width="1853" height="662" alt="image" src="https://github.com/user-attachments/assets/905c38be-0ac4-4cea-9b8b-364ff69e6a1c" />

https://www.malware-traffic-analysis.net/2021/12/13/index.html
<img width="2357" height="1217" alt="image" src="https://github.com/user-attachments/assets/2aea7ed9-fa4c-43b8-b255-8ca1b60c8308" />

https://www.malware-traffic-analysis.net/2020/02/26/index.html
<img width="2487" height="315" alt="image" src="https://github.com/user-attachments/assets/e665e470-a5e3-4c73-a889-a8d5af40a364" />


## What it detects

**Scope: outbound C2 only.** This package analyses OUTBOUND flows —
internal clients calling out to external servers (the direction a
compromised host beacons in). Inbound connections (external → internal,
such as RDP brute-force or inbound scanning) and, by default, east-west
(internal → internal) flows are out of scope and dropped before any
analysis. "Internal" is determined by Zeek's `Site::local_nets` plus a
configurable `c2_internal_nets` set (RFC1918/CGNAT by default), so the
direction filter works whether or not the sensor has `local_nets` set. This
is controlled by `c2_require_outbound` (default on) and `c2_analyse_east_west`
(default off). Without this filter, inbound RDP-over-TLS — regular
keep-alives, a self-signed server cert, no SNI — trips the beacon detector,
which is a false positive because the "beacon" is an external host hammering
an internal service, not a compromised host beaconing out.

| Category | Description |
|---|---|
| `SSL_PERIODIC_BEACON` | Repeated full-handshake TLS to the same destination at low jitter |
| `SSL_RESUMPTION_PINNED_BEACON` | Repeated TLS where ≥80% sessions are resumed — no certificate exchange (covert; common in modern tooling) |
| `SSL_TUNNEL_KEEPALIVE` | Long-lived TLS carrying low-BPS keep-alive cadence — persistent RAT/backdoor channel |
| `SSL_TUNNEL_INSIDE_TLS` | Long-lived TLS where originator packet sizes show fixed framing — TLS-in-TLS, hVNC, custom binary protocol |
| `SSL_REVERSE_FLOW_RAT` | Server-driven session: client idle → small server payload (command) → large client upload (result/exfil) |
| `SSL_BEACON_EXFIL` | A confirmed beacon destination that also moves a large, one-directional volume of data — upload-heavy (exfiltration) or download-heavy (payload/tooling staging). Only evaluated inside an already-confirmed beacon, so bulk transfer to benign hosts never triggers it |
| `SSL_C2_EXFIL_ESCALATION` | Escalating cumulative **upload** on a confirmed C2 channel. Fires at an initial 30 MB then at self-scaling decade milestones (100–900 MB, 1–9 GB, 10–90 GB, …), each rung once, plus a slow-drain re-fire while exfiltration is ongoing. Upload-only (downloads are payload-staging); only ever on a confirmed C2, so a benign large upload (backup, cloud sync) never reaches it |
| `SSL_HOST_C2_ESCALATION` | **Confirmed C2 behaviour** (beacon/tunnel/reverse-flow — not first contact) on a host already flagged by a prior high-confidence detection. Never fires on a single flow or a common-fingerprint coincidence; the flow must independently earn a behavioural detection first |
| `SSL_REVERSE_FLOW_RAT` | Server-driven RAT: the SPL path detects idle→command→result rhythm; two additional SPL-independent shapes catch interactive shells — long-lived idle keep-alives (hours open, near-zero throughput) and reverse-asymmetry (client streams stdout while server sends tiny typed-command payloads) |
| `SSL_TRUSTED_PIVOT_RARE_FP` | Connection to popular abusable host (Azure FD, Dropbox, Cloudflare) with a rare network-wide JA3 fingerprint |
| `SSL_NONSTANDARD_INNER_PROTO` | Non-HTTP(S) protocol tunnelled inside TLS (ALPN-based or packet-size distribution) |

All alerts are written to `c2_detections_ssl.log`.

## Beacon timing analysis

Timing regularity is scored with two complementary robust statistics, both
computed over the flow's inter-arrival deltas:

- **Dispersion (jitter).** `MAD(deltas) / median(deltas)` — how tightly the
  intervals cluster. Classified into tight (≤ `beacon_max_jitter`, 0.30),
  jittered (≤ `beacon_jittered_max`, 0.60), and chaotic tiers. Modern C2
  (Cobalt Strike, Sliver, Havoc) deliberately jitters intervals, so the
  jittered tier is retained and scored rather than discarded.

- **Symmetry (Bowley skewness).** `(Q1 + Q3 − 2·Q2) / (Q3 − Q1)` — whether the
  intervals are spread *symmetrically*. This is the measure RITA uses. It is
  complementary to dispersion: a genuine beacon has a symmetric delta
  distribution (skew ≈ 0) even when heavily jittered, whereas bursty
  human/app traffic that merely clusters tends to have a lopsided tail. A
  symmetric flow earns a small confidence bonus (helping a jittered-but-real
  beacon recover score — a false-negative win); a strongly asymmetric,
  non-pinned flow is penalised (a false-positive reduction). Bowley is used
  rather than moment skewness because quartiles are robust to the occasional
  sleep-gap outlier, matching the MAD/median approach. The term is gated on
  `beacon_skew_min_samples` (default 10) because quartile skew is noisy on
  small windows, and is a bounded confidence nudge — never a standalone gate,
  so it cannot manufacture an alert from non-beacon traffic. Resumption-pinned
  beacons are exempt from the asymmetric penalty, since pinning is itself
  C2-defining and can legitimately carry sleeps.

## False-positive defences

The framework layers many cheap-to-expensive defences. Each kills a
specific FP shape; together they keep alert volume manageable on busy
real networks while still catching custom C2 tooling.

1. **Triage allowlists** — M365, Teams, Exchange, SharePoint, PKI, OS
   update, and trusted device subnets are filtered before any state is
   allocated. See the bypass list below.

2. **Connection-state and byte floor** — RST-aborts, REJ, OTH, and any
   connection under 200 bytes total never enter state.

3. **Grace period** — the first 3 connections to any new
   `(client, destination, JA3)` only update lightweight counters. The
   rolling window stays empty. One- or two-shot legitimate browsing
   never accumulates beacon-shaped state. (`flow_grace_count`)

4. **5-host popularity rule** — once more than 5 distinct clients in
   the network connect to a destination, that destination is marked
   popular and **all existing flow state for it is immediately
   evicted**. (`popular_dest_threshold`)

5. **Active abandonment** — flows are dropped from state when:
   - they have fewer than `beacon_min_count` samples after the
     `track_abandon_after` window
   - they have ≥10 samples with >50% jitter and are not
     session-resumption-pinned

6. **Observation-duration gate** — even a perfect-shape beacon will
   not alert until it has been seen for at least
   `beacon_min_observation_duration` (default 15 min in production,
   5 min under the sandbox profile). Kills web-app keep-alives that
   briefly look beacon-shaped, and prevents short PCAP replays from
   firing on a live sensor. (`beacon_min_observation_duration`)

7. **Web-traffic suppression (sticky ALPN flag)** — if the flow has
   *ever* shown HTTP-family ALPN (`h2`, `http/1.1`), or if the JA4
   client fingerprint encodes an HTTP ALPN, the flow is treated as
   web traffic and gets a 0.50 confidence penalty. The flag is sticky
   so subsequent resumed sessions (which Zeek doesn't re-tag with
   ALPN) keep it set. (`web_alpn_penalty`)

8. **Browser JA4 cipher penalty (gated)** — when the JA4 cipher
   segment has been observed network-wide alongside HTTP ALPN at
   least 5 times, the cipher set is "browser-like". Apply a penalty
   only if the *current* flow's JA4 also encodes web ALPN — a flow
   using Chrome's cipher set but NOT offering ALPN is a malware
   indicator, not a browser. (`browser_ja4_penalty`)

9. **Browser cipher without ALPN (positive C2 signal)** — same
   browser cipher set, but `00` ALPN field in JA4 = malware
   mimicking Chrome's TLS handshake without speaking HTTP. Adds
   `+0.20` confidence and the `browser_cipher_no_alpn` indicator.

10. **Cert/SNI mismatch (SAN-aware)** — uses Zeek's built-in
    `c$ssl$sni_matches_cert` verdict, which checks both CN and every
    SAN entry via `x509_check_cert_hostname()`. A `F` verdict means
    the cert genuinely doesn't cover the SNI — strong C2 indicator
    (`CN=jquery.com` for `zuppohealth.com`, `CN=localhost` for raw
    IPs). A simple CN check would FP on every modern multi-domain
    cert (e.g. messenger.com's cert has `CN=*.facebook.com` plus a
    SAN for messenger.com). (`cert_sni_mismatch_bonus`)

11. **Valid-cert-with-matching-SAN suppression** — the inverse of
    (10): when both `validation_status == "ok"` AND
    `sni_matches_cert == "T"`, the destination is almost certainly a
    legitimate publicly-issued service. Apply `-0.30` penalty so it
    has to clear a higher bar via other suspicion signals. This
    is the defence that kills the `messenger.com` /
    `static.xx.fbcdn.net` FP class. (`valid_cert_match_penalty`)

12. **Pure-download suppression** — flows with PCR < -0.95 (>97% of
    bytes server→client) are content downloads, not C2. Even RATs
    upload some command results. (`pure_download_penalty`)

13. **Common-fingerprint penalty** — when a JA3 is shared by ≥10
    distinct clients AND the destination is moderately popular, the
    confidence score is reduced. Catches "stock browser to a small
    but legitimate shared site". (`common_ja3_client_floor`)

14. **Maximum-interval gate at alert time** — flows with median
    interval >6 hours never fire as a fast periodic beacon. They
    route to the sparse-beacon path or are ignored.
    (`beacon_max_median_interval`)

## Host compromise correlation (multi-C2 / payload transitions)

An intrusion is rarely a single flow. A loader (BumbleBee, IcedID, QakBot)
hands off to a full C2 (Cobalt Strike, Sliver), which then runs recon, exfil,
and ultimately ransomware — often within minutes. This package correlates
activity **per host** so a confirmed detection informs analysis of the same
host's later channels.

**The strongest C2 signal is behaviour over time, not any single flow.** A
first-contact connection, or a fingerprint match on a common TLS stack, is the
*weakest* possible signal and never produces an alert here. First-contact
"emerging" shapes are recorded as internal state only; they add a small
corroborating bonus if — and only if — the flow later confirms as a genuine
beacon/tunnel/reverse-flow. Escalation likewise requires a real behavioural
detection first.

The design is deliberately **conservative** — it only ever *escalates* flows
that are already independently suspicious; it never turns a benign flow into
an alert:

- **Host compromise state.** When a host produces an alert at or above
  `host_compromise_entry_confidence` (default 0.90 — high, so only
  near-certain catches arm it), it is marked compromised for
  `host_compromise_window` (default 6h). While compromised, a further flow
  that *already* scores at/above `host_escalation_floor` (0.45) gets a
  `host_compromise_bonus` (+0.15). A weak second C2 that fell just under the
  alert threshold is thereby caught — the false-negative reduction — but a
  benign flow, which never reaches the floor, is untouched.

- **Fingerprint pivot, with a commonality gate.** Malware reuses its TLS
  stack, so fingerprints seen on a confirmed C2 are recorded for correlation
  as *tracked* fingerprints. **JA4 is the primary fingerprint** for all rarity,
  tracking, and pivot logic, with JA3 retained for reporting and JA3-keyed
  intel. JA4 is preferred because it excludes GREASE and normalises cipher/
  extension order, so the same client yields a *stable* hash — whereas JA3
  includes GREASE and is order-sensitive, which makes browsers emit many
  different JA3s and look artificially "rare", polluting the rarity signal.
  When the JA4 field is absent (the FoxIO JA4 plugin isn't loaded), everything
  falls back to JA3 automatically. The package also uses JA4's readable prefix
  for **structured analytics**: a fingerprint whose prefix matches the browser
  envelope (modern TLS, SNI present, HTTP ALPN) is classified as browser-class
  and has its rarity demoted even when its exact hash is uncommon — attacking
  the "rare-but-benign browser" false-positive directly.

- **Payload-staging / stage transition.** Inside an **already-confirmed** C2,
  a large **download** burst (server→client) whose size is consistent with an
  executable/payload — either above an absolute floor
  (`payload_min_download_bytes`, ~20 KB) or many times the channel's own tiny
  heartbeat baseline — is recorded as evidence (`payloads=N`,
  `payload_max_dl=` in the alert details) and sets a **short-lived**
  (`payload_staged_window`, <1 min) host marker. If a **new** channel then
  independently confirms as C2 within that window, it gets a small
  corroboration and a `stage_transition` indicator — the "pull a next stage,
  then a new C2 stands up" pattern (e.g. → Sliver). The burst **never** alerts
  on its own, is download-only (uploads are exfil, handled separately), and is
  FP-safe **entirely** because it can only be observed on a flow that already
  confirmed as C2 — benign TLS updaters (Windows Update, browsers, AV) are
  never confirmed beacons, so a burst on them is never recorded. The window is
  deliberately short: a genuine execute-then-transition is quick, and a longer
  wait would link unrelated later channels.

- **Escalation is an indicator, not a category.** When host-correlation
  strengthens a detection, the alert's **category always names the actual C2
  behaviour** (`SSL_PERIODIC_BEACON`, `SSL_RESUMPTION_PINNED_BEACON`,
  `SSL_TUNNEL_*`, `SSL_REVERSE_FLOW_RAT`) so the detection type is
  unambiguous. The correlation is surfaced as indicators
  (`host_c2_escalation`, `rare_fingerprint_pivot`, `compromised_host_activity`,
  `stage_transition`) on top of that category, never by replacing it.

- **Allowlisted destinations are never escalated.** Correlation runs *after*
  the allowlist bypass, so legitimate first-party traffic (Microsoft/O365,
  WNS, vendor telemetry) from a compromised host is still bypassed.

- **Threat-intel corroboration.** An operator Intel-framework hit (intel.log)
  on a detection's destination adds `intel_corroboration_bonus` (+0.20) to a
  **behaviourally-confirmed** beacon/tunnel/reverse-flow. An intel hit alone
  never fires — a stale or benign reputation lookup must not alert — so an
  intel-listed beacon pages with high confidence while a bare lookup stays
  silent.

- **Masquerade guard.** The allowlist free pass is withheld only when a cert
  is visible and *demonstrably* fails to cover the claimed SNI **and** fails
  validation (`masquerade_guard_enabled`). A genuine first-party connection
  always has a valid matching cert, so this never fires on real Microsoft
  traffic.

State is in-memory with automatic time-decay (no disk persistence; resets on
restart). All thresholds are redef-able in `local-exclusions.zeek`.

## Deployment profiles

**Production is the default** — no configuration needed for a live sensor.
The thresholds are calibrated to catch real C2 (false negatives are the
priority) while staying tractable on a large network.

For replaying **short offline PCAPs** (malware-sandbox captures, a few
minutes of traffic) the production time/sample gates suppress detections
because the capture is too short. Load the sandbox profile for that:

```zeek
@load c2-detection-ssl
@load c2-detection-ssl/sandbox     # ONLY for short PCAP replay
```

| Setting | Production (default) | Sandbox (PCAP replay) |
|---|---:|---:|
| `beacon_alert_min_count` | 12 | 8 |
| `beacon_min_observation_duration` | 15 min | 5 min |
| `pinning_min_count` | 8 | 5 |
| `track_abandon_after` | 1 hr | 1 hr |
| `flow_grace_count` | 3 | 3 |

The production `beacon_alert_min_count` (12) and `beacon_min_observation_duration`
(15 min) are deliberately *jointly satisfiable*: a beacon of any interval up to
~75 s can reach 12 samples within the 15-minute window, and slower beacons still
alert via the resumption-pinned path (`pinning_min_count`), which does not
require the full sample count. This avoids the false-negative hole that a naive
"30 samples in 30 minutes" pairing would create — that combination silently
misses any beacon slower than ~60 s.

Do **not** load the sandbox profile on a live sensor; it lowers the evidence
bar and increases false positives at scale.

## What it explicitly bypasses (no tracking at all)

The framework uses three separate mechanisms to avoid tracking legitimate traffic:

### 1. The 5-host rule (popularity-based eviction)

The single most powerful FP killer. The framework counts distinct clients
per destination across the entire network. Once more than **5 distinct
clients** in the network have connected to any given destination
(lowercased SNI or IP), the destination is marked "popular" and:

- Any existing per-flow state for it is immediately evicted (memory reclaimed)
- All future connections to it skip tracking entirely (no CPU cost)

This catches the long tail of legitimate niche services (regional news,
vendor portals, CRM/HR/finance SaaS, video conferencing, niche cloud apps)
without requiring any pre-curated allowlist.

The threshold is configurable: `redef C2_SSL::popular_dest_threshold = 5`.

### 2. Active abandonment of non-beacon flows

The framework actively drops flows from tracking when they're determined
not to be beacons:

- After **10 samples**, if the flow is not session-resumption-pinned and its
  jitter exceeds 50%, the flow is conclusively browsing — state is deleted
- After **1 hour** of tracking with fewer than 6 samples, the flow is
  abandoned (it's casual one-shot traffic, not a beacon)

These work together: noisy fast-polling browsing gets dropped after 10 hits;
slow occasional browsing gets dropped after an hour. Both free memory aggressively
and prevent state accumulation over long sensor uptime.

### 3. Pre-curated safe-suffix bypass (Microsoft 365 et al.)

The `safe_sni_suffixes` list contains the complete Microsoft 365 endpoint
infrastructure based on the canonical Microsoft endpoint list
(https://aka.ms/o365endpointwebservice, last reviewed 2026-03-31):

- **Teams / Lync**: `*.lync.com`, `*.teams.microsoft.com`, `*.teams.cloud.microsoft`, `*.skype.com`
- **Exchange Online**: `*.outlook.com`, `*.office365.com`, `*.protection.outlook.com`
- **SharePoint / OneDrive for Business**: `*.sharepoint.com`, `*.sharepointonline.com`, `*.svc.ms`
- **Microsoft 365 Unified Domains**: `*.cloud.microsoft`, `*.static.microsoft`, `*.usercontent.microsoft`
- **Entra ID / Auth**: `*.microsoftonline.com`, `*.auth.microsoft.com`, `login.microsoft.com`, `graph.microsoft.com`, and full auth surface
- **Office Apps**: `*.office.com`, `*.office.net`, `*.officeapps.live.com`, `*.onenote.com`
- **PKI / CRL / OCSP infrastructure**: digicert, sectigo, letsencrypt, globalsign, lencr etc.
- **Windows Update / telemetry**: windowsupdate, events.data.microsoft.com, aria.microsoft.com

These are full triage bypasses — no state is allocated, no popularity
tracking, nothing. Teams and Exchange connections generate enormous volumes
of periodic/resumed TLS sessions that would be near-perfect false positives
without this bypass.

**Note on abusable Microsoft infrastructure**: `*.azureedge.net`, `*.azurefd.net`,
`*.blob.core.windows.net`, `*.trafficmanager.net` are in `trusted_pivot_suffixes`
(not bypassed). These CDN/blob services CAN be abused as C2 staging/fronting
and are still tracked for JA3 fingerprint rarity.

## Log schema highlights (c2_detections_ssl.log)

Key fields beyond the standard ts/orig_h/resp_h:

| Field | Description |
|---|---|
| `category` | Detection type (see table above) |
| `confidence` | 0.0–1.0 score — only alerts ≥ 0.70 fire |
| `sni` | TLS server name indicator (real destination when via proxy) |
| `via_proxy` | True when resp_h is a configured proxy; ja3s/ja4s are blanked |
| `tls_version` | TLS version negotiated |
| `alpn` | ALPN protocol advertised (`h2`, `http/1.1`, or something else) |
| `inner_proto` | What we think is tunnelled: `INNER_LIKELY_HTTPS`, `INNER_FIXED_FRAME`, `INNER_SMALL_UNIFORM`, `INNER_BINARY_BURST`, `INNER_NONSTANDARD_ALPN`, `INNER_UNKNOWN` |
| `cert_issuer` | Certificate issuer string |
| `cert_validation` | Zeek cert validation status |
| `ja3` / `ja4` | Client fingerprints (always populated when available) |
| `ja3s` / `ja4s` | Server fingerprints (blanked when `via_proxy=T`) |
| `pcr` | Producer-consumer ratio: -1 = pure download, +1 = pure upload |
| `sample_uid` | Representative uid for pivoting into ssl/conn/x509 |
| `indicators` | Set of signal tags: `suspect_issuer`, `no_sni`, `rare_ja3_to_raw_ip`, etc. |

## Inner protocol detection

The `inner_proto` field answers: *what protocol is actually running inside this TLS tunnel?*

| Value | Meaning |
|---|---|
| `INNER_LIKELY_HTTPS` | Wide packet-size variance + high max/median ratio — consistent with HTTP/2 |
| `INNER_FIXED_FRAME` | Tight packet-size variance + low max/median ratio — consistent with SSH, RDP, or custom binary |
| `INNER_SMALL_UNIFORM` | Very small (<100B) and very uniform packets — heartbeat / keep-alive C2 |
| `INNER_BINARY_BURST` | Irregular large bursts — binary file-transfer inside TLS |
| `INNER_NONSTANDARD_ALPN` | ALPN negotiated a protocol other than `h2` or `http/1.1` |
| `INNER_UNKNOWN` | Insufficient data or no clear classification |

`INNER_FIXED_FRAME` on a long-lived connection to an unusual destination is
a strong indicator of a non-HTTPS covert channel (hVNC, RDP-over-TLS, SSH
wrapped in TLS, custom C2 protocol). `INNER_SMALL_UNIFORM` typically indicates
a keep-alive/heartbeat-style C2 agent.

## Installation

```bash
# Optional but strongly recommended
zkg install zeek/corelight/zeek-long-connections
zkg install zeek/foxio/ja4

# Install this package
zkg install /path/to/c2-detection-ssl   # or a git URL
```

Then in `local.zeek`:

```zeek
@load c2-detection-ssl
@load corelight/zeek-long-connections
@load foxio/ja4

# Configure proxies and device VLANs — see local.zeek.example
redef C2_SSL::proxy_hosts += { 10.50.0.10 };
redef C2_SSL::trusted_orig_subnets += { 10.40.0.0/16 };  # medical VLAN
```

See `local.zeek.example` for a fully-commented template.

## Site tuning that survives package upgrades

The package ships a curated allowlist in `scripts/allowlists.zeek`. That file
is maintained upstream and is **replaced when you upgrade** the package. Do
not edit it directly — your changes would be lost on the next update.

Instead, all site-specific tuning goes in **`scripts/local-exclusions.zeek`**.
This file only ever *extends* the package sets with `+=`, so:

- the upstream curated lists can grow underneath you with each release, and
- your local additions are never touched by an upgrade.

Put your allowlisted domains, trusted subnets, proxy configuration, and
interception CA here. The package ships this file production-ready with your
site entries already in place; edit it in-place as your environment changes.

```zeek
# scripts/local-exclusions.zeek  — YOURS, preserved across upgrades
redef C2_SSL::safe_sni_suffixes += {
    "server.eu.action1.com",     # our sanctioned RMM instance
    ".isrg-simulation.com",      # approved attack-simulation target
};
redef C2_SSL::proxy_hosts += { 10.50.0.10, 10.50.0.11 };
redef C2_SSL::proxy_ca_issuers += { "CN=SJH TLS Inspection CA" };
```

**Upgrade rule:** when updating the package, preserve `local-exclusions.zeek`
and overwrite everything else. (Under `zkg upgrade` the same applies — keep
your copy of this one file.) Broadly-useful well-known domains — major cloud,
CDN, vendor telemetry, PKI — belong upstream in `allowlists.zeek` so every
deployment benefits; open a PR rather than carrying them locally.

## Proxy handling

When an explicit proxy (Cisco WSA/Secure Access, Squid, etc.) is in
`proxy_hosts` / `proxy_subnets`, the module adapts to the proxy's TLS mode.

**Common to both modes:**

1. **SNI is the destination identity** for state keying (not the proxy IP).
2. **CONNECT host correlation** — the plaintext `CONNECT host:port` in
   `http.log` is joined to the SSL flow by connection UID and used as the
   authoritative destination, especially when SNI is absent (Encrypted
   Client Hello). It also feeds the safe-SNI bypass and appears as
   `connect_host` in alerts.
3. **Beacon timing, PCR, and volume all survive the proxy** — a beacon is
   still a beacon on the client→proxy leg, so behavioural detection is
   unaffected.
4. **`via_proxy=T`** is set so analysts know the real destination is in `sni`.
5. **Flows originating from the proxy** (proxy→upstream) are skipped.

**`PROXY_NON_INTERCEPTING`** (plain CONNECT tunnel, no TLS inspection):
the client does end-to-end TLS with the real server, so **JA3S/JA4S and the
certificate chain are real** and are used exactly as for a direct connection.

**`PROXY_INTERCEPTING`** (default — SSL-bump / TLS inspection with your CA):
the cert, JA3S/JA4S and validation belong to the *proxy*, not the upstream.
Declare your interception CA (`proxy_ca_issuers`, `proxy_ca_fingerprints`,
`proxy_ja3s`/`proxy_ja4s`) so the module:

- **positively confirms interception** rather than mistaking your bump cert
  for attacker self-signing,
- **skips cert-based signals** on confirmed-intercepted flows (they would be
  meaningless), and
- **compensates with a behavioural credit** (`proxy_intercept_behaviour_credit`,
  default 0.15) so a genuine beacon behind inspection is not a false negative
  purely because the upstream cert is invisible.

A proxied flow in intercepting mode that does **not** match your CA is treated
as *not* intercepted — its cert signals are kept, since that can indicate
cert-pinning malware bypassing inspection or the proxy passing the real cert
through. The `proxy_intercepted` alert field records the verdict per flow.

See `local.zeek.example` section 1a for the interception-CA tuning block.

## Files in this package

```
scripts/__load__.zeek        Load order: config → allowlists → shared → detect
                             → local-exclusions (last, so site tuning wins)
scripts/config.zeek          All thresholds — every one is a redefable option/const
scripts/allowlists.zeek      PACKAGE-curated safe bypasses: O365, Teams, Exchange,
                             major cloud/vendor/PKI; trusted-pivot list;
                             suspect-issuer fragments. Updated with releases.
scripts/local-exclusions.zeek  YOURS — site-specific domains, subnets, proxy config
                             and interception CA. Extends the package sets with +=.
                             Preserved across package upgrades (do not overwrite).
scripts/production.zeek      Production thresholds (the DEFAULT — provided for
                             explicit @load and as the canonical value list).
scripts/sandbox.zeek         Relaxed gates for SHORT offline PCAP replay only.
scripts/shared.zeek          Log schema (c2_detections_ssl.log), types, helpers
scripts/detect.zeek          Detectors: beacon, tunnel, reverse-flow, pivot,
                             inner-protocol classification; proxy + CONNECT handling
local.zeek.example           Copy-paste site configuration template
testing/verify_against_supplied_logs.py
                             Python replay harness — confirms correct detections
                             against supplied ssl.log / conn.log / x509.log
```
