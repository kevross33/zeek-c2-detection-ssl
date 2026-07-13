#!/usr/bin/env python3
"""
verify_against_supplied_logs.py — replays supplied Zeek logs through a faithful
Python simulation of the beacon detector, confirming expected C2 detections.

Run:
    python3 verify_against_supplied_logs.py /path/to/uploads/

Expected output:
  baeswea.com  (87.120.8.98)    → SSL_PERIODIC_BEACON, conf=1.00
  solobiv.com  (108.62.118.215) → SSL_RESUMPTION_PINNED_BEACON, conf~0.71
"""
from __future__ import annotations
import argparse, statistics, json, ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# ---- Thresholds ----
# This harness replays SHORT offline PCAPs, so it mirrors the SANDBOX
# profile (relaxed time/sample gates), which is what you load for PCAP
# replay: @load c2-detection-ssl/sandbox. The package itself now defaults
# to the stricter PRODUCTION profile for live sensors.
MIN_TRACK_BYTES         = 200
BEACON_MIN              = 6
BEACON_ALERT_MIN        = 8            # sandbox (production default is 12)
BEACON_MAX_JITTER       = 0.30
BEACON_JITTERED_MAX     = 0.60         # jittered-beacon tier upper bound
BEACON_SKEW_ENABLED         = True
BEACON_SKEW_MIN_SAMPLES     = 10
BEACON_SKEW_SYMMETRIC_MAX   = 0.30
BEACON_SKEW_ASYMMETRIC_MIN  = 0.60
BEACON_SKEW_SYMMETRIC_BONUS = 0.10
BEACON_SKEW_ASYMMETRIC_PENALTY = 0.15
BEACON_JITTERED_MIN_CNT = 12           # samples required for jittered tier
BEACON_CHAOTIC_THRESH   = 0.70         # above this + unpinned → abandon
EARLY_JITTER_SAMPLE_FLR = 10
BURST_COLLAPSE          = 1.0
PINNING_MIN_COUNT       = 5
PINNING_MIN_RATIO       = 0.80
PINNING_STRONG_COUNT    = 20           # strong-pinning obs-gate bypass
EXFIL_MIN_BYTES         = 5000000      # beacon-exfil: bulk transfer floor
EXFIL_MIN_PCR_SKEW      = 0.60         # beacon-exfil: one-directional skew
EXFIL_BASE_CONFIDENCE   = 0.80
EXFIL_UPLOAD_BONUS      = 0.10
ALERT_CONFIDENCE        = 0.70
POPULAR_DEST_THRESHOLD  = 5            # >5 distinct clients → drop tracking
FLOW_GRACE_COUNT        = 3            # don't populate window for first 3 conns
BEACON_MAX_MEDIAN_S     = 6 * 3600     # 6 hours — slower → not a fast beacon
COMMON_JA3_FLOOR        = 10           # JA3 shared by ≥10 clients = "common"
COMMON_JA3_PENALTY      = 0.30
BEACON_MIN_OBS_DURATION = 5 * 60       # 5 min observation minimum (sandbox profile)
WEB_ALPN_PENALTY        = 0.50         # flow seen with HTTP ALPN → strong penalty
BROWSER_JA4_FLOOR       = 5            # JA4 cipher seen with web-ALPN ≥N times
BROWSER_JA4_PENALTY     = 0.30
MAX_DOWNLOAD_PCR        = -0.95
PURE_DOWNLOAD_PENALTY   = 0.40
CERT_SNI_MISMATCH_BONUS = 0.25
VALID_CERT_MATCH_PENALTY = 0.30
VALID_CERT_MATCH_PENALTY_STRONG_BEACON = 0.10
REQUIRE_BIDIRECTIONAL = True    # Gate: need server_seen before alerting

WEB_ALPNS = {"h2", "http/1.1", "http/1.0", "h3", "h2c"}
JA4_WEB_PREFIXES = {"h2", "h1", "h0"}  # JA4 first-segment last-2-chars

# ---- Safe SNI suffixes (mirrors allowlists.zeek — key O365 entries) ----
SAFE_SUFFIXES = (
    # Major enterprise vendor infra (mirrors package allowlists.zeek)
    ".cisco.com", ".webex.com", ".ciscodna.com", ".ciscoconnectdna.com",
    ".opinsights.azure.com", ".atp.azure.com", ".servicebus.windows.net",
    ".dell.com", ".redhat.com", ".ecostruxureit.com",
    ".adobe.io", ".adobess.com",
    # M365 Unified
    ".cloud.microsoft", ".static.microsoft", ".usercontent.microsoft",
    # Exchange
    ".outlook.com", ".office365.com", ".protection.outlook.com",
    ".mail.protection.outlook.com", ".mx.microsoft",
    # SharePoint / OneDrive Business
    ".sharepoint.com", ".sharepointonline.com", ".svc.ms",
    # Teams / Lync
    ".lync.com", ".teams.microsoft.com", ".teams.cloud.microsoft",
    ".skype.com", ".skypeassets.com",
    # Auth / Entra ID
    ".microsoftonline.com", ".microsoftonline-p.com",
    ".msauth.net", ".msftauth.net", ".auth.microsoft.com",
    ".msidentity.com", ".msftidentity.com", ".phonefactor.net",
    "login.microsoft.com", "login.windows.net",
    "graph.microsoft.com", "graph.windows.net",
    "enterpriseregistration.windows.net",
    # Office apps
    ".office.com", ".office.net", ".officeapps.live.com",
    ".online.office.com", ".onenote.com",
    # Telemetry
    ".aria.microsoft.com", ".events.data.microsoft.com",
    # PKI / CRL / OCSP
    ".windowsupdate.com", ".update.microsoft.com",
    ".pki.goog", ".digicert.com", ".sectigo.com",
    ".letsencrypt.org", ".lencr.org", ".globalsign.com",
    ".symantec.com", ".verisign.com", ".entrust.net",
)

SUSPECT_ISSUER_FRAGMENTS = (
    "Internet Widgits Pty Ltd", "CN=localhost", "Acme Co",
    "Default Company Ltd", "snakeoil", "/CN=Default", "Test CA",
    "Metasploit", "msf", "My Company Ltd",
)

def is_internal(a: str) -> bool:
    """Mirror is_internal_addr(): RFC1918/CGNAT/loopback/link-local."""
    if not a:
        return False
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return False
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                "fc00::/7", "fe80::/10"):
        if ip in ipaddress.ip_network(net):
            return True
    return False

def is_outbound(orig: str, resp: str, east_west: bool = False) -> bool:
    """Mirror is_outbound_flow(): internal orig -> external resp."""
    oi, ri = is_internal(orig), is_internal(resp)
    if not oi:
        return False
    if not ri:
        return True
    return east_west

def is_sni_safe(sni: str) -> bool:
    if not sni or sni in ("(empty)", "-"):
        return False
    lc = sni.lower()
    for s in SAFE_SUFFIXES:
        if lc.endswith(s) or lc == s.lstrip("."):
            return True
    return False

def has_suspect_issuer(issuer: str) -> bool:
    return any(f in issuer for f in SUSPECT_ISSUER_FRAGMENTS) if issuer else False

def load_zeek_log(path: Path) -> list[dict]:
    """Load a Zeek log in either JSON-stream or TSV format.

    Zeek can emit logs as one JSON object per line (LogAscii::use_json=T)
    or as classic tab-separated with a #fields header. Detect and handle
    both so the harness works against whatever the sensor produced.
    """
    rows = []
    fields: list[str] = []
    with path.open() as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("{"):
                # JSON-stream format.
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            elif line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif not line.startswith("#"):
                parts = line.split("\t")
                if len(parts) == len(fields):
                    rows.append(dict(zip(fields, parts)))
    return rows

def _norm_bool(v):
    """Normalize a Zeek bool to the TSV 'T'/'F' convention."""
    if isinstance(v, bool):
        return "T" if v else "F"
    return v

def normalize_rows(rows: list[dict]) -> list[dict]:
    """Make JSON-loaded rows look like TSV rows for the rest of the harness:
    booleans -> 'T'/'F' strings, list fields -> comma-joined strings, and
    numeric byte counts left as-is (int() handles both)."""
    for r in rows:
        for k in ("established", "resumed"):
            if k in r:
                r[k] = _norm_bool(r[k])
        # sni_matches_cert may be bool in JSON
        if "sni_matches_cert" in r:
            r["sni_matches_cert"] = _norm_bool(r["sni_matches_cert"])
        # list fields -> comma-joined (cert_chain_fps, san.dns)
        for k in ("cert_chain_fps", "san.dns"):
            if isinstance(r.get(k), list):
                r[k] = ",".join(str(x) for x in r[k])
    return rows

@dataclass
class FlowState:
    first_seen: float = 0.0
    last_seen:  float = 0.0
    ts:         list = field(default_factory=list)
    orig_size:  list = field(default_factory=list)
    resp_size:  list = field(default_factory=list)
    resumed:    list = field(default_factory=list)
    issuer:     str = ""
    subject:    str = ""
    validation: str = ""
    sni:        str = ""
    ja3:        str = ""
    ja4:        str = ""
    alpn:       str = ""
    seen_web_alpn: bool = False
    sni_matches_cert: str = ""
    server_seen: bool = False   # True once ja3s/ja4s observed (server responded)
    tls_version: str = ""       # TLS version string
    last_resp_h: str = ""

def collapse_bursts(ts: list[float], threshold: float = BURST_COLLAPSE) -> list[float]:
    if not ts: return []
    out = [ts[0]]
    for t in ts[1:]:
        if t - out[-1] >= threshold:
            out.append(t)
    return out

def gaps(ts: list[float]) -> list[float]:
    return [b - a for a, b in zip(ts, ts[1:])]

def mad(values: list[float], median_val: float) -> float:
    return statistics.median(abs(v - median_val) for v in values) if values else 0.0

def bowley_skewness(values: list[float]) -> float:
    """Quartile-based robust skewness — mirrors bowley_skewness() in shared.zeek."""
    n = len(values)
    if n < 4:
        return 0.0
    s = sorted(values)
    def q(frac):
        pos = frac * (n - 1)
        lo = int(pos // 1)
        hi = lo + 1
        if hi >= n:
            return s[-1]
        return s[lo] + (s[hi] - s[lo]) * (pos - lo)
    q1, q2, q3 = q(0.25), q(0.50), q(0.75)
    iqr = q3 - q1
    if iqr <= 0:
        return 0.0
    return max(-1.0, min(1.0, (q1 + q3 - 2 * q2) / iqr))

def names_from_cert(cert_row: dict) -> list:
    """Collect all hostnames the cert covers — CN plus every SAN entry.

    Mirrors what x509_check_cert_hostname() does in Zeek (which is what
    populates c$ssl$sni_matches_cert): the CN is included, every SAN.dns
    is included, all lower-cased, leading "*." kept (to be wildcard-
    matched at compare time).
    """
    names = []
    subj = cert_row.get("certificate.subject", "") or ""
    # Extract CN from subject DN.
    lc = subj.lower()
    idx = lc.find("cn=")
    if idx >= 0:
        rest = subj[idx + 3:]
        end = len(rest)
        for sep in (",", "/"):
            i = rest.find(sep)
            if 0 <= i < end:
                end = i
        cn = rest[:end].lower().strip()
        if cn:
            names.append(cn)
    # Add every SAN.DNS entry.
    san = cert_row.get("san.dns", "") or ""
    if san and san not in ("-", "(empty)"):
        for n in san.split(","):
            n = n.strip().lower()
            if n:
                names.append(n)
    return names


def hostname_matches(cert_name: str, sni: str) -> bool:
    """Match a single cert name against an SNI, with wildcard support."""
    if cert_name == sni:
        return True
    if cert_name.startswith("*."):
        # Wildcard matches exactly one label. e.g. *.facebook.com matches
        # www.facebook.com but not facebook.com or a.b.facebook.com.
        suffix = cert_name[1:]  # ".facebook.com"
        if not sni.endswith(suffix):
            return False
        prefix = sni[:-len(suffix)]
        return prefix and "." not in prefix
    return False


def sni_matches_any_cert_name(sni: str, names: list) -> bool:
    """True iff SNI matches at least one of the cert's names (CN or SAN)."""
    if not sni or sni in ("(empty)", "-"):
        return True  # no SNI = nothing to mismatch with
    sni_lc = sni.lower()
    for n in names:
        if hostname_matches(n, sni_lc):
            return True
    return False


def evaluate_beacon(key: tuple, st: FlowState,
                    dest_client_count, ja3_client_count,
                    browser_ja4_ciphers) -> dict:
    if len(st.ts) < BEACON_MIN:
        return None

    # Bidirectionality gate — server must have responded.
    if REQUIRE_BIDIRECTIONAL and not st.server_seen:
        return None

    collapsed = collapse_bursts(st.ts)
    if len(collapsed) < BEACON_MIN:
        return None
    g = gaps(collapsed)
    if len(g) < 5:
        return None
    med = statistics.median(g)
    if med <= 0:
        return None

    # Observation duration gate — bypassed by strong resumption-pinning.
    obs_duration = st.last_seen - st.first_seen
    res_count_early = sum(1 for r in st.resumed if r)
    res_ratio_early = res_count_early / len(st.resumed) if st.resumed else 0.0
    strong_pinned = (len(st.ts) >= PINNING_STRONG_COUNT and
                     res_ratio_early >= PINNING_MIN_RATIO)
    if obs_duration < BEACON_MIN_OBS_DURATION and not strong_pinned:
        return None

    # Slow-cadence beacons: not a fast beacon.
    if med > BEACON_MAX_MEDIAN_S:
        return None

    jitter = mad(g, med) / med

    res_count = sum(1 for r in st.resumed if r)
    res_ratio = res_count / len(st.resumed) if st.resumed else 0.0
    pinned = len(st.ts) >= PINNING_MIN_COUNT and res_ratio >= PINNING_MIN_RATIO

    # ---- Jitter classification (tight / jittered / chaotic) ----
    is_tight    = jitter <= BEACON_MAX_JITTER
    is_jittered = (not is_tight) and jitter <= BEACON_JITTERED_MAX

    # Machine-driven gate (jitter-aware): a non-tight, non-pinned flow above
    # the sub-second threshold is only pursued if it's jittered with enough
    # samples.
    if med > 0.5 and not is_tight and not pinned:
        if not (is_jittered and len(st.ts) >= BEACON_JITTERED_MIN_CNT):
            return None

    # Chaotic abandonment: beyond the jittered band, unpinned, well-sampled.
    if jitter > BEACON_CHAOTIC_THRESH and not pinned and \
            len(st.ts) >= EARLY_JITTER_SAMPLE_FLR:
        return None

    if not pinned and len(st.ts) < BEACON_ALERT_MIN:
        return None

    # ---- Jitter-tiered time score ----
    if is_tight:
        time_score = 1.0 - (jitter * 0.5)
    elif is_jittered:
        time_score = max(0.85 - ((jitter - BEACON_MAX_JITTER) * 1.00), 0.0)
    else:
        time_score = 0.20
    if time_score < 0.0:
        time_score = 0.0

    # ---- Bowley-skewness symmetry adjustment ----
    skew_tag = ""
    if BEACON_SKEW_ENABLED and len(g) >= BEACON_SKEW_MIN_SAMPLES:
        sk = abs(bowley_skewness(g))
        if sk <= BEACON_SKEW_SYMMETRIC_MAX:
            time_score += BEACON_SKEW_SYMMETRIC_BONUS
            skew_tag = "symmetric_timing"
        elif sk >= BEACON_SKEW_ASYMMETRIC_MIN and not pinned:
            time_score -= BEACON_SKEW_ASYMMETRIC_PENALTY
            skew_tag = "asymmetric_timing"
        time_score = max(0.0, min(1.0, time_score))

    if pinned:
        conf = res_ratio * 0.50 + time_score * 0.25
    else:
        conf = time_score * 0.65

    indicators = []
    if skew_tag:
        indicators.append(skew_tag)
    if pinned:
        indicators.append("session_resumption_pinned")
    if is_jittered:
        indicators.append("jittered_beacon")

    # ---- Web traffic suppression (sticky-ALPN flag) ----
    if st.seen_web_alpn:
        conf -= WEB_ALPN_PENALTY
        indicators.append("web_alpn_observed")

    # ---- Browser-JA4 cipher penalty (gated on current flow's ALPN) ----
    ja4_cipher = ""
    cur_ja4_alpn = ""
    if st.ja4 and "_" in st.ja4:
        parts = st.ja4.split("_")
        if len(parts) >= 2:
            ja4_cipher = parts[1]
        if parts and len(parts[0]) >= 2:
            cur_ja4_alpn = parts[0][-2:]
    cur_ja4_is_web = cur_ja4_alpn in JA4_WEB_PREFIXES
    is_browser_cipher = (ja4_cipher and
                         browser_ja4_ciphers.get(ja4_cipher, 0) >= BROWSER_JA4_FLOOR)

    # Same cipher set + this flow's JA4 also encodes web ALPN → real browser
    if is_browser_cipher and cur_ja4_is_web:
        conf -= BROWSER_JA4_PENALTY
        indicators.append("browser_ja4_cipher_set")

    # Same cipher set BUT no ALPN offered → malware mimicking browser TLS
    if is_browser_cipher and cur_ja4_alpn == "00":
        conf += 0.20
        indicators.append("browser_cipher_no_alpn")

    # TLS 1.3 + no ALPN = Go TLS stack (Sliver, CS-Go, etc.)
    if cur_ja4_alpn == "00" and st.tls_version in ("TLSv13", "TLS13", "TLSv1.3"):
        conf += 0.15
        indicators.append("tls13_no_alpn")

    if not st.sni or st.sni in ("(empty)", "-"):
        conf += 0.10; indicators.append("no_sni")
    if has_suspect_issuer(st.issuer):
        conf += 0.25; indicators.append("suspect_issuer")
    if st.validation:
        if "self signed" in st.validation or "expired" in st.validation or "signature failure" in st.validation:
            conf += 0.15; indicators.append("bad_cert_validation")
        elif "unable to get local issuer" in st.validation:
            conf += 0.05; indicators.append("unrooted_cert_chain")

    # ALPN explicitly non-web (e.g. exotic protocol).
    if st.alpn and st.alpn not in ("", "-", "h2", "http/1.1", "http/1.0", "h3", "h2c"):
        conf += 0.10; indicators.append("nonstandard_alpn")

    # Cert/SNI mismatch — uses Zeek's SAN-aware verdict, which we
    # compute in the main loop using x509.log's san.dns field.
    if st.sni_matches_cert == "F":
        conf += CERT_SNI_MISMATCH_BONUS
        indicators.append("cert_sni_mismatch")

    # Valid CA chain + SNI matches cert = probably-legitimate service.
    # Reduced penalty for strong-behaviour (pinned/tight) beacons so a cheap
    # free-CA cert can't suppress CobaltStrike/Sliver-over-Let's-Encrypt.
    if st.sni_matches_cert == "T" and st.validation == "ok":
        strong_behaviour = pinned or is_tight
        conf -= (VALID_CERT_MATCH_PENALTY_STRONG_BEACON if strong_behaviour
                 else VALID_CERT_MATCH_PENALTY)
        indicators.append("valid_cert_match")

    # Pure-download flow penalty.
    total_orig = sum(st.orig_size)
    total_resp = sum(st.resp_size)
    if total_orig + total_resp > 0:
        flow_pcr = (total_orig - total_resp) / (total_orig + total_resp)
        if flow_pcr < MAX_DOWNLOAD_PCR:
            conf -= PURE_DOWNLOAD_PENALTY
            indicators.append("pure_download_flow")

    # Common-JA3 + popular-ish destination penalty.
    ja3_pop = len(ja3_client_count.get(st.ja3, set()))
    dest_pop_n = len(dest_client_count.get(key[1], set()))
    if ja3_pop >= COMMON_JA3_FLOOR and dest_pop_n >= POPULAR_DEST_THRESHOLD * 0.5:
        conf -= COMMON_JA3_PENALTY
        indicators.append("common_ja3_to_popular_dest")

    if dest_pop_n == 1:
        indicators.append("single_client_destination")
    elif dest_pop_n <= POPULAR_DEST_THRESHOLD:
        indicators.append(f"rare_destination_{dest_pop_n}_clients")

    if conf < ALERT_CONFIDENCE:
        return None

    # ---- Beacon-exfil escalation (models SSL_BEACON_EXFIL) ----
    exfil = None
    dominant = max(total_orig, total_resp)
    abs_skew = abs(flow_pcr) if (total_orig + total_resp) > 0 else 0.0
    if dominant >= EXFIL_MIN_BYTES and abs_skew >= EXFIL_MIN_PCR_SKEW:
        is_upload = total_orig > total_resp
        exfil = {
            "direction": "upload/exfil" if is_upload else "download/payload",
            "confidence": round(min(EXFIL_BASE_CONFIDENCE +
                          (EXFIL_UPLOAD_BONUS if is_upload else 0.0), 1.0), 2),
            "orig": total_orig, "resp": total_resp, "pcr": round(flow_pcr, 2),
        }

    return {
        "category": "SSL_RESUMPTION_PINNED_BEACON" if pinned else "SSL_PERIODIC_BEACON",
        "orig_h": key[0], "dest_id": key[1], "ja3": key[2],
        "resp_h": st.last_resp_h, "sni": st.sni, "issuer": st.issuer,
        "samples": len(st.ts),
        "median_interval_s": round(med, 2),
        "exfil": exfil,
        "obs_duration_s": round(obs_duration, 1),
        "jitter_pct": round(jitter * 100, 1),
        "resumption_pct": round(res_ratio * 100, 1),
        "confidence": round(min(conf, 1.0), 2),
        "indicators": indicators,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logs_dir", type=Path)
    args = ap.parse_args()

    ssl_log  = normalize_rows(load_zeek_log(args.logs_dir / "ssl.log"))
    conn_log = normalize_rows(load_zeek_log(args.logs_dir / "conn.log"))
    x509_log = normalize_rows(load_zeek_log(args.logs_dir / "x509.log")) if (args.logs_dir / "x509.log").exists() else []

    conn_by_uid = {r["uid"]: r for r in conn_log}
    x509_by_fp  = {r["fingerprint"]: r for r in x509_log}

    flow_state: dict = defaultdict(FlowState)
    dest_client_count: dict = defaultdict(set)
    ja3_client_count: dict = defaultdict(set)
    browser_ja4_ciphers: dict = defaultdict(int)
    popular_dests: set = set()

    skipped_safe = skipped_floor = skipped_popular = skipped_grace = processed = 0

    for r in ssl_log:
        if r.get("established", "F") != "T":
            continue
        # Direction filter — outbound only (internal orig -> external resp).
        if not is_outbound(r.get("id.orig_h", ""), r.get("id.resp_h", "")):
            continue
        sni = r.get("server_name", "")
        if is_sni_safe(sni):
            skipped_safe += 1
            continue
        uid = r["uid"]
        c = conn_by_uid.get(uid)
        if not c:
            continue
        try:
            ob_raw = c.get("orig_bytes", 0)
            rb_raw = c.get("resp_bytes", 0)
            ob = int(ob_raw) if ob_raw not in ("-", None) else 0
            rb = int(rb_raw) if rb_raw not in ("-", None) else 0
        except (ValueError, TypeError):
            ob = rb = 0
        if ob + rb < MIN_TRACK_BYTES:
            skipped_floor += 1
            continue

        orig    = r["id.orig_h"]
        dest_id = sni.lower() if sni and sni not in ("(empty)", "-") else r["id.resp_h"]
        ja3     = r.get("ja3", "")
        if ja3 == "-": ja3 = ""
        key = (orig, dest_id, ja3)

        # Always update popularity counters first.
        ja3_client_count[ja3].add(orig)
        if dest_id not in popular_dests:
            dest_client_count[dest_id].add(orig)
            if len(dest_client_count[dest_id]) > POPULAR_DEST_THRESHOLD:
                # Destination just crossed the popularity threshold —
                # mark it popular and evict any existing flow_state for it.
                popular_dests.add(dest_id)
                victims = [k for k in flow_state if k[1] == dest_id]
                for v in victims:
                    del flow_state[v]
                # Reclaim memory.
                del dest_client_count[dest_id]

        # Skip tracking entirely if destination is popular.
        if dest_id in popular_dests:
            skipped_popular += 1
            continue

        # Issuer / subject / cert names from x509 via first cert fingerprint.
        # If the user's ssl.log already has a sni_matches_cert verdict,
        # prefer that — it's exactly what Zeek's x509_check_cert_hostname()
        # computed at parse time. Otherwise reconstruct from x509.log SAN.
        issuer = ""
        subject = ""
        cert_names = []
        cert_fps = r.get("cert_chain_fps", "")
        if cert_fps and cert_fps not in ("(empty)", "-"):
            x = x509_by_fp.get(cert_fps.split(",")[0])
            if x:
                issuer = x.get("certificate.issuer", "")
                subject = x.get("certificate.subject", "")
                cert_names = names_from_cert(x)

        # Zeek's verdict if present — most accurate (uses live cert,
        # not just what's in our x509.log).
        zeek_verdict = r.get("sni_matches_cert", "")

        ts = float(r["ts"])
        st = flow_state[key]
        if not st.first_seen:
            st.first_seen = ts
        st.last_seen = ts
        st.last_resp_h = r["id.resp_h"]
        if sni and sni not in ("(empty)", "-"):
            st.sni = sni
        if not st.ja3 and ja3:
            st.ja3 = ja3
        val = r.get("validation_status", "")
        if val and val not in ("-", "(empty)"):
            st.validation = val
        if issuer:
            st.issuer = issuer
        if subject:
            st.subject = subject
        ver = r.get("version", "")
        if ver and ver not in ("-", "(empty)"):
            st.tls_version = ver

        # Determine SAN-aware match verdict for THIS connection.
        this_verdict = ""
        if zeek_verdict in ("T", "F"):
            this_verdict = zeek_verdict
        elif cert_names and sni and sni not in ("(empty)", "-"):
            this_verdict = "T" if sni_matches_any_cert_name(sni, cert_names) else "F"

        # Sticky update: once F (mismatch), stay F. Once T, stay T unless
        # we see F. This mirrors update_flow_state in detect.zeek.
        if this_verdict == "F":
            st.sni_matches_cert = "F"
        elif this_verdict == "T" and st.sni_matches_cert != "F":
            st.sni_matches_cert = "T"

        # ---- ALPN handling ----
        # Both directly observed next_protocol AND the JA4 first-segment
        # ALPN field count as evidence the client speaks HTTP. Once
        # set, seen_web_alpn is sticky (never reset) — resumed sessions
        # don't carry ALPN, so we have to remember.
        alpn = r.get("next_protocol", "")
        if alpn and alpn not in ("-", "(empty)"):
            st.alpn = alpn
            if alpn.lower() in WEB_ALPNS:
                st.seen_web_alpn = True

        ja4 = r.get("ja4", "")
        if ja4 and ja4 not in ("-", "(empty)"):
            st.ja4 = ja4
            # Extract first-segment last-2-chars (JA4 ALPN field).
            parts = ja4.split("_")
            if parts:
                first = parts[0]
                if len(first) >= 2:
                    ja4_alpn = first[-2:]
                    if ja4_alpn in JA4_WEB_PREFIXES:
                        st.seen_web_alpn = True
                        # Also bump network-wide browser-cipher counter.
                        if len(parts) >= 2:
                            browser_ja4_ciphers[parts[1]] += 1

        # Server fingerprint — marks bidirectional communication.
        ja3s = r.get("ja3s", "")
        ja4s = r.get("ja4s", "")
        if (ja3s and ja3s not in ("-", "(empty)")) or \
           (ja4s and ja4s not in ("-", "(empty)")):
            st.server_seen = True

        # Track total_seen on a side counter so we can apply grace period.
        # In Zeek this is st$total_seen; here we use len(st.ts) once we
        # decide to actually populate the window.
        # Grace period: skip window population for first FLOW_GRACE_COUNT
        # connections (use a hidden counter on the dataclass).
        if not hasattr(st, "_total_seen"):
            st._total_seen = 0
        st._total_seen += 1

        if st._total_seen <= FLOW_GRACE_COUNT:
            skipped_grace += 1
            continue

        st.ts.append(ts)
        st.orig_size.append(ob)
        st.resp_size.append(rb)
        st.resumed.append(r.get("resumed", "F") == "T")
        processed += 1

    print(f"# ssl.log: {processed} rows tracked, "
          f"{skipped_safe} safe-SNI, {skipped_floor} byte-floor, "
          f"{skipped_popular} popular-dest, {skipped_grace} grace-period")
    print(f"# Tracking {len(flow_state)} distinct flows, "
          f"{len(popular_dests)} destinations marked popular")
    print()
    hdr = f"{'Category':<32} {'Orig':<14} {'Dest':<28} {'N':>5} {'Int_s':>7} {'Jit%':>5} {'Res%':>5} {'Conf':>5}  Indicators"
    print(hdr)
    print("-" * len(hdr))

    alerts = sorted(
        [a for a in (evaluate_beacon(k, st, dest_client_count,
                                     ja3_client_count, browser_ja4_ciphers)
                     for k, st in flow_state.items()) if a],
        key=lambda a: -a["confidence"]
    )
    for a in alerts:
        print(f"{a['category']:<32} {a['orig_h']:<14} {a['dest_id'][:28]:<28} "
              f"{a['samples']:>5} {a['median_interval_s']:>7.1f} "
              f"{a['jitter_pct']:>5.0f} {a['resumption_pct']:>5.0f} "
              f"{a['confidence']:>5.2f}  {','.join(a['indicators'])}")
        if a.get("exfil"):
            ex = a["exfil"]
            print(f"  \\__ SSL_BEACON_EXFIL  dir={ex['direction']} "
                  f"orig={ex['orig']:,} resp={ex['resp']:,} "
                  f"pcr={ex['pcr']} conf={ex['confidence']:.2f}")
    if not alerts:
        print("(no alerts — check thresholds or log content)")

    # Verify O365 is correctly bypassed
    print()
    print("# O365/Teams/Microsoft bypass verification:")
    ms_snis = [r.get("server_name","") for r in ssl_log
               if r.get("established","F") == "T"
               and is_sni_safe(r.get("server_name",""))]
    ms_sample = sorted(set(s for s in ms_snis if s and s != "(empty)"))[:12]
    if ms_sample:
        print(f"#   Safe-bypassed Microsoft SNIs (first 12): {ms_sample}")
    else:
        print("#   No Microsoft SNIs in this log sample (expected for malware sandboxes)")

if __name__ == "__main__":
    main()
