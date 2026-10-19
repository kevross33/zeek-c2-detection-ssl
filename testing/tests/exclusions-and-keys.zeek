# @TEST-DOC: Allowlist robustness (trailing-dot FQDNs, vendor apex domains),
#            allowlist propagation to SNI-less connections via learned safe
#            IPs, the resumption-invariant flow-grouping key, and that cluster
#            sharing is inert in standalone mode.
#
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-diff out

@load c2-detection-ssl

# These behaviours default OFF (1.0-equivalent); enable them for this test.
redef C2_SSL::safe_ip_learning_enabled = T;
redef C2_SSL::flowkey_resumption_invariant = T;

event zeek_init()
    {
    # ---- Allowlist: trailing-dot FQDN must still match ----
    print fmt("is_sni_fully_safe(update.eset.com.) = %s (expect T, trailing dot)",
              C2_SSL::is_sni_fully_safe("update.eset.com.") ? "T" : "F");
    print fmt("is_sni_fully_safe(ts.e5.sk) = %s (expect T, ESET LiveGrid apex)",
              C2_SSL::is_sni_fully_safe("ts.e5.sk") ? "T" : "F");
    print fmt("is_sni_fully_safe(x.esetsoftware.com) = %s (expect T)",
              C2_SSL::is_sni_fully_safe("x.esetsoftware.com") ? "T" : "F");
    print fmt("is_sni_fully_safe(fakee5.sk) = %s (expect F, not a real suffix)",
              C2_SSL::is_sni_fully_safe("fakee5.sk") ? "T" : "F");

    # ---- Learned safe IPs (allowlist propagation to SNI-less flows) ----
    print fmt("is_learned_safe_ip(203.0.113.7) before = %s (expect F)",
              C2_SSL::is_learned_safe_ip(203.0.113.7) ? "T" : "F");
    C2_SSL::note_safe_dest_ip(203.0.113.7);
    print fmt("is_learned_safe_ip(203.0.113.7) after = %s (expect T)",
              C2_SSL::is_learned_safe_ip(203.0.113.7) ? "T" : "F");
    print fmt("is_learned_safe_ip(203.0.113.8) unrelated = %s (expect F)",
              C2_SSL::is_learned_safe_ip(203.0.113.8) ? "T" : "F");

    # ---- Resumption-invariant flow key ----
    # Same Chromium client: full handshake (16 exts) vs resumed (17 exts,
    # pre_shared_key added). Must group into ONE flow.
    local full = C2_SSL::flow_fp("", "t13d1516h2_8daaf6152771_02713d6af862");
    local resumed = C2_SSL::flow_fp("", "t13d1517h2_8daaf6152771_a87ad97598a9");
    print fmt("flow_fp(full) = %s (expect t13d15h2_8daaf6152771)", full);
    print fmt("flow_fp(full) == flow_fp(resumed) = %s (expect T)",
              full == resumed ? "T" : "F");
    # Different cipher set must NOT merge.
    print fmt("flow_fp(other cipher) differs = %s (expect T)",
              C2_SSL::flow_fp("", "t13d1516h2_aaaaaaaaaaaa_02713d6af862") != full
              ? "T" : "F");
    # JA3-only and malformed JA4 fall back to primary_fp.
    print fmt("flow_fp(ja3 only) = %s (expect abc123)",
              C2_SSL::flow_fp("abc123", ""));
    print fmt("flow_fp(malformed ja4) = %s (expect short)",
              C2_SSL::flow_fp("", "short"));

    # ---- Cluster sharing is inert outside a cluster ----
    print fmt("cluster_sharing_active() standalone = %s (expect F)",
              C2_SSL::cluster_sharing_active() ? "T" : "F");
    }
