# @TEST-DOC: The safe-SNI allowlist is ABSOLUTE (suffix and apex matching,
#            with nothing able to revoke a match — this is a regression lock
#            for the masquerade-guard removal). ja4_is_browser_shape correctly
#            classifies real Chromium/BoringSSL JA4s (observed on a live
#            estate) as browser-shaped regardless of extension-count churn.
#
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-diff out

@load c2-detection-ssl

redef C2_SSL::safe_sni_suffixes += {
    ".testsafe.example",
    "apex.testsafe.example",
};

event zeek_init()
    {
    # ---- Suffix matching ----
    print fmt("is_sni_fully_safe(sub.testsafe.example) = %s (expect T)",
              (C2_SSL::is_sni_fully_safe("sub.testsafe.example") ? "T" : "F"));
    print fmt("is_sni_fully_safe(deep.sub.testsafe.example) = %s (expect T)",
              (C2_SSL::is_sni_fully_safe("deep.sub.testsafe.example") ? "T" : "F"));
    # Apex match: the bare suffix itself (no subdomain) must also match.
    print fmt("is_sni_fully_safe(testsafe.example) = %s (expect T, apex match)",
              (C2_SSL::is_sni_fully_safe("testsafe.example") ? "T" : "F"));
    # Case-insensitivity.
    print fmt("is_sni_fully_safe(SUB.TESTSAFE.EXAMPLE) = %s (expect T, case-insensitive)",
              (C2_SSL::is_sni_fully_safe("SUB.TESTSAFE.EXAMPLE") ? "T" : "F"));
    # Must NOT match on a bare substring that isn't a real suffix.
    print fmt("is_sni_fully_safe(nottestsafe.example) = %s (expect F, not a real suffix match)",
              (C2_SSL::is_sni_fully_safe("nottestsafe.example") ? "T" : "F"));
    print fmt("is_sni_fully_safe(evil.com) = %s (expect F)",
              (C2_SSL::is_sni_fully_safe("evil.com") ? "T" : "F"));
    print fmt("is_sni_fully_safe(empty) = %s (expect F)",
              (C2_SSL::is_sni_fully_safe("") ? "T" : "F"));

    # ---- JA4 browser-shape classification ----
    # Real Chromium/BoringSSL JA4s observed on a live estate: three clusters
    # differing ONLY in extension count (16/17/34), all sharing the
    # 8daaf6152771 BoringSSL cipher hash. All three must classify as browser
    # shape from the prefix envelope alone (t13 + SNI-present + h2 ALPN),
    # regardless of the extension-count churn between them.
    print fmt("ja4_is_browser_shape(cluster1, 16 ext) = %s (expect T)",
              (C2_SSL::ja4_is_browser_shape("t13d1517h2_8daaf6152771_a87ad97598a9") ? "T" : "F"));
    print fmt("ja4_is_browser_shape(cluster2, 16 ext) = %s (expect T)",
              (C2_SSL::ja4_is_browser_shape("t13d1516h2_8daaf6152771_02713d6af862") ? "T" : "F"));
    print fmt("ja4_is_browser_shape(cluster3, 34 ext) = %s (expect T)",
              (C2_SSL::ja4_is_browser_shape("t13d1534h2_8daaf6152771_095a2c1ad15d") ? "T" : "F"));

    # QUIC ('q' proto) is deliberately EXCLUDED from browser-shape
    # classification (conservative default — see shared.zeek).
    print fmt("ja4_is_browser_shape(QUIC proto) = %s (expect F, q excluded by design)",
              (C2_SSL::ja4_is_browser_shape("q13d1517h2_8daaf6152771_a87ad97598a9") ? "T" : "F"));

    # No SNI ('i' not 'd') is not the browser envelope this classifier covers.
    print fmt("ja4_is_browser_shape(no-SNI variant) = %s (expect F)",
              (C2_SSL::ja4_is_browser_shape("t13i1517h2_8daaf6152771_a87ad97598a9") ? "T" : "F"));

    # Malformed / too-short prefix must not crash, just return F.
    print fmt("ja4_is_browser_shape(malformed) = %s (expect F)",
              (C2_SSL::ja4_is_browser_shape("short") ? "T" : "F"));
    }
