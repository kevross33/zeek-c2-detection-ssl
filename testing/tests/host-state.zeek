# @TEST-DOC: Host-compromise correlation, payload-staging correlation,
#            tracked-C2-fingerprint pivot, and the destination fan-out /
#            popularity tracking all behave correctly. The fan-out case is a
#            regression guard for the popular_dests &write_expire fix (it
#            must use &write_expire, not &create_expire, or an actively-used
#            popular destination would silently expire and have to re-earn
#            popularity from zero — see shared.zeek).
#
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-diff out

@load c2-detection-ssl

event zeek_init()
    {
    local victim = 10.5.5.5;
    local other  = 10.5.5.6;

    # ---- Host compromise: not compromised until marked ----
    print fmt("is_host_compromised(unmarked) = %s (expect F)",
              (C2_SSL::is_host_compromised(victim) ? "T" : "F"));

    # Use a deliberately rare, non-browser-shaped JA3/JA4 so the fingerprint
    # gets armed (real browser stacks and common fingerprints are correctly
    # excluded from arming — see mark_host_compromised).
    local rare_ja3 = "deadbeefcafef00d0123456789abcdef";
    local rare_ja4 = "t00i000000_aaaaaaaaaaaa_bbbbbbbbbbbb";
    C2_SSL::mark_host_compromised(victim, rare_ja3, rare_ja4);
    print fmt("is_host_compromised(marked) = %s (expect T)",
              (C2_SSL::is_host_compromised(victim) ? "T" : "F"));
    print fmt("is_host_compromised(unrelated host) = %s (expect F)",
              (C2_SSL::is_host_compromised(other) ? "T" : "F"));

    # ---- Tracked C2 fingerprint pivot: exact match on JA3 or JA4 ----
    print fmt("is_tracked_c2_fingerprint(same JA3) = %s (expect T)",
              (C2_SSL::is_tracked_c2_fingerprint(rare_ja3, "", other) ? "T" : "F"));
    print fmt("is_tracked_c2_fingerprint(same JA4) = %s (expect T)",
              (C2_SSL::is_tracked_c2_fingerprint("", rare_ja4, other) ? "T" : "F"));
    print fmt("is_tracked_c2_fingerprint(unrelated fp) = %s (expect F)",
              (C2_SSL::is_tracked_c2_fingerprint("0000000000000000000000000000000",
                                                 "", other) ? "T" : "F"));

    # ---- Payload staging: short-lived marker for stage-transition corroboration ----
    print fmt("is_payload_staged(unmarked) = %s (expect F)",
              (C2_SSL::is_payload_staged(victim) ? "T" : "F"));
    C2_SSL::mark_payload_staged(victim);
    print fmt("is_payload_staged(marked) = %s (expect T)",
              (C2_SSL::is_payload_staged(victim) ? "T" : "F"));

    # ---- Destination fan-out / popularity (popular_dest_threshold = 3) ----
    local dest = "198.51.100.10";
    print fmt("dest_client_n(never seen) = %d (expect 0)",
              C2_SSL::dest_client_n(dest));

    C2_SSL::note_dest_client(dest, 10.9.9.1);
    C2_SSL::note_dest_client(dest, 10.9.9.2);
    C2_SSL::note_dest_client(dest, 10.9.9.3);
    print fmt("dest_client_n(3 distinct clients, at threshold) = %d (expect 3, not yet popular)",
              C2_SSL::dest_client_n(dest));
    print fmt("is_dest_popular(at threshold) = %s (expect F)",
              (C2_SSL::is_dest_popular(dest) ? "T" : "F"));

    # 4th distinct client crosses the threshold (> 3) and flips it popular.
    C2_SSL::note_dest_client(dest, 10.9.9.4);
    print fmt("is_dest_popular(4 distinct clients) = %s (expect T)",
              (C2_SSL::is_dest_popular(dest) ? "T" : "F"));
    print fmt("dest_client_n(popular) = %d (expect 4, popular_dest_threshold+1)",
              C2_SSL::dest_client_n(dest));

    # Re-adding an already-popular destination must be a WRITE (refreshes
    # &write_expire) and must NOT change the reported count or drop out of
    # popular_dests. This is the exact behaviour the write_expire fix relies
    # on — see note_dest_client's early-return-on-refresh branch.
    C2_SSL::note_dest_client(dest, 10.9.9.1);
    print fmt("is_dest_popular(after refresh re-add) = %s (expect T, still popular)",
              (C2_SSL::is_dest_popular(dest) ? "T" : "F"));
    print fmt("dest_client_n(after refresh re-add) = %d (expect 4, unchanged)",
              C2_SSL::dest_client_n(dest));
    }
