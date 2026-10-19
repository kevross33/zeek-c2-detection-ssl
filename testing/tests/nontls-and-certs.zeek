# @TEST-DOC: Non-TLS-on-TLS-port gate (connection history) and alert rule,
#            and certificate key-identifier normalisation used by the
#            self-signed / forged-issuer label.
#
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-diff out

@load c2-detection-ssl

event zeek_init()
    {
    # ---- History gate ----
    # Real SECTOPRAT C2 session: start seen, data both ways, no gaps.
    print fmt("history ShAdDawwwTwTfF = %s (expect T)",
              C2_SSL::nontls_history_ok("ShAdDawwwTwTfF") ? "T" : "F");
    # Retry that carried no data.
    print fmt("history ShAfFa = %s (expect F, no data)",
              C2_SSL::nontls_history_ok("ShAfFa") ? "T" : "F");
    # Joined mid-stream (sensor restart): the start was never seen.
    print fmt("history DdAaTt = %s (expect F, mid-stream)",
              C2_SSL::nontls_history_ok("DdAaTt") ? "T" : "F");
    # Content gap: a ClientHello could have been missed.
    print fmt("history ShADdgG = %s (expect F, gap)",
              C2_SSL::nontls_history_ok("ShADdgG") ? "T" : "F");
    # Upload only, server never sent data.
    print fmt("history ShADaF = %s (expect F, one-way)",
              C2_SSL::nontls_history_ok("ShADaF") ? "T" : "F");

    # ---- Alert rule (intel, host, cadence, exfil, session) ----
    print fmt("intel+exfil+session = %d (expect 3)",
              C2_SSL::nontls_decide(T, F, F, T, T));
    print fmt("intel alone = %d (expect 0)",
              C2_SSL::nontls_decide(T, F, F, F, F));
    print fmt("exfil+session (shape only) = %d (expect 0)",
              C2_SSL::nontls_decide(F, F, F, T, T));
    print fmt("host+session = %d (expect 0)",
              C2_SSL::nontls_decide(F, T, F, F, T));
    print fmt("host+exfil = %d (expect 2)",
              C2_SSL::nontls_decide(F, T, F, T, F));
    print fmt("cadence+host = %d (expect 2)",
              C2_SSL::nontls_decide(F, T, T, F, F));

    # ---- Key identifier normalisation ----
    print fmt("key_id_hex(OpenSSL 1.1 AKI) = %s",
              C2_SSL::key_id_hex("keyid:8A:23:EB:9E:6B:D7:F9:37:5D:F9:6D:21:39:76:9A:A1:D4:5A:3E:2E\n"));
    print fmt("key_id_hex(OpenSSL 3 AKI) = %s",
              C2_SSL::key_id_hex("8A:23:EB:9E:6B:D7:F9:37:5D:F9:6D:21:39:76:9A:A1:D4:5A:3E:2E"));
    print fmt("key_id_hex(AKI with DirName/serial) = %s",
              C2_SSL::key_id_hex("keyid:AA:BB:CC:DD\nDirName:/CN=Fake CA\nserial:01:02:03\n"));
    print fmt("key_id_hex(no hex) = '%s' (expect empty)",
              C2_SSL::key_id_hex("not a key id"));
    }
