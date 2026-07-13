# @TEST-DOC: Statistical helpers behave correctly on edge cases.
#
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-diff out

@load c2-detection-ssl

event zeek_init()
    {
    # median: odd count
    print fmt("median([1,2,3,4,5]) = %.1f (expect 3.0)",
              C2_SSL::median(vector(1.0, 2.0, 3.0, 4.0, 5.0)));

    # median: even count
    print fmt("median([1,2,3,4]) = %.1f (expect 2.5)",
              C2_SSL::median(vector(1.0, 2.0, 3.0, 4.0)));

    # MAD: spread around median
    local v = vector(1.0, 1.0, 1.0, 1.0, 1.0, 5.0);
    local m = C2_SSL::median(v);
    print fmt("median([1,1,1,1,1,5]) = %.1f (expect 1.0)", m);
    print fmt("MAD = %.1f (expect 0.0)", C2_SSL::mad(v, m));

    # mode: most frequent
    print fmt("mode([10,20,10,30,10]) = %d (expect 10)",
              C2_SSL::mode_count(vector(10, 20, 10, 30, 10)));

    # PCR: sanity at boundaries
    print fmt("pcr(100,0) = %.2f (expect 1.0)", C2_SSL::pcr(100, 0));
    print fmt("pcr(0,100) = %.2f (expect -1.0)", C2_SSL::pcr(0, 100));
    print fmt("pcr(50,50) = %.2f (expect 0.0)", C2_SSL::pcr(50, 50));
    print fmt("pcr(0,0) = %.2f (expect 0.0)", C2_SSL::pcr(0, 0));

    # dest_identity: SNI wins when present, IP-string when absent.
    print fmt("dest_identity_for(\"Foo.COM\", 1.2.3.4, F) = %s (expect foo.com)",
              C2_SSL::dest_identity_for("Foo.COM", 1.2.3.4, F));
    print fmt("dest_identity_for(\"\", 1.2.3.4, F) = %s (expect 1.2.3.4)",
              C2_SSL::dest_identity_for("", 1.2.3.4, F));
    print fmt("dest_identity_for(\"\", 1.2.3.4, T) = %s (expect proxy:1.2.3.4)",
              C2_SSL::dest_identity_for("", 1.2.3.4, T));
    }
