# @TEST-DOC: The package must load cleanly and create the c2_detections_ssl log stream.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff zeek-output

@load c2-detection-ssl

event zeek_init()
    {
    if ( C2_SSL::LOG !in Log::active_streams )
        {
        print "FAIL: c2_detections_ssl log stream not registered";
        exit(1);
        }
    print "OK: c2_detections_ssl log stream registered";
    }
