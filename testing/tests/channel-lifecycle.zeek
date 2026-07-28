# @TEST-DOC: The channel-phase lifecycle transition memory correctly
#            recognises BOTH orderings (quiet-then-reverse and
#            reverse-then-quiet) as a transition, and correctly does NOT
#            fire on a single repeated phase or an unrelated channel.
#
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-diff out

@load c2-detection-ssl

event zeek_init()
    {
    local h1 = 10.1.1.1;
    local h2 = 10.1.1.2;
    local h3 = 10.1.1.3;
    local d1 = "203.0.113.10";
    local d2 = "203.0.113.20";

    # ---- Case 1: single phase, repeated many times -> NO transition ----
    # A quiet beacon that just keeps beaconing must never look like a
    # transition just because it was observed multiple times.
    C2_SSL::note_channel_phase(h1, d1, C2_SSL::CHANNEL_PHASE_BEACON);
    C2_SSL::note_channel_phase(h1, d1, C2_SSL::CHANNEL_PHASE_BEACON);
    C2_SSL::note_channel_phase(h1, d1, C2_SSL::CHANNEL_PHASE_BEACON);
    print fmt("h1->d1 after 3x BEACON only: has_transition = %s (expect F)",
              (C2_SSL::channel_has_transition(h1, d1) ? "T" : "F"));

    # ---- Case 2: quiet (tunnel) THEN reverse-flow -> transition ----
    C2_SSL::note_channel_phase(h2, d1, C2_SSL::CHANNEL_PHASE_TUNNEL);
    print fmt("h2->d1 after TUNNEL only: has_transition = %s (expect F)",
              (C2_SSL::channel_has_transition(h2, d1) ? "T" : "F"));
    C2_SSL::note_channel_phase(h2, d1, C2_SSL::CHANNEL_PHASE_REVERSE);
    print fmt("h2->d1 after TUNNEL then REVERSE: has_transition = %s (expect T)",
              (C2_SSL::channel_has_transition(h2, d1) ? "T" : "F"));

    # ---- Case 3: reverse-flow THEN quiet (beacon) -> transition, other order ----
    # This is the "hello/recon then goes quiet" ordering.
    C2_SSL::note_channel_phase(h3, d2, C2_SSL::CHANNEL_PHASE_REVERSE);
    print fmt("h3->d2 after REVERSE only: has_transition = %s (expect F)",
              (C2_SSL::channel_has_transition(h3, d2) ? "T" : "F"));
    C2_SSL::note_channel_phase(h3, d2, C2_SSL::CHANNEL_PHASE_BEACON);
    print fmt("h3->d2 after REVERSE then BEACON (reverse-first ordering): has_transition = %s (expect T)",
              (C2_SSL::channel_has_transition(h3, d2) ? "T" : "F"));

    # ---- Case 4: an unrelated channel (different orig, same dest) must not
    #      inherit another host's phase history ----
    print fmt("h1->d2 (never touched): has_transition = %s (expect F)",
              (C2_SSL::channel_has_transition(h1, d2) ? "T" : "F"));

    # ---- Case 5: first_phase is recorded correctly for each ordering ----
    local mem2 = C2_SSL::note_channel_phase(h2, d1, C2_SSL::CHANNEL_PHASE_TUNNEL);
    print fmt("h2->d1 first_phase = %s (expect tunnel)", mem2$first_phase);
    local mem3 = C2_SSL::note_channel_phase(h3, d2, C2_SSL::CHANNEL_PHASE_BEACON);
    print fmt("h3->d2 first_phase = %s (expect reverse)", mem3$first_phase);
    }
