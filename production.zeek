# C2_SSL — production profile.
#
# Production thresholds are now the DEFAULT — you do not need to load this
# file. It is provided so an operator can @load it explicitly for clarity,
# and as the single place to see/pin the production values.
#
#   @load c2-detection-ssl            # production thresholds already active
#   @load c2-detection-ssl/production # optional, explicit — same effect
#
# The redefs below restate the built-in production defaults. They are safe
# to load (idempotent) and can be tuned per-site in local-exclusions.zeek.
#
# For replaying short offline PCAPs, load the sandbox profile instead, which
# relaxes the time/sample gates:  @load c2-detection-ssl/sandbox

@load ./config

module C2_SSL;

redef deployment_profile               = PRODUCTION_PROFILE;
redef beacon_alert_min_count           = 12;
redef beacon_min_observation_duration  = 15min;
redef pinning_min_count                = 8;
redef track_abandon_after              = 1hr;
redef flow_grace_count                 = 3;
