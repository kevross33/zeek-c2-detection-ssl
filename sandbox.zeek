# C2_SSL — sandbox / offline-PCAP profile.
#
# The package now defaults to PRODUCTION thresholds (calibrated for a live
# sensor). When replaying SHORT offline captures — a few minutes of traffic,
# malware-sandbox PCAPs, unit tests — those production time/sample gates will
# suppress real detections simply because the capture is too short.
#
# Load this profile to relax the wall-clock and sample-count gates so a
# genuine beacon visible in a brief PCAP still fires:
#
#   @load c2-detection-ssl
#   @load c2-detection-ssl/sandbox
#
# Do NOT load this on a live production sensor — it lowers the evidence bar
# and will increase false positives at scale.

@load ./config

module C2_SSL;

redef deployment_profile               = SANDBOX_PROFILE;
redef beacon_alert_min_count           = 8;
redef beacon_min_observation_duration  = 5min;
redef pinning_min_count                = 5;
