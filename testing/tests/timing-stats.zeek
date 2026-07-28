# @TEST-DOC: Statistical signals added for jitter-outlier confirmation
#            (peak density, IQR spread, IAT entropy, lag-1 autocorrelation,
#            Bowley skewness) behave correctly on known inputs and edge cases.
#
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-diff out

@load c2-detection-ssl

event zeek_init()
    {
    # ---- quantile_sorted: linear-interpolation quantile ----
    local s8 = vector(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0);
    print fmt("quantile_sorted(1..8, 0.25) = %.2f (expect 2.75)",
              C2_SSL::quantile_sorted(s8, 0.25));
    print fmt("quantile_sorted(1..8, 0.75) = %.2f (expect 6.25)",
              C2_SSL::quantile_sorted(s8, 0.75));

    # ---- bowley_skewness: quartile-based robust skew ----
    local sym = vector(10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0);
    print fmt("bowley_skewness(symmetric) = %.2f (expect 0.00)",
              C2_SSL::bowley_skewness(sym));

    local skewed = vector(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 100.0, 200.0);
    print fmt("bowley_skewness(right-tail) = %.2f (expect 0.87)",
              C2_SSL::bowley_skewness(skewed));

    local too_few = vector(1.0, 2.0, 3.0);
    print fmt("bowley_skewness(n=3, too few) = %.2f (expect 0.00)",
              C2_SSL::bowley_skewness(too_few));

    # ---- iqr_spread: absolute spread of the middle 50% ----
    local jittered = vector(45.2, 48.7, 52.1, 55.9, 58.3, 61.4, 44.8, 49.6,
                             53.2, 57.7, 60.1, 46.5, 50.9, 54.4, 59.2, 47.1,
                             51.6, 56.0, 62.3, 43.9);
    print fmt("iqr_spread(jittered, n=20) = %.2f (expect 9.55)",
              C2_SSL::iqr_spread(jittered));
    print fmt("iqr_spread(n=3, too few) = %.2f (expect 0.00)",
              C2_SSL::iqr_spread(too_few));

    # ---- iat_entropy: relative-binned Shannon entropy of gaps ----
    # 9 samples dominate one bin, 3 sit in a clearly different bin: low but
    # non-zero entropy, i.e. "mostly predictable, not perfectly regular".
    local lowmix = vector(60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0,
                           60.0, 78.0, 78.0, 78.0);
    print fmt("iat_entropy(9-vs-3 mix) = %.2f (expect 0.81)",
              C2_SSL::iat_entropy(lowmix, 0.10));

    local varied = vector(10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0,
                           90.0, 100.0, 110.0, 120.0);
    print fmt("iat_entropy(widely varied) = %.2f (expect 3.58, high/chaotic)",
              C2_SSL::iat_entropy(varied, 0.10));

    local few_gaps = vector(60.0, 61.0, 59.0, 60.5, 59.5);
    print fmt("iat_entropy(n=5, below min_samples floor) = %.2f (expect 999.00, sentinel)",
              C2_SSL::iat_entropy(few_gaps, 0.10));

    # ---- lag1_autocorr: period-2 patterned-sleep detector ----
    local alt = vector(5.0, 10.0, 5.0, 10.0, 5.0, 10.0, 5.0, 10.0, 5.0, 10.0,
                        5.0, 10.0, 5.0, 10.0, 5.0, 10.0, 5.0, 10.0, 5.0, 10.0);
    print fmt("lag1_autocorr(alternating 5,10) = %.2f (expect -0.95, strong negative)",
              C2_SSL::lag1_autocorr(alt));

    local trend = vector(10.0, 15.0, 20.0, 25.0, 30.0, 35.0, 40.0, 45.0, 50.0, 55.0);
    print fmt("lag1_autocorr(trending) = %.2f (expect 0.70, POSITIVE - must never confirm)",
              C2_SSL::lag1_autocorr(trend));

    print fmt("lag1_autocorr(n=3, too few) = %.2f (expect 0.00)",
              C2_SSL::lag1_autocorr(too_few));

    # ---- peak_density: dominance of the modal response size ----
    local dominant_size = vector(100, 100, 100, 100, 100, 100, 100, 100, 200, 300);
    print fmt("peak_density(8/10 same size) = %.2f (expect 0.80)",
              C2_SSL::peak_density(dominant_size));

    local uniform_size = vector(100, 200, 300, 400, 500);
    print fmt("peak_density(all distinct) = %.2f (expect 0.20)",
              C2_SSL::peak_density(uniform_size));
    }
