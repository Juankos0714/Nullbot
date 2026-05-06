#pragma once

/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: network/c2_detection/beacon_math.h
 *
 * Pure stateless helpers for beaconing statistical analysis.
 * No system includes beyond <vector> and <cmath>.
 */

#include <limits>
#include <vector>
#include <cmath>

namespace nullbot::network::beacon_math {

// Population mean of v. Returns 0.0 for empty input.
inline double Mean(const std::vector<double>& v) {
    if (v.empty()) return 0.0;
    double sum = 0.0;
    for (double x : v) sum += x;
    return sum / static_cast<double>(v.size());
}

// Population standard deviation of v given a precomputed mean.
// Returns 0.0 for fewer than 2 samples (undefined otherwise).
inline double StdDev(const std::vector<double>& v, double mean) {
    if (v.size() < 2) return 0.0;
    double sum_sq = 0.0;
    for (double x : v) {
        double d = x - mean;
        sum_sq += d * d;
    }
    return std::sqrt(sum_sq / static_cast<double>(v.size()));
}

// Coefficient of variation (stddev / mean). Returns infinity for mean == 0.
// Callers must guard against mean == 0 before using the result in a comparison.
inline double CoeffVariation(double stddev, double mean) {
    if (mean == 0.0) return std::numeric_limits<double>::infinity();
    return stddev / mean;
}

} // namespace nullbot::network::beacon_math
