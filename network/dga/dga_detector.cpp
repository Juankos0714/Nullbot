/*
 * NullBot — Open Source Anti-Botnet | GPL-3.0
 * File: network/dga/dga_detector.cpp
 */

#include "network/dga/dga_detector.h"

#include <algorithm>
#include <cmath>
#include <numeric>

namespace nullbot {
namespace network {

DGADetector::DGADetector() = default;

bool DGADetector::LoadNgramModel(const std::string&) { return false; }

void DGADetector::SetConfidenceThreshold(double threshold) {
    confidence_threshold_ = threshold;
}

DGAAnalysisResult DGADetector::Analyze(const std::string& domain) const {
    DGAAnalysisResult result;
    const std::string sld = ExtractSecondLevelDomain(domain);
    if (sld.empty()) return result;

    result.entropy_score     = ComputeEntropy(sld);
    result.ngram_score       = ComputeNgramScore(sld);
    result.vowel_ratio_score = ComputeVowelRatioScore(sld);
    result.length_score      = ComputeLengthScore(sld);

    result.confidence = (result.entropy_score * 0.40 +
                         result.ngram_score   * 0.30 +
                         result.vowel_ratio_score * 0.20 +
                         result.length_score  * 0.10);

    result.is_likely_dga = result.confidence >= confidence_threshold_;
    return result;
}

std::vector<std::pair<std::string, DGAAnalysisResult>>
DGADetector::FilterDGA(const std::vector<std::string>& domains) const {
    std::vector<std::pair<std::string, DGAAnalysisResult>> result;
    for (const auto& d : domains) {
        auto analysis = Analyze(d);
        if (analysis.is_likely_dga)
            result.emplace_back(d, std::move(analysis));
    }
    return result;
}

double DGADetector::ComputeEntropy(const std::string& s) const {
    if (s.empty()) return 0.0;
    int freq[256] = {};
    for (unsigned char c : s) freq[c]++;
    double entropy = 0.0;
    const auto len = static_cast<double>(s.size());
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / len;
        entropy -= p * std::log2(p);
    }
    return std::min(entropy / 4.0, 1.0);
}

double DGADetector::ComputeNgramScore(const std::string& domain) const {
    if (!model_loaded_ || domain.size() < 2) return 0.5;
    double score = 0.0;
    int    count = 0;
    for (size_t i = 0; i + 1 < domain.size(); ++i) {
        std::string bigram(1, domain[i]);
        bigram += domain[i + 1];
        auto it = bigram_freq_.find(bigram);
        score += (it == bigram_freq_.end()) ? 1.0 : (1.0 - it->second);
        ++count;
    }
    return count > 0 ? score / static_cast<double>(count) : 0.5;
}

double DGADetector::ComputeVowelRatioScore(const std::string& s) const {
    if (s.empty()) return 0.0;
    const std::string vowels = "aeiouAEIOU";
    double vowel_count = static_cast<double>(
        std::count_if(s.begin(), s.end(),
                      [&](char c) { return vowels.find(c) != std::string::npos; }));
    double ratio = vowel_count / static_cast<double>(s.size());
    return ratio < 0.15 ? 1.0 : (ratio > 0.45 ? 0.0 : 1.0 - (ratio - 0.15) / 0.30);
}

double DGADetector::ComputeLengthScore(const std::string& s) const {
    const size_t len = s.size();
    if (len < 6)  return 0.0;
    if (len > 20) return 1.0;
    return static_cast<double>(len - 6) / 14.0;
}

std::string DGADetector::ExtractSecondLevelDomain(const std::string& domain) const {
    size_t last_dot = domain.rfind('.');
    if (last_dot == std::string::npos || last_dot == 0) return domain;
    size_t prev_dot = domain.rfind('.', last_dot - 1);
    if (prev_dot == std::string::npos) return domain.substr(0, last_dot);
    return domain.substr(prev_dot + 1, last_dot - prev_dot - 1);
}

} // namespace network
} // namespace nullbot
