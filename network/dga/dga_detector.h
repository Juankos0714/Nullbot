#pragma once

/*
 * NullBot — DGA Detection Module
 * File: network/dga/dga_detector.h
 *
 * Detects Domain Generation Algorithm (DGA) domains used by botnets
 * to evade static blacklists. DGA domains are algorithmically generated
 * and appear as random, high-entropy strings.
 *
 * Detection techniques:
 * 1. Shannon entropy of domain name
 * 2. N-gram frequency analysis (compares against real English word corpus)
 * 3. Vowel/consonant ratio anomaly
 * 4. Dictionary word coverage
 * 5. Known DGA family signatures
 */

#include <string>
#include <vector>
#include <unordered_map>

namespace nullbot {
namespace network {

// ─── DGA analysis result ──────────────────────────────────────────────────────

struct DGAAnalysisResult {
    bool   is_likely_dga     = false;
    double confidence        = 0.0;   // 0.0 to 1.0

    // Sub-scores (0.0 to 1.0, higher = more suspicious)
    double entropy_score     = 0.0;
    double ngram_score       = 0.0;
    double vowel_ratio_score = 0.0;
    double length_score      = 0.0;

    std::string matched_family;  // If it matches a known DGA family pattern
    std::string explanation;
};

// ─── DGA Detector ─────────────────────────────────────────────────────────────

class DGADetector {
public:
    DGADetector();

    // Load n-gram model (pre-built from Alexa Top 1M domains)
    bool LoadNgramModel(const std::string& model_path);

    // Analyze a single domain
    DGAAnalysisResult Analyze(const std::string& domain) const;

    // Batch analysis — returns only likely DGA domains
    std::vector<std::pair<std::string, DGAAnalysisResult>>
    FilterDGA(const std::vector<std::string>& domains) const;

    // Threshold for DGA classification (default: 0.70)
    void SetConfidenceThreshold(double threshold);

private:
    // ── Feature extraction ────────────────────────────────────────────────────

    double ComputeEntropy(const std::string& s)         const;
    double ComputeNgramScore(const std::string& domain) const;
    double ComputeVowelRatioScore(const std::string& s) const;
    double ComputeLengthScore(const std::string& s)     const;

    std::string ExtractSecondLevelDomain(const std::string& domain) const;

    // ── N-gram model ──────────────────────────────────────────────────────────
    // Bigram frequency table built from legitimate domains
    std::unordered_map<std::string, double> bigram_freq_;
    bool model_loaded_ = false;

    double confidence_threshold_ = 0.70;

    // ── Known DGA families ────────────────────────────────────────────────────
    // Pattern-based detection for well-known botnets
    struct DGAFamily {
        std::string name;
        // Typical domain length range
        int min_length;
        int max_length;
        // Typical TLDs used
        std::vector<std::string> common_tlds;
        // Regex or characteristic (simplified)
        bool only_lowercase_alpha;
        bool no_vowels;
    };

    static const std::vector<DGAFamily> KNOWN_DGA_FAMILIES;
};

// ─── Known DGA families ───────────────────────────────────────────────────────

inline const std::vector<DGADetector::DGAFamily> DGADetector::KNOWN_DGA_FAMILIES = {
    {
        "Conficker",
        8, 16,
        { ".com", ".net", ".org", ".info", ".biz" },
        true, false
    },
    {
        "Zeus/Zbot",
        12, 20,
        { ".com", ".ru", ".in" },
        true, false
    },
    {
        "Mirai (variant)",
        8, 12,
        { ".com", ".xyz", ".top" },
        true, false
    },
    {
        "Necurs",
        10, 24,
        { ".com", ".net", ".info", ".top", ".xyz" },
        true, false
    },
    {
        "Locky",
        16, 24,
        { ".com", ".net" },
        true, false
    }
};

} // namespace network
} // namespace nullbot
