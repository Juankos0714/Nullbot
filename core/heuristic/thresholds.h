#pragma once
// NullBot — Open Source Anti-Botnet | GPL-3.0
// File: core/heuristic/thresholds.h
//
// Single source of truth for all numerical detection thresholds.
// No logic, no system includes — only constexpr constants.

namespace nullbot::heuristic::thresholds {

constexpr double SECTION_ENTROPY_HIGH   = 7.2;  // Packed/encrypted section
constexpr double SECTION_ENTROPY_MEDIUM = 6.5;  // Potentially obfuscated section
constexpr int    MIN_SUSPICIOUS_IMPORTS = 3;    // Imports needed to flag PE
constexpr int    ANTI_DEBUG_MIN_CLUSTER = 3;    // Anti-debug imports to escalate

} // namespace nullbot::heuristic::thresholds
