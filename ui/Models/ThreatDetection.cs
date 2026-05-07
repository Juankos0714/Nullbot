namespace NullBot.UI.Models;

public enum ThreatSeverity { Low, Medium, High, Critical }

public enum DetectionType { Signature, Heuristic, C2, DGA, Behavioral }

public record ThreatDetection(
    string Id,
    string ThreatName,
    string FilePath,
    ThreatSeverity Severity,
    DetectionType DetectionType,
    DateTime DetectedAt,
    string? Hash
);
