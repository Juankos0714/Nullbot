namespace NullBot.UI.Models;

public record QuarantinedItem(
    string Id,
    string ThreatName,
    string OriginalPath,
    DetectionType DetectionType,
    DateTime QuarantinedAt,
    long SizeBytes
);
