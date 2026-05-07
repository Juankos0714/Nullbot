namespace NullBot.UI.Models;

public record ScanResult(
    DateTime StartedAt,
    DateTime CompletedAt,
    int FilesScanned,
    IReadOnlyList<ThreatDetection> Threats
)
{
    public int ThreatCount => Threats.Count;
    public TimeSpan Duration => CompletedAt - StartedAt;

    public int CountBySeverity(ThreatSeverity severity) =>
        Threats.Count(t => t.Severity == severity);
}
