namespace NullBot.UI.Models;

public enum ProtectionLevel { Safe, Warning, Danger }

public record ProtectionStatus(
    ProtectionLevel Level,
    bool FilesystemWatcherActive,
    bool NetworkMonitorActive,
    bool AmsiProviderActive,
    int SignatureCount,
    DateTime? LastSignatureUpdate,
    int QuarantineCount,
    int C2AlertsLast24h
)
{
    public static ProtectionStatus Empty => new(
        ProtectionLevel.Safe,
        FilesystemWatcherActive: false,
        NetworkMonitorActive: false,
        AmsiProviderActive: false,
        SignatureCount: 0,
        LastSignatureUpdate: null,
        QuarantineCount: 0,
        C2AlertsLast24h: 0);
}
