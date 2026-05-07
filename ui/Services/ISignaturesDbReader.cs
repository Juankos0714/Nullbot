namespace NullBot.UI.Services;

/// <summary>Read-only access to signatures.db — never writes, never conflicts with the updater.</summary>
public interface ISignaturesDbReader
{
    Task<int> GetSignatureCountAsync(CancellationToken ct = default);
    Task<DateTime?> GetLastUpdateTimeAsync(CancellationToken ct = default);
}
