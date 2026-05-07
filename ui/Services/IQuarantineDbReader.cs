using NullBot.UI.Models;

namespace NullBot.UI.Services;

/// <summary>
/// Read-only view of quarantine.db. Restore and delete are delegated to the CLI
/// because they require the AES-256 vault key and proper file system cleanup.
/// </summary>
public interface IQuarantineDbReader
{
    Task<IReadOnlyList<QuarantinedItem>> GetAllItemsAsync(CancellationToken ct = default);
    Task<int> GetItemCountAsync(CancellationToken ct = default);
}
