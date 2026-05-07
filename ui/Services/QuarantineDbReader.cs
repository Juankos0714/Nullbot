using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using NullBot.UI.Models;

namespace NullBot.UI.Services;

public sealed class QuarantineDbReader : IQuarantineDbReader
{
    private const string DbPath = @"C:\ProgramData\NullBot\quarantine\quarantine.db";

    private readonly ILogger<QuarantineDbReader> _logger;

    public QuarantineDbReader(ILogger<QuarantineDbReader> logger) => _logger = logger;

    public async Task<IReadOnlyList<QuarantinedItem>> GetAllItemsAsync(CancellationToken ct = default)
    {
        if (!File.Exists(DbPath)) return [];

        try
        {
            await using var conn = new SqliteConnection($"Data Source={DbPath};Mode=ReadOnly");
            await conn.OpenAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, threat_name, original_path, detection_type, quarantined_at, file_size
                FROM quarantine
                ORDER BY quarantined_at DESC
                """;

            var items = new List<QuarantinedItem>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var detType = ParseDetectionType(reader.GetString(3));
                var quarantinedAt = DateTime.TryParse(reader.GetString(4), out var dt)
                    ? dt : DateTime.UtcNow;

                items.Add(new QuarantinedItem(
                    Id: reader.GetString(0),
                    ThreatName: reader.GetString(1),
                    OriginalPath: reader.GetString(2),
                    DetectionType: detType,
                    QuarantinedAt: quarantinedAt,
                    SizeBytes: reader.IsDBNull(5) ? 0 : reader.GetInt64(5)));
            }
            return items;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read quarantine items");
            return [];
        }
    }

    public async Task<int> GetItemCountAsync(CancellationToken ct = default)
    {
        if (!File.Exists(DbPath)) return 0;

        try
        {
            await using var conn = new SqliteConnection($"Data Source={DbPath};Mode=ReadOnly");
            await conn.OpenAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM quarantine";
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is long count ? (int)count : 0;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read quarantine count");
            return 0;
        }
    }

    private static DetectionType ParseDetectionType(string raw) => raw.ToUpperInvariant() switch
    {
        "SIGNATURE" => DetectionType.Signature,
        "HEURISTIC" => DetectionType.Heuristic,
        "C2"        => DetectionType.C2,
        "DGA"       => DetectionType.DGA,
        "BEHAVIORAL"=> DetectionType.Behavioral,
        _           => DetectionType.Signature,
    };
}
