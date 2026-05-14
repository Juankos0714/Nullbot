using System.IO;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace NullBot.UI.Services;

public sealed class SignaturesDbReader : ISignaturesDbReader
{
    private const string DbPath = @"C:\ProgramData\NullBot\signatures\signatures.db";

    private readonly ILogger<SignaturesDbReader> _logger;

    public SignaturesDbReader(ILogger<SignaturesDbReader> logger) => _logger = logger;

    public async Task<int> GetSignatureCountAsync(CancellationToken ct = default)
    {
        if (!File.Exists(DbPath)) return 0;

        try
        {
            await using var conn = new SqliteConnection($"Data Source={DbPath};Mode=ReadOnly");
            await conn.OpenAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM hashes";
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is long count ? (int)count : 0;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read signature count");
            return 0;
        }
    }

    public async Task<DateTime?> GetLastUpdateTimeAsync(CancellationToken ct = default)
    {
        if (!File.Exists(DbPath)) return null;

        try
        {
            await using var conn = new SqliteConnection($"Data Source={DbPath};Mode=ReadOnly");
            await conn.OpenAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT MAX(last_update) FROM feed_metadata";
            var result = await cmd.ExecuteScalarAsync(ct);
            if (result is string iso && DateTime.TryParse(iso, out var dt))
                return dt;
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read last update time");
            return null;
        }
    }
}
