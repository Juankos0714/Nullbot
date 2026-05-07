using System.Collections.ObjectModel;
using System.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NullBot.UI.Models;
using NullBot.UI.Services;

namespace NullBot.UI.ViewModels;

public partial class NetworkViewModel : ObservableObject
{
    private readonly ICliRunner           _cli;
    private readonly SynchronizationContext _uiCtx;

    [ObservableProperty] private NetworkConnection? _selectedConnection;
    [ObservableProperty] private int  _totalConnections;
    [ObservableProperty] private int  _suspiciousConnections;
    [ObservableProperty] private int  _beaconingDetected;
    [ObservableProperty] private bool _isRefreshing;

    public ObservableCollection<NetworkConnection> Connections { get; } = [];

    public NetworkViewModel(ICliRunner cli)
    {
        _cli   = cli;
        _uiCtx = SynchronizationContext.Current ?? new SynchronizationContext();
    }

    [RelayCommand]
    public async Task RefreshAsync(CancellationToken ct = default)
    {
        IsRefreshing = true;
        Connections.Clear();

        try
        {
            var output = await _cli.RunOnceAsync(["--status"], ct);
            ParseStatusOutput(output);
        }
        finally
        {
            IsRefreshing = false;
            TotalConnections    = Connections.Count;
            SuspiciousConnections = Connections.Count(c => c.Status != ConnectionStatus.Clean);
            BeaconingDetected   = Connections.Count(c => c.IsBeaconing);
        }
    }

    private void ParseStatusOutput(string output)
    {
        // Parses lines like:
        // CONN: <process>|<pid>|<dst_ip>|<dst_port>|<sni>|<status>|<reason>|<beaconing>
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!line.StartsWith("CONN:", StringComparison.Ordinal)) continue;
            var parts = line[5..].Split('|');
            if (parts.Length < 6) continue;

            var status = parts[5].Trim().ToUpperInvariant() switch
            {
                "SUSPICIOUS" => ConnectionStatus.Suspicious,
                "MALICIOUS"  => ConnectionStatus.Malicious,
                _            => ConnectionStatus.Clean,
            };

            Connections.Add(new NetworkConnection(
                parts[0].Trim(),
                int.TryParse(parts[1].Trim(), out var pid) ? pid : 0,
                parts[2].Trim(),
                int.TryParse(parts[3].Trim(), out var port) ? port : 0,
                parts.Length > 4 && !string.IsNullOrEmpty(parts[4].Trim()) ? parts[4].Trim() : null,
                status,
                parts.Length > 6 ? parts[6].Trim() : null,
                parts.Length > 7 && parts[7].Trim() == "1",
                null,
                DateTime.UtcNow));
        }
    }
}
