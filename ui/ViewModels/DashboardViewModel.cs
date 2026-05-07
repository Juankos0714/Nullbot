using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NullBot.UI.Models;
using NullBot.UI.Services;

namespace NullBot.UI.ViewModels;

public partial class DashboardViewModel : ObservableObject
{
    private readonly ISignaturesDbReader _signatures;
    private readonly IQuarantineDbReader _quarantine;
    private readonly ICliRunner          _cli;

    [ObservableProperty] private int             _signatureCount;
    [ObservableProperty] private DateTime?       _lastUpdateTime;
    [ObservableProperty] private int             _quarantineCount;
    [ObservableProperty] private int             _c2AlertsLast24h;
    [ObservableProperty] private ProtectionLevel _shieldStatus = ProtectionLevel.Safe;
    [ObservableProperty] private bool            _isLoading;

    public ObservableCollection<ThreatDetection> RecentDetections { get; } = [];

    public DashboardViewModel(
        ISignaturesDbReader signatures,
        IQuarantineDbReader quarantine,
        ICliRunner          cli)
    {
        _signatures = signatures;
        _quarantine = quarantine;
        _cli        = cli;
    }

    [RelayCommand]
    public async Task LoadDataAsync(CancellationToken ct = default)
    {
        IsLoading = true;
        try
        {
            SignatureCount  = await _signatures.GetSignatureCountAsync(ct);
            LastUpdateTime  = await _signatures.GetLastUpdateTimeAsync(ct);
            QuarantineCount = await _quarantine.GetItemCountAsync(ct);

            await LoadRecentDetectionsAsync(ct);
            UpdateShieldStatus();
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private async Task ForceUpdateAsync(CancellationToken ct)
    {
        await _cli.RunStreamingAsync(["--update"], _ => { }, ct);
        await LoadDataAsync(ct);
    }

    private async Task LoadRecentDetectionsAsync(CancellationToken ct)
    {
        RecentDetections.Clear();
        var items = await _quarantine.GetAllItemsAsync(ct);

        foreach (var item in items.Take(10))
        {
            RecentDetections.Add(new ThreatDetection(
                item.Id,
                item.ThreatName,
                item.OriginalPath,
                ThreatSeverity.High,
                item.DetectionType,
                item.QuarantinedAt,
                null));
        }
    }

    private void UpdateShieldStatus()
    {
        ShieldStatus = (C2AlertsLast24h, QuarantineCount) switch
        {
            (> 0, _)  => ProtectionLevel.Danger,
            (0, > 5)  => ProtectionLevel.Warning,
            _         => ProtectionLevel.Safe,
        };
    }
}
