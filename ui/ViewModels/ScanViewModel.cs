using System.Collections.ObjectModel;
using System.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NullBot.UI.Models;
using NullBot.UI.Services;

namespace NullBot.UI.ViewModels;

public enum ScanMode { Quick, Full, Custom }

public partial class ScanViewModel : ObservableObject
{
    private readonly ICliRunner           _cli;
    private readonly SynchronizationContext _uiCtx;
    private DateTime _scanStart;

    [ObservableProperty] private ScanMode _scanMode  = ScanMode.Quick;
    [ObservableProperty] private string   _customPath = string.Empty;
    [ObservableProperty] private bool     _autoQuarantine;
    [ObservableProperty] private bool     _isScanning;
    [ObservableProperty] private int      _filesProcessed;
    [ObservableProperty] private int      _filesTotal;
    [ObservableProperty] private double   _scanSpeed;
    [ObservableProperty] private string   _currentFile = string.Empty;
    [ObservableProperty] private ScanResult? _completedResult;

    public ObservableCollection<ThreatDetection> DetectedThreats { get; } = [];

    public int ProgressPercent =>
        FilesTotal > 0 ? (int)((double)FilesProcessed / FilesTotal * 100) : 0;

    public ScanViewModel(ICliRunner cli)
    {
        _cli    = cli;
        _uiCtx  = SynchronizationContext.Current ?? new SynchronizationContext();
    }

    partial void OnFilesProcessedChanged(int value) => OnPropertyChanged(nameof(ProgressPercent));
    partial void OnFilesTotalChanged(int value)     => OnPropertyChanged(nameof(ProgressPercent));

    [RelayCommand(IncludeCancelCommand = true)]
    private async Task StartScanAsync(CancellationToken ct)
    {
        IsScanning = true;
        DetectedThreats.Clear();
        FilesProcessed  = 0;
        FilesTotal      = 0;
        CompletedResult = null;
        _scanStart      = DateTime.UtcNow;

        try
        {
            await _cli.RunStreamingAsync(BuildArgs(), ParseLine, ct);
        }
        finally
        {
            IsScanning = false;
            CompletedResult = new ScanResult(
                _scanStart,
                DateTime.UtcNow,
                FilesProcessed,
                DetectedThreats.ToList());
        }
    }

    private void ParseLine(string line)
    {
        if (line.StartsWith("PROGRESS:", StringComparison.Ordinal))
        {
            var parts = line[9..].Split('/');
            if (parts.Length == 2
                && int.TryParse(parts[0].Trim(), out var done)
                && int.TryParse(parts[1].Trim(), out var total))
            {
                var elapsed = (DateTime.UtcNow - _scanStart).TotalSeconds;
                _uiCtx.Post(_ =>
                {
                    FilesProcessed = done;
                    FilesTotal     = total;
                    ScanSpeed      = elapsed > 0 ? done / elapsed : 0;
                }, null);
            }
        }
        else if (line.StartsWith("FILE:", StringComparison.Ordinal))
        {
            _uiCtx.Post(_ => CurrentFile = line[5..].Trim(), null);
        }
        else if (line.StartsWith("THREAT:", StringComparison.Ordinal))
        {
            var threat = ParseThreat(line[7..]);
            if (threat is not null)
                _uiCtx.Post(_ => DetectedThreats.Add(threat), null);
        }
    }

    private static ThreatDetection? ParseThreat(string data)
    {
        // Format: SEVERITY|NAME|PATH|TYPE|HASH
        var parts = data.Trim().Split('|');
        if (parts.Length < 3) return null;

        var severity = parts[0].Trim().ToUpperInvariant() switch
        {
            "LOW"      => ThreatSeverity.Low,
            "MEDIUM"   => ThreatSeverity.Medium,
            "HIGH"     => ThreatSeverity.High,
            "CRITICAL" => ThreatSeverity.Critical,
            _          => ThreatSeverity.Medium,
        };

        var detType = parts.Length > 3 ? parts[3].Trim().ToUpperInvariant() switch
        {
            "HEURISTIC" => DetectionType.Heuristic,
            "C2"        => DetectionType.C2,
            "DGA"       => DetectionType.DGA,
            _           => DetectionType.Signature,
        } : DetectionType.Signature;

        return new ThreatDetection(
            Guid.NewGuid().ToString("N")[..8],
            parts.Length > 1 ? parts[1].Trim() : "Unknown",
            parts.Length > 2 ? parts[2].Trim() : string.Empty,
            severity,
            detType,
            DateTime.UtcNow,
            parts.Length > 4 ? parts[4].Trim() : null);
    }

    private string[] BuildArgs() => ScanMode switch
    {
        ScanMode.Quick  => AutoQuarantine
            ? ["--scan", "--quick", "--auto-quarantine"]
            : ["--scan", "--quick"],
        ScanMode.Full   => ["--scan", "--path", "C:\\"],
        ScanMode.Custom => AutoQuarantine && !string.IsNullOrWhiteSpace(CustomPath)
            ? ["--scan", "--path", CustomPath, "--auto-quarantine"]
            : ["--scan", "--path", CustomPath],
        _               => ["--scan", "--quick"],
    };
}
