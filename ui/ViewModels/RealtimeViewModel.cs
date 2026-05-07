using System.Collections.ObjectModel;
using System.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NullBot.UI.Services;

namespace NullBot.UI.ViewModels;

public partial class RealtimeViewModel : ObservableObject
{
    private const int MaxLiveEvents = 100;

    private readonly ICliRunner           _cli;
    private readonly SynchronizationContext _uiCtx;
    private CancellationTokenSource?      _watchCts;

    [ObservableProperty] private bool _isWatching;
    [ObservableProperty] private bool _amsiProviderRegistered;
    [ObservableProperty] private int  _connectionsInspected;
    [ObservableProperty] private int  _scriptsScanned;
    [ObservableProperty] private string _filesystemWatcherPaths = "%TEMP%, %APPDATA%, Startup";

    public ObservableCollection<string> LiveEvents { get; } = [];

    public RealtimeViewModel(ICliRunner cli)
    {
        _cli    = cli;
        _uiCtx  = SynchronizationContext.Current ?? new SynchronizationContext();
    }

    [RelayCommand]
    private async Task StartWatchingAsync()
    {
        _watchCts = new CancellationTokenSource();
        IsWatching = true;

        try
        {
            await _cli.RunStreamingAsync(["--watch"], OnWatchLine, _watchCts.Token);
        }
        catch (OperationCanceledException)
        {
            // expected on stop
        }
        finally
        {
            IsWatching = false;
        }
    }

    [RelayCommand]
    private void StopWatching()
    {
        _watchCts?.Cancel();
        _watchCts = null;
    }

    [RelayCommand]
    private async Task RegisterAmsiAsync()
    {
        await _cli.RunElevatedAsync(["--amsi", "--register"]);
        AmsiProviderRegistered = true;
    }

    [RelayCommand]
    private async Task UnregisterAmsiAsync()
    {
        await _cli.RunElevatedAsync(["--amsi", "--unregister"]);
        AmsiProviderRegistered = false;
    }

    private void OnWatchLine(string line)
    {
        _uiCtx.Post(_ =>
        {
            if (LiveEvents.Count >= MaxLiveEvents)
                LiveEvents.RemoveAt(0);

            LiveEvents.Add($"[{DateTime.Now:HH:mm:ss}] {line}");

            if (line.Contains("CONNECTION", StringComparison.OrdinalIgnoreCase))
                ConnectionsInspected++;
            else if (line.Contains("AMSI", StringComparison.OrdinalIgnoreCase))
                ScriptsScanned++;
        }, null);
    }
}
