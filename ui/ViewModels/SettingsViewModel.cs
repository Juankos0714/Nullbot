using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using NullBot.UI.Services;

namespace NullBot.UI.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private const string RunKey   = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName  = "NullBot";

    private readonly ICliRunner _cli;

    [ObservableProperty] private int    _updateIntervalHours   = 6;
    [ObservableProperty] private bool   _autoQuarantineEnabled;
    [ObservableProperty] private bool   _runAtStartup;
    [ObservableProperty] private string _newExcludedPath       = string.Empty;

    public ObservableCollection<string> ExcludedPaths { get; } = [];

    public IReadOnlyList<int> UpdateIntervalOptions { get; } = [1, 3, 6, 12, 24];

    public string AppVersion { get; } = typeof(SettingsViewModel).Assembly
        .GetName().Version?.ToString(3) ?? "0.1.0";

    public SettingsViewModel(ICliRunner cli)
    {
        _cli = cli;
        LoadStartupSetting();
    }

    [RelayCommand]
    private void AddExcludedPath()
    {
        var p = NewExcludedPath.Trim();
        if (!string.IsNullOrEmpty(p) && !ExcludedPaths.Contains(p))
        {
            ExcludedPaths.Add(p);
            NewExcludedPath = string.Empty;
        }
    }

    [RelayCommand]
    private void RemoveExcludedPath(string? path)
    {
        if (path is not null) ExcludedPaths.Remove(path);
    }

    partial void OnRunAtStartupChanged(bool value)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
        if (key is null) return;
        if (value)
            key.SetValue(AppName, Environment.ProcessPath ?? string.Empty);
        else
            key.DeleteValue(AppName, throwOnMissingValue: false);
    }

    [RelayCommand]
    private async Task OpenGitHubAsync()
    {
        await _cli.RunOnceAsync(["--version"]); // touch CLI so it stays cached
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
            "https://github.com/Juankos0714/nullbot") { UseShellExecute = true });
    }

    private void LoadStartupSetting()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        _runAtStartup = key?.GetValue(AppName) is not null;
    }
}
