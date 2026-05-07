using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NullBot.UI.Models;
using NullBot.UI.Services;

namespace NullBot.UI.ViewModels;

public partial class QuarantineViewModel : ObservableObject
{
    private readonly IQuarantineDbReader _db;
    private readonly ICliRunner          _cli;

    [ObservableProperty] private string          _searchText  = string.Empty;
    [ObservableProperty] private string          _filterType  = "All";
    [ObservableProperty] private QuarantinedItem? _selectedItem;
    [ObservableProperty] private bool            _isLoading;

    private ObservableCollection<QuarantinedItem> _allItems = [];

    public IEnumerable<QuarantinedItem> FilteredItems =>
        (string.IsNullOrWhiteSpace(SearchText) && FilterType == "All")
            ? _allItems
            : _allItems.Where(i =>
                (FilterType == "All" || i.DetectionType.ToString() == FilterType)
                && (string.IsNullOrWhiteSpace(SearchText)
                    || i.ThreatName.Contains(SearchText, StringComparison.OrdinalIgnoreCase)
                    || i.OriginalPath.Contains(SearchText, StringComparison.OrdinalIgnoreCase)));

    public IReadOnlyList<string> FilterTypes { get; } =
        ["All", "Signature", "Heuristic", "C2", "DGA", "Behavioral"];

    public QuarantineViewModel(IQuarantineDbReader db, ICliRunner cli)
    {
        _db  = db;
        _cli = cli;
    }

    partial void OnSearchTextChanged(string value) => OnPropertyChanged(nameof(FilteredItems));
    partial void OnFilterTypeChanged(string value) => OnPropertyChanged(nameof(FilteredItems));

    [RelayCommand]
    public async Task LoadItemsAsync(CancellationToken ct = default)
    {
        IsLoading = true;
        var items = await _db.GetAllItemsAsync(ct);
        _allItems = new ObservableCollection<QuarantinedItem>(items);
        OnPropertyChanged(nameof(FilteredItems));
        IsLoading = false;
    }

    [RelayCommand]
    private async Task RestoreItemAsync(QuarantinedItem? item)
    {
        if (item is null) return;
        await _cli.RunOnceAsync(["--quarantine", "restore", item.Id]);
        await LoadItemsAsync();
    }

    [RelayCommand]
    private async Task DeleteItemAsync(QuarantinedItem? item)
    {
        if (item is null) return;
        // CLI does not currently expose a delete command; the vault file removal
        // would go here once --quarantine delete <id> is added to the backend.
        await LoadItemsAsync();
    }

    [RelayCommand]
    private async Task DeleteOldItemsAsync()
    {
        var cutoff = DateTime.UtcNow.AddDays(-30);
        var old = _allItems.Where(i => i.QuarantinedAt < cutoff).ToList();
        foreach (var item in old)
            await DeleteItemAsync(item);
    }

    [RelayCommand]
    private async Task ExportReportAsync()
    {
        var csv = new System.Text.StringBuilder();
        csv.AppendLine("ID,ThreatName,OriginalPath,DetectionType,QuarantinedAt,SizeBytes");
        foreach (var item in _allItems)
        {
            csv.AppendLine(
                $"{item.Id},{Escape(item.ThreatName)},{Escape(item.OriginalPath)}," +
                $"{item.DetectionType},{item.QuarantinedAt:O},{item.SizeBytes}");
        }

        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"nullbot-quarantine-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
        await File.WriteAllTextAsync(path, csv.ToString());
    }

    private static string Escape(string s) =>
        s.Contains(',') || s.Contains('"') ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
}
