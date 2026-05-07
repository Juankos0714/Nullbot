using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace NullBot.UI.ViewModels;

public partial class MainWindowViewModel : ObservableObject
{
    [ObservableProperty]
    private ObservableObject _currentViewModel;

    public IReadOnlyList<SidebarItemViewModel> SidebarItems { get; }

    public DashboardViewModel  Dashboard  { get; }
    public ScanViewModel       Scan       { get; }
    public RealtimeViewModel   Realtime   { get; }
    public QuarantineViewModel Quarantine { get; }
    public NetworkViewModel    Network    { get; }
    public SettingsViewModel   Settings   { get; }

    public MainWindowViewModel(
        DashboardViewModel  dashboard,
        ScanViewModel       scan,
        RealtimeViewModel   realtime,
        QuarantineViewModel quarantine,
        NetworkViewModel    network,
        SettingsViewModel   settings)
    {
        Dashboard  = dashboard;
        Scan       = scan;
        Realtime   = realtime;
        Quarantine = quarantine;
        Network    = network;
        Settings   = settings;

        SidebarItems =
        [
            new("Dashboard",  "icon_shield",   Dashboard),
            new("Scan",       "icon_search",   Scan),
            new("Realtime",   "icon_activity", Realtime),
            new("Quarantine", "icon_lock",     Quarantine),
            new("Network",    "icon_network",  Network),
            new("Settings",   "icon_settings", Settings),
        ];

        SidebarItems[0].IsSelected = true;
        _currentViewModel = Dashboard;
    }

    [RelayCommand]
    private void NavigateTo(SidebarItemViewModel item)
    {
        foreach (var s in SidebarItems) s.IsSelected = false;
        item.IsSelected   = true;
        CurrentViewModel  = item.ViewModel;
    }
}
