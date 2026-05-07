using CommunityToolkit.Mvvm.ComponentModel;

namespace NullBot.UI.ViewModels;

public partial class SidebarItemViewModel : ObservableObject
{
    [ObservableProperty]
    private bool _isSelected;

    public string           Name      { get; }
    public string           IconKey   { get; }
    public ObservableObject ViewModel { get; }

    public SidebarItemViewModel(string name, string iconKey, ObservableObject viewModel)
    {
        Name      = name;
        IconKey   = iconKey;
        ViewModel = viewModel;
    }
}
