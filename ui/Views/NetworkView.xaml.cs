using System.Windows.Controls;
using NullBot.UI.ViewModels;

namespace NullBot.UI.Views;

public partial class NetworkView : UserControl
{
    public NetworkView()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            if (DataContext is NetworkViewModel vm)
                await vm.RefreshCommand.ExecuteAsync(null);
        };
    }
}
