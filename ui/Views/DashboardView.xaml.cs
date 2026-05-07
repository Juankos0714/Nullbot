using System.Windows.Controls;
using NullBot.UI.ViewModels;

namespace NullBot.UI.Views;

public partial class DashboardView : UserControl
{
    public DashboardView()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            if (DataContext is DashboardViewModel vm)
                await vm.LoadDataCommand.ExecuteAsync(null);
        };
    }
}
