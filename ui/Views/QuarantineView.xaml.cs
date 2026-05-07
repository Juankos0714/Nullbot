using System.Windows.Controls;
using NullBot.UI.ViewModels;

namespace NullBot.UI.Views;

public partial class QuarantineView : UserControl
{
    public QuarantineView()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            if (DataContext is QuarantineViewModel vm)
                await vm.LoadItemsCommand.ExecuteAsync(null);
        };
    }
}
