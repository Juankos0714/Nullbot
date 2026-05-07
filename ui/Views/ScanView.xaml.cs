using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace NullBot.UI.Views;

public partial class ScanView : UserControl
{
    public ScanView() => InitializeComponent();

    private void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title         = "Select folder to scan",
            Multiselect   = false,
        };

        if (dialog.ShowDialog() == true && DataContext is ViewModels.ScanViewModel vm)
            vm.CustomPath = dialog.FolderName;
    }
}
