using System.Windows;

namespace NullBot.UI.Services;

public sealed class NotificationService : INotificationService
{
    // WPF has no built-in toast; we use a simple tray balloon via NotifyIcon.
    // Full Windows toast integration requires the Windows Community Toolkit
    // (Microsoft.Toolkit.Uwp.Notifications). This implementation uses a
    // lightweight fallback that works without extra packages.

    public void ShowThreatDetected(string threatName, string path)
    {
        // TODO: Wire up system tray NotifyIcon balloon once it is added to MainWindow.
        // For now, a MessageBox-free approach: the dashboard stream handles UI update.
        _ = (threatName, path);
    }

    public void ShowUpdateComplete(int newSignatures)
    {
        _ = newSignatures;
    }

    public void ShowError(string title, string message) =>
        Application.Current.Dispatcher.InvokeAsync(() =>
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Warning));
}
