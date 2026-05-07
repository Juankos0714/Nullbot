namespace NullBot.UI.Services;

/// <summary>Windows toast notifications for background events.</summary>
public interface INotificationService
{
    void ShowThreatDetected(string threatName, string path);
    void ShowUpdateComplete(int newSignatures);
    void ShowError(string title, string message);
}
