namespace NullBot.UI.Services;

/// <summary>Executes nullbot_cli.exe commands without blocking the UI thread.</summary>
public interface ICliRunner
{
    /// <summary>Runs the CLI and returns the complete stdout output.</summary>
    Task<string> RunOnceAsync(string[] args, CancellationToken ct = default);

    /// <summary>Runs the CLI and invokes <paramref name="onLine"/> for each stdout line as it arrives.</summary>
    Task RunStreamingAsync(string[] args, Action<string> onLine, CancellationToken ct = default);

    /// <summary>Spawns an elevated instance of nullbot_cli.exe via ShellExecute runas verb.</summary>
    Task RunElevatedAsync(string[] args);
}
