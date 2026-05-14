using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Extensions.Logging;

namespace NullBot.UI.Services;

public sealed class CliRunner : ICliRunner
{
    private static readonly string[] _candidatePaths =
    [
        Path.Combine(AppContext.BaseDirectory, "nullbot_cli.exe"),
        Path.Combine(AppContext.BaseDirectory, "..", "bin", "nullbot_cli.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                     "NullBot", "nullbot_cli.exe"),
    ];

    private readonly string _cliPath;
    private readonly ILogger<CliRunner> _logger;

    public CliRunner(ILogger<CliRunner> logger)
    {
        _logger = logger;
        _cliPath = _candidatePaths.FirstOrDefault(File.Exists) ?? _candidatePaths[0];
        _logger.LogDebug("CLI path resolved to: {Path}", _cliPath);
    }

    public async Task<string> RunOnceAsync(string[] args, CancellationToken ct = default)
    {
        var output = new StringBuilder();
        using var process = CreateProcess(args);

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null) output.AppendLine(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null) _logger.LogWarning("CLI stderr: {Line}", e.Data);
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await process.WaitForExitAsync(ct);
        return output.ToString();
    }

    public async Task RunStreamingAsync(string[] args, Action<string> onLine, CancellationToken ct = default)
    {
        using var process = CreateProcess(args);

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null) onLine(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null) _logger.LogWarning("CLI stderr: {Line}", e.Data);
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        try
        {
            await process.WaitForExitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already exited */ }
        }
    }

    public Task RunElevatedAsync(string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _cliPath,
            Arguments = string.Join(' ', args.Select(a => a.Contains(' ') ? $"\"{a}\"" : a)),
            UseShellExecute = true,
            Verb = "runas",
        };
        Process.Start(psi);
        return Task.CompletedTask;
    }

    private Process CreateProcess(string[] args) => new()
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = _cliPath,
            Arguments = string.Join(' ', args.Select(a => a.Contains(' ') ? $"\"{a}\"" : a)),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        },
        EnableRaisingEvents = true,
    };
}
