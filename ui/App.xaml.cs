using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NullBot.UI.Services;
using NullBot.UI.ViewModels;
using NullBot.UI.Views;

namespace NullBot.UI;

public partial class App : Application
{
    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _host = Host.CreateDefaultBuilder()
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddDebug();
                logging.SetMinimumLevel(LogLevel.Warning);
            })
            .ConfigureServices(RegisterServices)
            .Build();

        await _host.StartAsync();

        var mainWindow = _host.Services.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }
        base.OnExit(e);
    }

    private static void RegisterServices(IServiceCollection services)
    {
        // Infrastructure
        services.AddSingleton<ICliRunner, CliRunner>();
        services.AddSingleton<ISignaturesDbReader, SignaturesDbReader>();
        services.AddSingleton<IQuarantineDbReader, QuarantineDbReader>();
        services.AddSingleton<INotificationService, NotificationService>();

        // ViewModels — singleton; captured by MainWindowViewModel singleton
        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<ScanViewModel>();
        services.AddSingleton<RealtimeViewModel>();
        services.AddSingleton<QuarantineViewModel>();
        services.AddSingleton<NetworkViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<MainWindowViewModel>();

        // Window
        services.AddSingleton<MainWindow>();
    }
}
