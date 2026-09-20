using GalacticGuard.Services;
using GalacticGuard.ViewModels;
using GalacticGuard.Views;
using Microsoft.Extensions.Logging;

namespace GalacticGuard
{
    public static class MauiProgram
    {
        public static IServiceProvider? Services { get; private set; }

        public static MauiApp CreateMauiApp()
        {
            var builder = MauiApp.CreateBuilder();
            builder
                .UseMauiApp<App>()
                .ConfigureFonts(fonts =>
                {
                    fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                    fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
                });

#if DEBUG
            builder.Logging.AddDebug();
#endif
            builder.Services.AddSingleton<AuthSession>();
            builder.Services.AddSingleton(_ => new HttpClient
            {
                BaseAddress = new Uri("http://127.0.0.1:5000/"),
                Timeout = TimeSpan.FromSeconds(10)
            });
            builder.Services.AddSingleton<IpsApiClient>();
            builder.Services.AddSingleton<LoginViewModel>();
            builder.Services.AddSingleton<DashboardViewModel>();
            builder.Services.AddSingleton<LogsViewModel>();
            builder.Services.AddSingleton<AnalyticsViewModel>();
            builder.Services.AddSingleton<ReportsViewModel>();
            builder.Services.AddSingleton<RulesViewModel>();
            builder.Services.AddTransient<LoginPage>();
            builder.Services.AddTransient<DashboardView>();
            builder.Services.AddTransient<LogsView>();
            builder.Services.AddTransient<AnalyticsView>();
            builder.Services.AddTransient<ReportsView>();
            builder.Services.AddTransient<RulesView>();

            var app = builder.Build();
            Services = app.Services;
            return app;
        }
    }
}
