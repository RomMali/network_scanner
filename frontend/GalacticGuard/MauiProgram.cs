using GalacticGuard.DB;
using Microsoft.Extensions.Logging;

namespace GalacticGuard
{
    public static class MauiProgram
    {
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

            // Add services to the container. - Debugging
#if DEBUG
            builder.Logging.AddDebug();
#endif
            // Initialize the database
            Init dbInit = new Init();
            dbInit.InitializeDatabase();

            return builder.Build();
        }
    }
}
