using GalacticGuard.Services;
using GalacticGuard.Views;

namespace GalacticGuard
{
    public partial class App : Application
    {
        public App()
        {
            InitializeComponent();
        }

        protected override Window CreateWindow(IActivationState? activationState)
        {
            var services = MauiProgram.Services;
            Page root;
            if (services != null)
            {
                var session = services.GetRequiredService<AuthSession>();
                root = session.HasToken
                    ? new AppShell()
                    : services.GetRequiredService<LoginPage>();
            }
            else
            {
                var token = Preferences.Default.Get("gg_token", string.Empty);
                root = string.IsNullOrEmpty(token) ? new LoginPage() : new AppShell();
            }
            return new Window(root);
        }
    }
}
