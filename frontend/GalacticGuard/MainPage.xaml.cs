using GalacticGuard.Services;

namespace GalacticGuard
{
    public partial class MainPage : Shell
    {
        public MainPage()
        {
            InitializeComponent();
            var advanced = MauiProgram.Services?.GetService<AuthSession>()?.AdvancedMode
                           ?? Preferences.Default.Get("gg_advanced", false);
            if (!advanced && RulesTab != null)
            {
                Items.OfType<TabBar>().FirstOrDefault()?.Items.Remove(RulesTab);
            }
        }
    }
}
