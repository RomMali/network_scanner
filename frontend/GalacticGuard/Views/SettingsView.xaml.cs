using GalacticGuard.ViewModels;

namespace GalacticGuard.Views
{
    public partial class SettingsView : ContentPage
    {
        public SettingsView()
        {
            InitializeComponent();
            BindingContext = new SettingsViewModel();
        }
    }
}
