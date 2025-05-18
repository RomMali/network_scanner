using Microsoft.Maui.Controls.Xaml;
using GalacticGuard.ViewModels;

namespace GalacticGuard.Views
{
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class LogsView : ContentPage
    {
        public LogsView()
        {
            InitializeComponent();
            BindingContext = new LogsViewModel();
        }
    }
}
