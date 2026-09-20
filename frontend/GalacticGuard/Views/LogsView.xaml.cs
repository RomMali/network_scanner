using GalacticGuard.ViewModels;

namespace GalacticGuard.Views
{
    public partial class LogsView : ContentPage
    {
        public LogsView()
        {
            InitializeComponent();
            BindingContext = MauiProgram.Services?.GetService<LogsViewModel>() ?? new LogsViewModel();
        }

        protected override void OnAppearing()
        {
            base.OnAppearing();
            (BindingContext as LogsViewModel)?.StartPolling();
        }

        protected override void OnDisappearing()
        {
            (BindingContext as LogsViewModel)?.StopPolling();
            base.OnDisappearing();
        }
    }
}
