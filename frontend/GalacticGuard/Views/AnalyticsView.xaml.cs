using GalacticGuard.ViewModels;

namespace GalacticGuard.Views
{
    public partial class AnalyticsView : ContentPage
    {
        public AnalyticsView()
        {
            InitializeComponent();
            BindingContext = MauiProgram.Services?.GetService<AnalyticsViewModel>() ?? new AnalyticsViewModel();
        }

        protected override void OnAppearing()
        {
            base.OnAppearing();
            (BindingContext as AnalyticsViewModel)?.StartPolling();
        }

        protected override void OnDisappearing()
        {
            (BindingContext as AnalyticsViewModel)?.StopPolling();
            base.OnDisappearing();
        }
    }
}
