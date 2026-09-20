using GalacticGuard.ViewModels;

namespace GalacticGuard.Views
{
    public partial class DashboardView : ContentPage
    {
        public DashboardView()
        {
            InitializeComponent();
            BindingContext = MauiProgram.Services?.GetService<DashboardViewModel>();
        }

        public DashboardView(DashboardViewModel vm)
        {
            InitializeComponent();
            BindingContext = vm;
        }

        protected override void OnAppearing()
        {
            base.OnAppearing();
            (BindingContext as DashboardViewModel)?.StartPolling();
        }

        protected override void OnDisappearing()
        {
            (BindingContext as DashboardViewModel)?.StopPolling();
            base.OnDisappearing();
        }
    }
}
