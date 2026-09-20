using GalacticGuard.ViewModels;

namespace GalacticGuard.Views
{
    public partial class ReportsView : ContentPage
    {
        public ReportsView()
        {
            InitializeComponent();
            BindingContext = MauiProgram.Services?.GetService<ReportsViewModel>() ?? new ReportsViewModel();
        }

        protected override async void OnAppearing()
        {
            base.OnAppearing();
            if (BindingContext is ReportsViewModel vm)
                await vm.RefreshAsync();
        }
    }
}
