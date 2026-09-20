using GalacticGuard.ViewModels;

namespace GalacticGuard.Views
{
    public partial class RulesView : ContentPage
    {
        public RulesView()
        {
            InitializeComponent();
            BindingContext = MauiProgram.Services?.GetService<RulesViewModel>();
        }

        protected override async void OnAppearing()
        {
            base.OnAppearing();
            if (BindingContext is RulesViewModel vm)
                await vm.LoadAsync();
        }
    }
}
