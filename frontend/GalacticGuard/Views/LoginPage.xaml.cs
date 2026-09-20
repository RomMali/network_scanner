namespace GalacticGuard.Views
{
    public partial class LoginPage : ContentPage
    {
        public LoginPage()
        {
            InitializeComponent();
            BindingContext = MauiProgram.Services?.GetService<ViewModels.LoginViewModel>();
        }

        public LoginPage(ViewModels.LoginViewModel vm) : this()
        {
            BindingContext = vm;
        }
    }
}
