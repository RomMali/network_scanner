using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GalacticGuard.Services;

namespace GalacticGuard.ViewModels
{
    public partial class LoginViewModel : ObservableObject
    {
        private readonly IpsApiClient _api;
        private readonly AuthSession _session;

        [ObservableProperty] private string username = string.Empty;
        [ObservableProperty] private string password = string.Empty;
        [ObservableProperty] private string baseUrl = "http://127.0.0.1:5000";
        [ObservableProperty] private bool registerAdvanced;
        [ObservableProperty] private string errorMessage = string.Empty;
        [ObservableProperty] private bool busy;

        public LoginViewModel(IpsApiClient api, AuthSession session)
        {
            _api = api;
            _session = session;
            BaseUrl = session.BaseUrl;
        }

        [RelayCommand]
        async Task Login()
        {
            await Run(async () =>
            {
                Preferences.Default.Set("gg_baseurl", BaseUrl.TrimEnd('/'));
                var login = await _api.LoginAsync(Username, Password);
                _session.SetSession(login, BaseUrl);
                var window = Application.Current.Windows.FirstOrDefault();
                if (window != null)
                    window.Page = new AppShell();
                else
                    Application.Current.MainPage = new AppShell();
            });
        }

        [RelayCommand]
        async Task Register()
        {
            await Run(async () =>
            {
                Preferences.Default.Set("gg_baseurl", BaseUrl.TrimEnd('/'));
                await _api.RegisterAsync(Username, Password, RegisterAdvanced);
                await Login();
            });
        }

        async Task Run(Func<Task> action)
        {
            if (Busy) return;
            Busy = true;
            ErrorMessage = string.Empty;
            try
            {
                await action();
            }
            catch (Exception ex)
            {
                ErrorMessage = ex.Message;
            }
            finally
            {
                Busy = false;
            }
        }
    }
}
