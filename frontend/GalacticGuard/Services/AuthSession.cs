using GalacticGuard.Models;

namespace GalacticGuard.Services
{
    public class AuthSession
    {
        const string TokenKey = "gg_token";
        const string UserKey = "gg_user";
        const string AdvKey = "gg_advanced";
        const string BaseKey = "gg_baseurl";

        public string Token { get; private set; } = string.Empty;
        public string Username { get; private set; } = string.Empty;
        public bool AdvancedMode { get; private set; }
        public string BaseUrl { get; private set; } = "http://127.0.0.1:5000";

        public bool HasToken => !string.IsNullOrWhiteSpace(Token);

        public AuthSession()
        {
            Token = Preferences.Default.Get(TokenKey, string.Empty);
            Username = Preferences.Default.Get(UserKey, string.Empty);
            AdvancedMode = Preferences.Default.Get(AdvKey, false);
            BaseUrl = Preferences.Default.Get(BaseKey, "http://127.0.0.1:5000");
        }

        public void SetSession(LoginResponse login, string? baseUrl = null)
        {
            Token = login.Token;
            Username = login.Username;
            AdvancedMode = login.AdvancedMode;
            if (!string.IsNullOrWhiteSpace(baseUrl))
                BaseUrl = baseUrl.TrimEnd('/');
            Preferences.Default.Set(TokenKey, Token);
            Preferences.Default.Set(UserKey, Username);
            Preferences.Default.Set(AdvKey, AdvancedMode);
            Preferences.Default.Set(BaseKey, BaseUrl);
        }

        public void Clear()
        {
            Token = string.Empty;
            Username = string.Empty;
            AdvancedMode = false;
            Preferences.Default.Remove(TokenKey);
            Preferences.Default.Remove(UserKey);
            Preferences.Default.Remove(AdvKey);
        }
    }
}
