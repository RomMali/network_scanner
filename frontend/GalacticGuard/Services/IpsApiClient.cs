using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using GalacticGuard.Models;

namespace GalacticGuard.Services
{
    public class IpsApiClient
    {
        private readonly HttpClient _http;
        private readonly AuthSession _session;
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNameCaseInsensitive = true,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };

        public IpsApiClient(HttpClient http, AuthSession session)
        {
            _http = http;
            _session = session;
        }

        void ApplyAuth()
        {
            var baseUrl = string.IsNullOrWhiteSpace(_session.BaseUrl)
                ? "http://127.0.0.1:5000"
                : _session.BaseUrl;
            _http.BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/");
            _http.DefaultRequestHeaders.Authorization = string.IsNullOrWhiteSpace(_session.Token)
                ? null
                : new AuthenticationHeaderValue("Bearer", _session.Token);
        }

        async Task<T?> Read<T>(HttpResponseMessage response)
        {
            var body = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"{(int)response.StatusCode}: {body}");
            if (string.IsNullOrWhiteSpace(body))
                return default;
            return JsonSerializer.Deserialize<T>(body, JsonOpts);
        }

        StringContent JsonBody(object payload) =>
            new(JsonSerializer.Serialize(payload, JsonOpts), Encoding.UTF8, "application/json");

        public async Task<LoginResponse> LoginAsync(string username, string password)
        {
            ApplyAuth();
            var resp = await _http.PostAsync("auth/login", JsonBody(new { username, password }));
            var login = await Read<LoginResponse>(resp) ?? throw new InvalidOperationException("Empty login");
            _session.SetSession(login);
            ApplyAuth();
            return login;
        }

        public async Task RegisterAsync(string username, string password, bool advanced)
        {
            ApplyAuth();
            var resp = await _http.PostAsync("auth/register",
                JsonBody(new { username, password, advanced_mode = advanced }));
            await Read<Dictionary<string, object>>(resp);
        }

        public async Task<StatusResponse> GetStatusAsync()
        {
            ApplyAuth();
            var resp = await _http.GetAsync("status");
            return await Read<StatusResponse>(resp) ?? new StatusResponse();
        }

        public async Task StartAsync()
        {
            ApplyAuth();
            var resp = await _http.GetAsync("start");
            resp.EnsureSuccessStatusCode();
        }

        public async Task StopAsync()
        {
            ApplyAuth();
            var resp = await _http.GetAsync("stop");
            resp.EnsureSuccessStatusCode();
        }

        public async Task<string> GetLogsTextAsync()
        {
            ApplyAuth();
            var resp = await _http.GetAsync("api/logs");
            var parsed = await Read<LogsResponse>(resp);
            return parsed?.Logs ?? string.Empty;
        }

        public async Task<List<IpsEvent>> GetEventsAsync()
        {
            ApplyAuth();
            var resp = await _http.GetAsync("api/logs?format=json&limit=200");
            return await Read<List<IpsEvent>>(resp) ?? new List<IpsEvent>();
        }

        public async Task<List<AlertItem>> GetAlertsAsync()
        {
            ApplyAuth();
            var resp = await _http.GetAsync("api/alerts");
            return await Read<List<AlertItem>>(resp) ?? new List<AlertItem>();
        }

        public async Task<List<IpsRule>> GetRulesAsync()
        {
            ApplyAuth();
            var resp = await _http.GetAsync("api/rules");
            return await Read<List<IpsRule>>(resp) ?? new List<IpsRule>();
        }

        public async Task<IpsRule> SaveRuleAsync(IpsRule rule)
        {
            ApplyAuth();
            HttpResponseMessage resp;
            if (rule.Id > 0)
                resp = await _http.PutAsync($"api/rules/{rule.Id}", JsonBody(rule));
            else
                resp = await _http.PostAsync("api/rules", JsonBody(rule));
            return await Read<IpsRule>(resp) ?? rule;
        }

        public async Task DeleteRuleAsync(int id)
        {
            ApplyAuth();
            var resp = await _http.DeleteAsync($"api/rules/{id}");
            resp.EnsureSuccessStatusCode();
        }

        public async Task<List<BlacklistItem>> GetBlacklistAsync()
        {
            ApplyAuth();
            var resp = await _http.GetAsync("api/blacklist");
            return await Read<List<BlacklistItem>>(resp) ?? new List<BlacklistItem>();
        }
    }
}
