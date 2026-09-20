using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GalacticGuard.Models;
using GalacticGuard.Services;

namespace GalacticGuard.ViewModels
{
    public partial class DashboardViewModel : ObservableObject
    {
        private readonly IpsApiClient _api;
        private readonly AuthSession _session;
        private IDispatcherTimer? _timer;

        [ObservableProperty] private string serviceStatus = "Checking...";
        [ObservableProperty] private Color serviceColor = Colors.Gray;
        [ObservableProperty] private string failOpen = "fail-open";
        [ObservableProperty] private int dropCount;
        [ObservableProperty] private int acceptCount;
        [ObservableProperty] private int alertCount;
        [ObservableProperty] private string lastDrop = "None";
        [ObservableProperty] private string userLabel = string.Empty;
        [ObservableProperty] private string modeLabel = "Standard";
        [ObservableProperty] private string errorMessage = string.Empty;

        public DashboardViewModel(IpsApiClient api, AuthSession session)
        {
            _api = api;
            _session = session;
            UserLabel = session.Username;
            ModeLabel = session.AdvancedMode ? "Advanced" : "Standard";
        }

        public void StartPolling()
        {
            _timer ??= Application.Current?.Dispatcher.CreateTimer();
            if (_timer == null) return;
            _timer.Interval = TimeSpan.FromSeconds(3);
            _timer.Tick -= OnTick;
            _timer.Tick += OnTick;
            _timer.Start();
            _ = RefreshAsync();
        }

        public void StopPolling() => _timer?.Stop();

        void OnTick(object? sender, EventArgs e) => _ = RefreshAsync();

        [RelayCommand]
        async Task ToggleIps()
        {
            try
            {
                var status = await _api.GetStatusAsync();
                if (string.Equals(status.Status, "running", StringComparison.OrdinalIgnoreCase))
                    await _api.StopAsync();
                else
                    await _api.StartAsync();
                await RefreshAsync();
            }
            catch (Exception ex)
            {
                ErrorMessage = ex.Message;
            }
        }

        [RelayCommand]
        void Logout()
        {
            _session.Clear();
            var window = Application.Current?.Windows.FirstOrDefault();
            if (window != null)
                window.Page = new Views.LoginPage();
            else if (Application.Current != null)
                Application.Current.MainPage = new Views.LoginPage();
        }

        async Task RefreshAsync()
        {
            try
            {
                var status = await _api.GetStatusAsync();
                var running = string.Equals(status.Status, "running", StringComparison.OrdinalIgnoreCase);
                ServiceStatus = running ? "Running" : "Stopped";
                ServiceColor = running ? Colors.Green : Colors.Red;
                FailOpen = status.FailOpen ? "fail-open (queue rules removed on stop)" : "fail-closed";
                var events = await _api.GetEventsAsync();
                DropCount = events.Count(e => string.Equals(e.Action, "DROP", StringComparison.OrdinalIgnoreCase));
                AcceptCount = events.Count(e => string.Equals(e.Action, "ACCEPT", StringComparison.OrdinalIgnoreCase));
                AlertCount = events.Count(e => string.Equals(e.Action, "ALERT", StringComparison.OrdinalIgnoreCase));
                var last = events.LastOrDefault(e => string.Equals(e.Action, "DROP", StringComparison.OrdinalIgnoreCase));
                LastDrop = last == null ? "None" : $"{last.Src} → {last.Dst} ({last.Reason})";
                ErrorMessage = string.Empty;
            }
            catch (Exception ex)
            {
                ServiceStatus = "Unreachable";
                ServiceColor = Colors.Orange;
                ErrorMessage = ex.Message;
            }
        }
    }
}
