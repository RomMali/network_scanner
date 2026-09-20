using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GalacticGuard.Services;
using Microsoft.Maui.Graphics;

namespace GalacticGuard.ViewModels
{
    public partial class LogsViewModel : ObservableObject
    {
        private readonly IpsApiClient _api;
        private IDispatcherTimer? _timer;

        [ObservableProperty] private string logContent = "Loading...";
        [ObservableProperty] private string filteredLogContent = string.Empty;
        [ObservableProperty] private string searchText = string.Empty;
        [ObservableProperty] private string serviceStatus = "Checking...";
        [ObservableProperty] private Color serviceColor = Colors.Gray;

        public LogsViewModel(IpsApiClient api)
        {
            _api = api;
        }

        public LogsViewModel() : this(
            MauiProgram.Services?.GetService<IpsApiClient>()
            ?? new IpsApiClient(new HttpClient { BaseAddress = new Uri("http://127.0.0.1:5000/") }, new AuthSession()))
        {
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

        partial void OnSearchTextChanged(string value) => ApplyFilter();

        void ApplyFilter()
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                FilteredLogContent = LogContent;
                return;
            }
            var lines = LogContent.Split('\n')
                .Where(line => line.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
            FilteredLogContent = string.Join("\n", lines);
        }

        [RelayCommand]
        async Task StartService()
        {
            try
            {
                await _api.StartAsync();
                await RefreshAsync();
            }
            catch
            {
                ServiceStatus = "Failed to start";
                ServiceColor = Colors.Red;
            }
        }

        [RelayCommand]
        async Task StopService()
        {
            try
            {
                await _api.StopAsync();
                await RefreshAsync();
            }
            catch
            {
                ServiceStatus = "Failed to stop";
                ServiceColor = Colors.Orange;
            }
        }

        async Task RefreshAsync()
        {
            try
            {
                var status = await _api.GetStatusAsync();
                var running = string.Equals(status.Status, "running", StringComparison.OrdinalIgnoreCase);
                ServiceStatus = running ? "Running" : "Stopped";
                ServiceColor = running ? Colors.Green : Colors.Red;
                LogContent = await _api.GetLogsTextAsync();
                ApplyFilter();
            }
            catch (Exception ex)
            {
                ServiceStatus = "Service Unreachable";
                ServiceColor = Colors.Orange;
                LogContent = ex.Message;
            }
        }
    }
}
