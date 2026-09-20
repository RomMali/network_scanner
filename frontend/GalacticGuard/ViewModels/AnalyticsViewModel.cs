using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using GalacticGuard.Models;
using GalacticGuard.Services;

namespace GalacticGuard.ViewModels
{
    public partial class AnalyticsViewModel : ObservableObject
    {
        private readonly IpsApiClient _api;
        private IDispatcherTimer? _timer;

        public ObservableCollection<AlertItem> Alerts { get; } = new();

        [ObservableProperty] private string summary = "No alerts";

        public AnalyticsViewModel(IpsApiClient api)
        {
            _api = api;
        }

        public AnalyticsViewModel() : this(
            MauiProgram.Services?.GetService<IpsApiClient>()
            ?? new IpsApiClient(new HttpClient { BaseAddress = new Uri("http://127.0.0.1:5000/") }, new AuthSession()))
        {
        }

        public void StartPolling()
        {
            _timer ??= Application.Current?.Dispatcher.CreateTimer();
            if (_timer == null) return;
            _timer.Interval = TimeSpan.FromSeconds(5);
            _timer.Tick -= OnTick;
            _timer.Tick += OnTick;
            _timer.Start();
            _ = RefreshAsync();
        }

        public void StopPolling() => _timer?.Stop();

        void OnTick(object? sender, EventArgs e) => _ = RefreshAsync();

        async Task RefreshAsync()
        {
            try
            {
                var items = await _api.GetAlertsAsync();
                Alerts.Clear();
                foreach (var a in items)
                    Alerts.Add(a);
                Summary = items.Count == 0 ? "No ML alerts" : $"{items.Count} anomaly alerts (informational, not auto-DROP)";
            }
            catch (Exception ex)
            {
                Summary = ex.Message;
            }
        }
    }
}
