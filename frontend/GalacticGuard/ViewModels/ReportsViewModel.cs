using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using GalacticGuard.Models;
using GalacticGuard.Services;

namespace GalacticGuard.ViewModels
{
    public partial class ReportsViewModel : ObservableObject
    {
        private readonly IpsApiClient _api;

        public ObservableCollection<IpsEvent> Drops { get; } = new();

        [ObservableProperty] private string summary = "No drops";

        public ReportsViewModel(IpsApiClient api)
        {
            _api = api;
        }

        public ReportsViewModel() : this(
            MauiProgram.Services?.GetService<IpsApiClient>()
            ?? new IpsApiClient(new HttpClient { BaseAddress = new Uri("http://127.0.0.1:5000/") }, new AuthSession()))
        {
        }

        public async Task RefreshAsync()
        {
            try
            {
                var events = await _api.GetEventsAsync();
                var drops = events.Where(e => string.Equals(e.Action, "DROP", StringComparison.OrdinalIgnoreCase)).ToList();
                Drops.Clear();
                foreach (var d in drops)
                    Drops.Add(d);
                Summary = $"{drops.Count} DROP events";
            }
            catch (Exception ex)
            {
                Summary = ex.Message;
            }
        }
    }
}
