using GalacticGuard.ViewModels;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace GalacticGuard.ViewModels
{
    public class AnalyticsViewModel : BaseViewModel
    {
        private string databasePath = Path.Combine(FileSystem.AppDataDirectory, "analytics.json");

        private ObservableCollection<AttackSummary> _attackData;
        public ObservableCollection<AttackSummary> AttackData
        {
            get => _attackData;
            set => SetProperty(ref _attackData, value);
        }

        public AnalyticsViewModel()
        {
            LoadAnalyticsData();
        }

        private async void LoadAnalyticsData()
        {
            if (File.Exists(databasePath))
            {
                try
                {
                    string json = await File.ReadAllTextAsync(databasePath);
                    AttackData = new ObservableCollection<AttackSummary>(JsonSerializer.Deserialize<List<AttackSummary>>(json) ?? new List<AttackSummary>());
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading analytics data: {ex.Message}");
                }
            }
            else
            {
                AttackData = new ObservableCollection<AttackSummary>();
            }
        }
    }

    public class AttackSummary
    {
        public string AttackType { get; set; }
        public int Count { get; set; }
    }
}
