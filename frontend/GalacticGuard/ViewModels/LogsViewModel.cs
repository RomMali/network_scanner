using System;
using System.IO;
using System.Net.Http;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Maui.Graphics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

public partial class LogsViewModel : ObservableObject
{
    private readonly HttpClient _httpClient = new();
    private readonly string logFilePath;
    private Timer logRefreshTimer;
    private Timer statusRefreshTimer;

    // 🟢 Observable Properties (Notify UI)
    [ObservableProperty] private string logContent;
    [ObservableProperty] private string filteredLogContent;
    [ObservableProperty] private string searchText;
    [ObservableProperty] private string serviceStatus = "Checking...";
    [ObservableProperty] private Color serviceColor = Colors.Gray;

    // Commands
    public ICommand StartServiceCommand { get; }
    public ICommand StopServiceCommand { get; }

    public LogsViewModel()
    {
        string basePath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        string logDir = Path.Combine(basePath, "GalacticGuard");
        logFilePath = Path.Combine(logDir, "service.log");

        EnsureLogFileExists(logDir, logFilePath);

        StartServiceCommand = new AsyncRelayCommand(StartService);
        StopServiceCommand = new AsyncRelayCommand(StopService);

        // Start Timers
        logRefreshTimer = new Timer(RefreshLogs, null, 0, 3000); // Auto-refresh logs every 3 sec
        statusRefreshTimer = new Timer(CheckServiceStatus, null, 0, 5000); // Auto-refresh status every 5 sec
    }

    private void EnsureLogFileExists(string directory, string filePath)
    {
        try
        {
            if (!Directory.Exists(directory))
            {
                Directory.Delete(directory, true); // Delete if it somehow exists
            }

            //creating anyway
            //Directory.CreateDirectory(directory);

            if (!File.Exists(filePath))
            {
                File.WriteAllText(filePath, "Log initialized...\n");
            }
        }
        catch (Exception ex)
        {
            LogContent = $"Error ensuring log file exists: {ex.Message}";
        }
    }

    private void RefreshLogs(object state)
    {
        try
        {
            string logs = File.Exists(logFilePath) ? File.ReadAllText(logFilePath) : "Log file not found.";
            MainThread.BeginInvokeOnMainThread(() =>
            {
                LogContent = logs;
                ApplyFilter();
            });
        }
        catch (Exception ex)
        {
            MainThread.BeginInvokeOnMainThread(() => LogContent = $"Error reading logs: {ex.Message}");
        }
    }
    public void ApplyFilter()
    {
        if (string.IsNullOrWhiteSpace(SearchText))
        {
            FilteredLogContent = LogContent;
        }
        else
        {
            var filteredLines = LogContent.Split('\n')
                .Where(line => line.Contains(SearchText, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            FilteredLogContent = string.Join("\n", filteredLines);
        }
    }

    private async void CheckServiceStatus(object state)
    {
        try
        {
            HttpResponseMessage response = await _httpClient.GetAsync("http://127.0.0.1:5000/status");
            string status = response.IsSuccessStatusCode ? await response.Content.ReadAsStringAsync() : "unknown";

            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (status.Contains("running", StringComparison.OrdinalIgnoreCase))
                {
                    ServiceStatus = "Running";
                    ServiceColor = Colors.Green;
                }
                else
                {
                    ServiceStatus = "Stopped";
                    ServiceColor = Colors.Red;
                }
            });
        }
        catch
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                ServiceStatus = "Service Unreachable";
                ServiceColor = Colors.Orange;
            });
        }
    }

    private async Task StartService()
    {
        try
        {
            HttpResponseMessage response = await _httpClient.GetAsync("http://127.0.0.1:5000/start");
            if (response.IsSuccessStatusCode)
            {
                ServiceStatus = "Running";
                ServiceColor = Colors.Green;
            }
        }
        catch
        {
            ServiceStatus = "Failed to start";
            ServiceColor = Colors.Red;
        }
    }

    private async Task StopService()
    {
        try
        {
            HttpResponseMessage response = await _httpClient.GetAsync("http://127.0.0.1:5000/stop");
            if (response.IsSuccessStatusCode)
            {
                ServiceStatus = "Stopped";
                ServiceColor = Colors.Red;
            }
        }
        catch
        {
            ServiceStatus = "Failed to stop";
            ServiceColor = Colors.Orange;
        }
    }
}
