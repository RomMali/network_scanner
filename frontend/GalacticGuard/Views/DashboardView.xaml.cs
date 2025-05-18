using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using Microsoft.Maui.Controls;
using System.IO;
using System.Windows.Input;

namespace GalacticGuard.Views
{
    public partial class DashboardView : ContentPage
    {
        private readonly HttpClient _httpClient = new HttpClient();
        private bool isServiceRunning = false;
        private readonly string logFilePath = Path.Combine(FileSystem.AppDataDirectory, "service_log.txt");
        private bool isLoading = false;

        public string ButtonText { get; set; } = "Start Service";
        public Color ButtonColor { get; set; } = Colors.Gray;

        public ICommand ToggleServiceCommand { get; }

        public DashboardView()
        {
            InitializeComponent();
            BindingContext = new ViewModels.DashboardViewModel();
            LoadDashboardHtml();
        }

        private void LoadDashboardHtml()
        {
            string localPath = string.Empty;
            using var stream = FileSystem.OpenAppPackageFileAsync("dashboard.html").Result;

            if (stream != null)
            {
                localPath = Path.Combine(FileSystem.Current.AppDataDirectory, "dashboard.html");// (stream as FileStream).Name;
                using var reader = new StreamReader(stream);
                string htmlContent = reader.ReadToEnd();
                File.WriteAllText(localPath, htmlContent);
                DashboardWebView.Source = new UrlWebViewSource { Url = $"file://{localPath}" };
            }
        }

        async Task LoadMauiAsset()
        {
            using var stream = await FileSystem.OpenAppPackageFileAsync("dashboard.html");
            using var reader = new StreamReader(stream);

            var contents = reader.ReadToEnd();

        }

        //private async void OnServiceButtonClicked(object sender, EventArgs e)
        //{
        //    if (!isServiceRunning)
        //    {
        //        bool started = await StartService();
        //        if (started)
        //        {
        //            ServiceButton.Text = "Stop Service";
        //            ServiceButton.BackgroundColor = Colors.Green;
        //            isServiceRunning = true;
        //            LogServiceStatus("Service started");
        //        }
        //    }
        //    else
        //    {
        //        bool stopped = await StopService();
        //        if (stopped)
        //        {
        //            ServiceButton.Text = "Start Service";
        //            ServiceButton.BackgroundColor = Colors.LightGray;
        //            isServiceRunning = false;
        //            LogServiceStatus("Service stopped");
        //        }
        //    }
        //}

        //private async Task<bool> StartService()
        //{
        //    try
        //    {
        //        HttpClient client = new HttpClient();
        //        HttpResponseMessage response = await client.GetAsync("http://127.0.0.1:5000/start");
        //        if (response.IsSuccessStatusCode)
        //        {
        //            await DisplayAlert("Success", "Service started!", "OK");
        //            return true;
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        await DisplayAlert("Error", ex.Message, "OK");
        //    }
        //    return false;
        //}

        //private async Task<bool> StopService()
        //{
        //    try
        //    {
        //        HttpClient client = new HttpClient();
        //        HttpResponseMessage response = await client.GetAsync("http://127.0.0.1:5000/stop");
        //        if (response.IsSuccessStatusCode)
        //        {
        //            await DisplayAlert("Success", "Service stopped!", "OK");
        //            return true;
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        await DisplayAlert("Error", ex.Message, "OK");
        //    }
        //    return false;
        //}

        //private void LogServiceStatus(string status)
        //{
        //    try
        //    {
        //        string logEntry = $"{DateTime.Now}: {status}\n";
        //        File.AppendAllText(logFilePath, logEntry);

        //        // Keep only logs from the last 7 days
        //        if (File.Exists(logFilePath))
        //        {
        //            string[] logLines = File.ReadAllLines(logFilePath);
        //            DateTime sevenDaysAgo = DateTime.Now.AddDays(-7);

        //            var recentLogs = logLines.Where(line =>
        //            {
        //                string[] parts = line.Split(':');
        //                if (parts.Length > 1 && DateTime.TryParse(parts[0], out DateTime logDate))
        //                {
        //                    return logDate >= sevenDaysAgo;
        //                }
        //                return false;
        //            }).ToArray();

        //            File.WriteAllLines(logFilePath, recentLogs);
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine($"Failed to log service status: {ex.Message}");
        //    }
        //}


        //private void OnViewLogsClicked(object sender, EventArgs e)
        //{
        //    try
        //    {
        //        if (File.Exists(logFilePath))
        //        {
        //            string logs = File.ReadAllText(logFilePath);
        //            LogLabel.Text = logs;
        //        }
        //        else
        //        {
        //            LogLabel.Text = "No logs found.";
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        LogLabel.Text = $"Error reading logs: {ex.Message}";
        //    }
        //}

        //private async Task ToggleServiceAsync()
        //{
        //    if (isLoading) return; // Prevent multiple clicks

        //    isLoading = true;
        //    ButtonText = "Loading...";
        //    ButtonColor = Colors.Orange;
        //    OnPropertyChanged(nameof(ButtonText));
        //    OnPropertyChanged(nameof(ButtonColor));

        //    await Task.Delay(2000); // Simulating service start delay

        //    isServiceRunning = !isServiceRunning;
        //    ButtonText = isServiceRunning ? "Stop Service" : "Start Service";
        //    ButtonColor = isServiceRunning ? Colors.Green : Colors.Gray;

        //    LogServiceStatus(isServiceRunning ? "Service Started" : "Service Stopped");

        //    isLoading = false;
        //    OnPropertyChanged(nameof(ButtonText));
        //    OnPropertyChanged(nameof(ButtonColor));
        //}
    }
}