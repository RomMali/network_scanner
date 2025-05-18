using System.ComponentModel;
using System.Windows.Input;
using Microsoft.Maui.Graphics;
using System.Threading.Tasks;
using System.IO;
using System.Net.Http;

namespace GalacticGuard.ViewModels
{
    public class DashboardViewModel : INotifyPropertyChanged
    {
        private readonly HttpClient _httpClient = new HttpClient();
        private bool isServiceRunning = false;
        private bool isLoading = false;
        private string buttonText = "Start Service";
        private Color buttonColor = Colors.Gray;
        private bool isButtonEnabled = true;
        private string logContent = "No logs available.";

        private readonly string logFilePath = Path.Combine(FileSystem.AppDataDirectory, "service_log.txt");

        public string ButtonText
        {
            get => buttonText;
            set { buttonText = value; OnPropertyChanged(nameof(ButtonText)); }
        }

        public Color ButtonColor
        {
            get => buttonColor;
            set { buttonColor = value; OnPropertyChanged(nameof(ButtonColor)); }
        }

        public bool IsButtonEnabled
        {
            get => isButtonEnabled;
            set { isButtonEnabled = value; OnPropertyChanged(nameof(IsButtonEnabled)); }
        }

        public string LogContent
        {
            get => logContent;
            set { logContent = value; OnPropertyChanged(nameof(LogContent)); }
        }

        public ICommand ToggleServiceCommand { get; }
        public ICommand ViewLogsCommand { get; }

        public DashboardViewModel()
        {
            ToggleServiceCommand = new Command(async () => await ToggleServiceAsync());
            ViewLogsCommand = new Command(ViewLogs);
        }

        private string errorMessage;
        public string ErrorMessage
        {
            get => errorMessage;
            set
            {
                errorMessage = value;
                OnPropertyChanged(nameof(ErrorMessage));
            }
        }

        private async Task ToggleServiceAsync()
        {
            if (isLoading) return; // Prevent multiple clicks

            isLoading = true;
            IsButtonEnabled = false;
            ButtonText = "Loading...";
            ButtonColor = Colors.Orange;
            ErrorMessage = ""; // Clear previous errors

            await Task.Delay(500); // Small delay to show loading state

            bool success = false;

            try
            {
                using HttpClient client = new HttpClient();
                string url = isServiceRunning ? "http://127.0.0.1:5000/stop" : "http://127.0.0.1:5000/start";
                HttpResponseMessage response = await client.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    isServiceRunning = !isServiceRunning;
                    success = true;
                }
                else
                {
                    ErrorMessage = "❌ Failed to start/stop the service.";
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"❌ Error: {ex.Message}";
            }

            ButtonText = isServiceRunning ? "Stop Service" : "Start Service";
            ButtonColor = isServiceRunning ? Colors.Green : Colors.Gray;
            isLoading = false;
            IsButtonEnabled = true; // Re-enable button

            if (success)
            {
                ErrorMessage = isServiceRunning ? "✅ Service started successfully." : "✅ Service stopped successfully.";
            }
        }



        private async Task<bool> StartService()
        {
            try
            {
                HttpResponseMessage response = await _httpClient.GetAsync("http://127.0.0.1:5000/start");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> StopService()
        {
            try
            {
                HttpResponseMessage response = await _httpClient.GetAsync("http://127.0.0.1:5000/stop");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private void LogServiceStatus(string status)
        {
            string logEntry = $"{DateTime.Now}: {status}\n";
            File.AppendAllText(logFilePath, logEntry);
        }

        private void ViewLogs()
        {
            try
            {
                if (File.Exists(logFilePath))
                {
                    LogContent = File.ReadAllText(logFilePath); // Reload logs each time
                }
                else
                {
                    LogContent = "No logs found.";
                }
            }
            catch (Exception ex)
            {
                LogContent = $"Error reading logs: {ex.Message}";
            }
        }


        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
