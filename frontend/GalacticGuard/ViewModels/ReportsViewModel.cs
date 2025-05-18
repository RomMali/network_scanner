using System;
using System.Collections.ObjectModel;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;

public class ReportsViewModel
{
    private readonly HttpClient _httpClient = new HttpClient();
    public ObservableCollection<string> Logs { get; set; } = new ObservableCollection<string>();

    public async Task LoadLogs()
    {
        try
        {
            string apiUrl = "http://localhost:5000/logs"; // URL of Python Flask API
            var response = await _httpClient.GetStringAsync(apiUrl);
            var logs = JsonConvert.DeserializeObject<string[]>(response);
            Logs.Clear();
            foreach (var log in logs)
                Logs.Add(log);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error fetching logs: {ex.Message}");
        }
    }
}
