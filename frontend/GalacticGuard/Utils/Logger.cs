using System;
using System.IO;
using System.Text;

namespace GalacticGuard.Utils
{
    public static class Logger
    {
        private static readonly object _lock = new();
        private static readonly string logDirectory = Path.Combine(AppContext.BaseDirectory, "logs");
        private static readonly string logFile = Path.Combine(logDirectory, "app.log");

        static Logger()
        {
            if (!Directory.Exists(logDirectory))
                Directory.CreateDirectory(logDirectory);
        }

        public static void Info(string message, string source = "GENERAL") => Log("INFO", message, source);
        public static void Warn(string message, string source = "GENERAL") => Log("WARN", message, source);
        public static void Error(string message, string source = "GENERAL") => Log("ERROR", message, source);

        private static void Log(string level, string message, string source)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string logLine = $"[{timestamp}] [{level}] [{source}] {message}";

            lock (_lock)
            {
                File.AppendAllText(logFile, logLine + Environment.NewLine, Encoding.UTF8);
            }

            Console.WriteLine(logLine); // Output to console during development
        }
    }
}
