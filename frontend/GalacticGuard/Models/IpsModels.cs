namespace GalacticGuard.Models
{
    public class LoginResponse
    {
        public string Token { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public bool AdvancedMode { get; set; }
        public int Id { get; set; }
    }

    public class StatusResponse
    {
        public string Status { get; set; } = "stopped";
        public bool Mock { get; set; }
        public int QueueNum { get; set; }
        public bool FailOpen { get; set; }
    }

    public class LogsResponse
    {
        public string Logs { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
    }

    public class IpsEvent
    {
        public string Ts { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string Src { get; set; } = string.Empty;
        public string Dst { get; set; } = string.Empty;
        public string Proto { get; set; } = string.Empty;
        public int? Sport { get; set; }
        public int? Dport { get; set; }
        public int? RuleId { get; set; }
        public string Reason { get; set; } = string.Empty;
    }

    public class IpsRule
    {
        public int Id { get; set; }
        public int Priority { get; set; } = 100;
        public string Action { get; set; } = "deny";
        public string Src { get; set; } = "any";
        public string Dst { get; set; } = "any";
        public string Proto { get; set; } = "any";
        public string? Sport { get; set; }
        public string? Dport { get; set; }
        public bool Enabled { get; set; } = true;
        public bool Proposed { get; set; }
    }

    public class AlertItem
    {
        public string Ts { get; set; } = string.Empty;
        public string Src { get; set; } = string.Empty;
        public string Dst { get; set; } = string.Empty;
        public bool Anomaly { get; set; }
        public string Reason { get; set; } = string.Empty;
        public double Zscore { get; set; }
    }

    public class BlacklistItem
    {
        public int Id { get; set; }
        public string Ip { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
    }
}
