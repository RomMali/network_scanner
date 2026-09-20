using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GalacticGuard.Models;
using GalacticGuard.Services;

namespace GalacticGuard.ViewModels
{
    public partial class RulesViewModel : ObservableObject
    {
        private readonly IpsApiClient _api;
        private readonly AuthSession _session;

        public ObservableCollection<IpsRule> Rules { get; } = new();
        public ObservableCollection<BlacklistItem> Blacklist { get; } = new();

        [ObservableProperty] private bool isAdvanced;
        [ObservableProperty] private string message = string.Empty;
        [ObservableProperty] private string newSrc = "0.0.0.0/0";
        [ObservableProperty] private string newDst = "any";
        [ObservableProperty] private string newProto = "tcp";
        [ObservableProperty] private string newDport = "80";
        [ObservableProperty] private string newAction = "deny";
        [ObservableProperty] private string newPriority = "100";
        [ObservableProperty] private string blacklistIp = string.Empty;

        public RulesViewModel(IpsApiClient api, AuthSession session)
        {
            _api = api;
            _session = session;
            IsAdvanced = session.AdvancedMode;
        }

        public async Task LoadAsync()
        {
            IsAdvanced = _session.AdvancedMode;
            if (!IsAdvanced)
            {
                Message = "Standard mode: rule editing is disabled.";
                return;
            }
            try
            {
                Rules.Clear();
                foreach (var r in await _api.GetRulesAsync())
                    Rules.Add(r);
                Blacklist.Clear();
                foreach (var b in await _api.GetBlacklistAsync())
                    Blacklist.Add(b);
                Message = $"Fail-open worker. {Rules.Count} rules.";
            }
            catch (Exception ex)
            {
                Message = ex.Message;
            }
        }

        [RelayCommand]
        async Task AddRule()
        {
            if (!IsAdvanced) return;
            try
            {
                await _api.SaveRuleAsync(new IpsRule
                {
                    Priority = int.TryParse(NewPriority, out var p) ? p : 100,
                    Action = NewAction,
                    Src = NewSrc,
                    Dst = NewDst,
                    Proto = NewProto,
                    Dport = string.IsNullOrWhiteSpace(NewDport) ? null : NewDport,
                    Enabled = true
                });
                await LoadAsync();
            }
            catch (Exception ex)
            {
                Message = ex.Message;
            }
        }

        [RelayCommand]
        async Task DeleteRule(IpsRule? rule)
        {
            if (!IsAdvanced || rule == null) return;
            try
            {
                await _api.DeleteRuleAsync(rule.Id);
                await LoadAsync();
            }
            catch (Exception ex)
            {
                Message = ex.Message;
            }
        }
    }
}
