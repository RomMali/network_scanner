using System.ComponentModel;

namespace GalacticGuard.ViewModels
{
    public class SettingsViewModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        private string _theme = "Light";

        public string Theme
        {
            get => _theme;
            set
            {
                if (_theme != value)
                {
                    _theme = value;
                    OnPropertyChanged(nameof(Theme));
                }
            }
        }

        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
