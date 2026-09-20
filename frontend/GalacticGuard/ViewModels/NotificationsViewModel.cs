using System.ComponentModel;

namespace GalacticGuard.ViewModels
{
    public class NotificationsViewModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        private string _notificationMessage = "No new notifications";

        public string NotificationMessage
        {
            get => _notificationMessage;
            set
            {
                if (_notificationMessage != value)
                {
                    _notificationMessage = value;
                    OnPropertyChanged(nameof(NotificationMessage));
                }
            }
        }

        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
