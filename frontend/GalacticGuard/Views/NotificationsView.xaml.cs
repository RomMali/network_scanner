using GalacticGuard.ViewModels;

namespace GalacticGuard.Views
{
    public partial class NotificationsView : ContentPage
    {
        public NotificationsView()
        {
            InitializeComponent();
            BindingContext = new NotificationsViewModel();
        }
    }
}
