using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using GalacticGuard.ViewModels;

namespace GalacticGuard.Views
{
    public partial class AnalyticsView : ContentPage
    {
        public AnalyticsView()
        {
            InitializeComponent();
            BindingContext = new AnalyticsViewModel();
        }
    }
}
