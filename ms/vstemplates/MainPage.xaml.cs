using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
#if WINDOWS_APP
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.UI;
using Windows.UI.Core;
#else
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;
using System.Windows.Media;
using System.Windows.Controls;
using System.Windows.Navigation;
using OpenSSLTestApp.Resources;
using System.Windows;
#endif

using winrtcomponent;
// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace OpenSSLTestApp
{
    public class TestRun
    {
        public String test { get; set; }
        public String errorcode { get; set; }
        public String time { get; set; }
        public Brush color { get; set; }

        public TestRun(String test, int errorcode, double time)
        {
            this.test = test;
            if (errorcode != 0)
            {
                this.errorcode = "FAIL";
                color = new SolidColorBrush(Colors.Red);
            }
            else
            {
                this.errorcode = "PASS";
                color = new SolidColorBrush(Colors.Green);
            }
            this.time = time.ToString();
        }
    }
    public partial class MainPage
#if WINDOWS_APP
        : Page
#else
        : PhoneApplicationPage
#endif
    {
        testClass testRunner;
        int anyError = 0;
        // Constructor
        public MainPage()
        {
            InitializeComponent();
            testRunner = new testClass();
            testRunner.testExecuted += updateRun;
        }
        private void updateRun(object sender, string testrun, int errorcode, double time)
        {
#if WINDOWS_APP
            Tests.Dispatcher.RunAsync( CoreDispatcherPriority.Normal, () =>
#else
            Tests.Dispatcher.BeginInvoke(() =>
#endif
            {
                if (errorcode != 0) anyError++;
                var item = new TestRun( testrun, errorcode, time );
                Tests.Items.Add( item );
                Tests.ScrollIntoView( item );
            } );
        }

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            Tests.Items.Clear();
            anyError = 0;
            Title.Text = "Running ... ";
            RunTests.IsEnabled = false;
            int errorlevel = 0;
            await Task.Run( () =>
            {
                errorlevel = testRunner.test();
            } );
            RunTests.IsEnabled = true;
            if (anyError != 0 || errorlevel !=0 )
                Title.Text = "Errors ocurred...";
            else
                Title.Text = "All tests passed!";
        }
    }
}
