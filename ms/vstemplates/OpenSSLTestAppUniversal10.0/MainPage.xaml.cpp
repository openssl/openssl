//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include <ppltasks.h>
#include "MainPage.xaml.h"
#include "TestRun.h"

using namespace OpenSSLTestApp;

using namespace concurrency;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Core;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace winrtcomponent;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

MainPage::MainPage()
{
	InitializeComponent();
	testRunner = ref new testClass();
	testRunner->testExecuted += ref new winrtcomponent::testUpdated(this, &OpenSSLTestApp::MainPage::updateRun);

	anyError = 0;
}


void OpenSSLTestApp::MainPage::RunTests_Click(Object^ sender, RoutedEventArgs^ e)
{
	Tests->Items->Clear();
	anyError = 0;
	Title->Text = "Running...";
	RunTests->IsEnabled = false;
	int errorlevel = 0;
	// Run the tests on a background thread to allow the UI to update
	auto task = create_task([this]()->int
	{
		return testRunner->test();
	}).then([this](int errorlevel)
	{
		// The tests have completed go back and update the UI
		Tests->Dispatcher->RunAsync(CoreDispatcherPriority::Normal,
			ref new DispatchedHandler([this, errorlevel]()
		{
			RunTests->IsEnabled = true;
			if (anyError != 0 || errorlevel != 0)
			{
				Title->Text = "Errors occured...";
			}
			else
			{
				Title->Text = "All tests passed!";
			}
		}));
	});
}

void OpenSSLTestApp::MainPage::updateRun(Platform::Object^ sender, Platform::String^ testrun, int errorcode, double time)
{
	// Update the UI based on the test result
	Tests->Dispatcher->RunAsync(CoreDispatcherPriority::Normal,
		ref new DispatchedHandler([testrun, errorcode, time, this]()
	{
		if (errorcode != 0) anyError++;
		auto item = ref new TestRun(testrun, errorcode, time);
		Tests->Items->Append(item);
		Tests->ScrollIntoView(item);
	}));
}

