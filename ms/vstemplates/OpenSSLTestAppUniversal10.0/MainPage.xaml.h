//
// MainPage.xaml.h
// Declaration of the MainPage class.
//

#pragma once

#include "MainPage.g.h"
#include "..\..\ms\vstemplates\winrtcomponent.h"
#include "TestRun.h"

namespace OpenSSLTestApp
{
	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	public ref class MainPage sealed
	{
	public:
		MainPage();
	private:
		void RunTests_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void updateRun(Platform::Object^ sender, Platform::String^ testrun, int errorcode, double time);

	private:
		winrtcomponent::testClass^ testRunner;
		int anyError;
	};
}
