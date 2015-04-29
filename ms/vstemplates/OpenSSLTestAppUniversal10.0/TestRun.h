#pragma once
namespace OpenSSLTestApp
{
	[Windows::UI::Xaml::Data::Bindable]
	public ref class TestRun sealed
	{
	public:
		TestRun(Platform::String^ test, int errorcode, double time);
		property Platform::String^ test
		{
			Platform::String^ get();
			void set(Platform::String^ value);
		}
		property Platform::String^ errorcode
		{
			Platform::String^ get();
			void set(Platform::String^ value);
		}
		property Platform::String^ time
		{
			Platform::String^ get();
			void set(Platform::String^ value);
		}
		property Windows::UI::Xaml::Media::Brush^ color
		{
			Windows::UI::Xaml::Media::Brush^ get();
			void set(Windows::UI::Xaml::Media::Brush^ value);
		}

	private:
		Platform::String^ m_test;
		Platform::String^ m_errorcode;
		Platform::String^ m_time;
		Windows::UI::Xaml::Media::Brush^ m_color;
	};
}
