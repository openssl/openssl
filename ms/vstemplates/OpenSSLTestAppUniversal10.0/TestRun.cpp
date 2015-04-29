#include "pch.h"
#include "TestRun.h"
using namespace Platform;
using namespace Windows::UI;
using namespace Windows::UI::Xaml::Media;

namespace OpenSSLTestApp
{
	TestRun::TestRun(Platform::String^ test, int errorcode, double time)
	{
		this->m_test = test;
		if (errorcode != 0)
		{
			this->m_errorcode = "FAIL";
			this->m_color = ref new SolidColorBrush(Colors::Red);
		}
		else
		{
			this->m_errorcode = "PASS";
			this->m_color = ref new SolidColorBrush(Colors::Green);
		}
		this->m_time = time.ToString();

	}

	String^ TestRun::test::get()
	{
		return m_test;
	}

	void TestRun::test::set(String^ value)
	{
		m_test = value;
	}

	String^ TestRun::errorcode::get()
	{
		return m_errorcode;
	}

	void TestRun::errorcode::set(String^ value)
	{
		m_errorcode = value;
	}

	String^ TestRun::time::get()
	{
		return m_time;
	}

	void TestRun::time::set(String^ value)
	{
		m_time = value;
	}

	Brush^ TestRun::color::get()
	{
		return m_color;
	}

	void TestRun::color::set(Brush^ value)
	{
		m_color = value;
	}
}
