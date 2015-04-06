/* winrt.cpp
 * C++/CX Entropy/shims for Windows Phone/Windows Store platform
 * written by Alejandro Jimenez Martinez
 * (aljim@microsoft.com) for the OpenSSL project 2014.
 */
#include <windows.h>
#if defined(WINAPI_FAMILY)
extern "C"
{
	unsigned entropyRT(BYTE *buffer, unsigned len);
	void RAND_add(const void *buf,int num,double entropy);
	int RAND_poll(void);
}
#endif

#if defined(OPENSSL_WINAPP_NOCRYPTOGRAPHICBUFFER)
#include <combaseapi.h>

// For Windows Phone 8, the Cryptography namespace is not avaialble from WinRT
// native code. Since we're only looking to generate random data, CoCreateGuid
// on WindowsPhone 8 internally calls GenerateRandom giving us an
// easy way to get to the API.

unsigned entropyRT(BYTE *buffer, unsigned len)
	{
	unsigned bytesLeft = len;
	BYTE* buffer_pos = buffer;
	GUID guid;
	while (bytesLeft > 0)
		{
		if (SUCCEEDED(CoCreateGuid(&guid)))
			{
			unsigned copy = (bytesLeft > sizeof(guid)) ? sizeof(guid) : bytesLeft;
			memcpy(buffer_pos, &guid, copy);
			buffer_pos += copy;
			bytesLeft -= copy;
			}
		else
			{
			break;
			}
		}
	return len - bytesLeft;
	}

#else
unsigned entropyRT(BYTE *buffer, unsigned len)
	{
	using namespace Platform;
	using namespace Windows::Foundation;
	using namespace Windows::Foundation::Collections;
	using namespace Windows::Security::Cryptography;
	using namespace Windows::Storage::Streams;
	IBuffer ^buf = CryptographicBuffer::GenerateRandom(len);
	Array<unsigned char> ^arr;
	CryptographicBuffer::CopyToByteArray(buf, &arr);
	unsigned arrayLen = arr->Length;

	// Make sure not to overflow the copy
	arrayLen = (arrayLen > len) ? len : arrayLen;
	memcpy(buffer, arr->Data, arrayLen);
	return arrayLen;
	}
#endif

int RAND_poll(void)
	{
	BYTE buf[60];
	unsigned collected = entropyRT(buf , sizeof(buf));
	RAND_add(buf, collected, collected);
	return 1;
	}

#if defined(OPENSSL_WINAPP)
extern "C"
{
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
	//no dynamic handle load
#if WINAPI_FAMILY==WINAPI_FAMILY_PHONE_APP
	void* LoadLibraryA(
					  const char* lpFileName
					  )
		{
		return NULL;
		}
#endif
	void* GetModuleHandle(
						 _In_opt_  LPCTSTR lpModuleName
						 )
		{
		return NULL;
		}
	//no log for phone
	int RegisterEventSource(
						   _In_  LPCTSTR lpUNCServerName,
						   _In_  LPCTSTR lpSourceName
						   )
		{
		return NULL;
		}

	int ReportEvent(
				   _In_  HANDLE hEventLog,
				   _In_  WORD wType,
				   _In_  WORD wCategory,
				   _In_  DWORD dwEventID,
				   _In_  PSID lpUserSid,
				   _In_  WORD wNumStrings,
				   _In_  DWORD dwDataSize,
				   _In_  LPCTSTR *lpStrings,
				   _In_  LPVOID lpRawData
				   )
		{
		return 0;
		}
	int MessageBox(
				  _In_opt_  HWND hWnd,
				  _In_opt_  LPCTSTR lpText,
				  _In_opt_  LPCTSTR lpCaption,
				  _In_      UINT uType
				  )
		{
		return 0;
		}

	HDC GetDC(
			 _In_  HWND hWnd
			 )
		{
		return NULL;
		}

	HDC CreateDC(
				LPCTSTR lpszDriver,
				_In_  LPCTSTR lpszDevice,
				LPCTSTR lpszOutput,
				_In_  const DEVMODE *lpInitData
				)
		{
		return NULL;
		}

	BOOL WINAPI GetVersionEx(
							_Inout_  LPOSVERSIONINFO lpVersionInfo
							)
		{
		return 0;
		}
	int GetObject(
				 _In_   HGDIOBJ hgdiobj,
				 _In_   int cbBuffer,
				 _Out_  LPVOID lpvObject
				 )
		{
		return 0;
		}
	int MoveFile(
				_In_  LPCTSTR lpExistingFileName,
				_In_  LPCTSTR lpNewFileName
				)
		{
		return 0;
		}
	int WINAPI GetProcessWindowStation(void)
		{
		return NULL;
		}
	BOOL WINAPI GetUserObjectInformationW(
										 _In_       HANDLE hObj,
										 _In_       int nIndex,
										 _Out_opt_  PVOID pvInfo,
										 _In_       DWORD nLength,
										 _Out_opt_  LPDWORD lpnLengthNeeded
										 )
		{
		return 0;
		}
#ifndef STD_ERROR_HANDLE
	int WINAPI GetStdHandle(
						   _In_  DWORD nStdHandle
						   )
		{
		return 0;
		}
#endif
	BOOL DeregisterEventSource(
							  _Inout_  HANDLE hEventLog
							  )
		{
		return 0;
		}
	char *winrt_getenv(
					  const char *varname
					  )
		{
		//hardcoded environmental variables used for the appx testing application for store/phone
		if (!strcmp(varname, "OPENSSL_CONF"))
			{
			return "./openssl.cnf";
			}
		return 0;
		}
	int winrt_setenv(const char *envname, const char *envval, int overwrite)
		{
		return -1;
		}
	void WINAPI GlobalMemoryStatus(
								  _Out_  LPMEMORYSTATUS lpBuffer
								  )
		{
		return;
		}
	HDC CreateCompatibleDC(
						  HDC hdc
						  )
		{
		return NULL;
		}
	int GetDeviceCaps(
					 _In_  HDC hdc,
					 _In_  int nIndex
					 )
		{
		return 0;
		}
	HBITMAP CreateCompatibleBitmap(
								  _In_  HDC hdc,
								  _In_  int nWidth,
								  _In_  int nHeight
								  )
		{
		return 0;
		}
	HGDIOBJ SelectObject(
						_In_  HDC hdc,
						_In_  HGDIOBJ hgdiobj
						)
		{
		return 0;
		}
	BOOL BitBlt(
			   _In_  HDC hdcDest,
			   _In_  int nXDest,
			   _In_  int nYDest,
			   _In_  int nWidth,
			   _In_  int nHeight,
			   _In_  HDC hdcSrc,
			   _In_  int nXSrc,
			   _In_  int nYSrc,
			   _In_  DWORD dwRop
			   )
		{
		return 0;
		}
	LONG GetBitmapBits(
					  _In_   HBITMAP hbmp,
					  _In_   LONG cbBuffer,
					  _Out_  LPVOID lpvBits
					  )
		{
		return 0;
		}
	BOOL DeleteObject(
					 _In_  HGDIOBJ hObject
					 )
		{
		return 0;
		}
	int _getch(void)
		{
		return 0;
		}
	int _kbhit()
		{
		return 0;
		}

	BOOL WINAPI FlushConsoleInputBuffer(
									   _In_  HANDLE hConsoleInput
									   )
		{
		return 0;
		}
	BOOL DeleteDC(
				 _In_  HDC hdc
				 )
		{
		return 0;
		}
	int winrt_GetTickCount(void)
		{
		LARGE_INTEGER t;
		return(int) (QueryPerformanceCounter(&t) ? t.QuadPart : 0);
		}
	void *OPENSSL_UplinkTable [26]= {0};
} //extern C

#endif /*WINAPI_FAMILY_PARTITION(WINAPI_FAMIILY_PHONE_APP)*/