#if defined(_WIN64) && !defined(UNICODE)
#define UNICODE
#endif
#if defined(UNICODE) && !defined(_UNICODE)
#define _UNICODE
#endif
#if defined(_UNICODE) && !defined(UNICODE)
#define UNICODE
#endif
#if defined(_MSC_VER) && !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0333	/* 3.51 */
#endif

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <malloc.h>
#include "uplink.h"

#ifdef _MSC_VER
#pragma comment(lib,"delayimp")
/*
 * CL command line should also be complemented with following:
 *
 *	/link /delayload:advapi32.dll /delayload:user32.dll
 *
 * This is required if/as we want to support Win9x. With delayloaded
 * DLLs in question all we have to do is to make sure NT-specific
 * functions are not actually called under Win9x.
 */
#endif

#if defined(_WIN32_WINNT) && _WIN32_WINNT>=0x0333
int IsService()
{ HWINSTA h;
  DWORD len;
  WCHAR *name;

    GetDesktopWindow(); /* return value is ignored */

    h = GetProcessWindowStation();
    if (h==NULL) return -1;

    if (GetUserObjectInformationW (h,UOI_NAME,NULL,0,&len) ||
	GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	return -1;

    if (len>512) return -1;		/* paranoia */
    len++,len&=~1;			/* paranoia */
#ifdef _MSC_VER
    name=(WCHAR *)_alloca(len+sizeof(WCHAR));
#else
    name=(WCHAR *)alloca(len+sizeof(WCHAR));
#endif
    if (!GetUserObjectInformationW (h,UOI_NAME,name,len,&len))
	return -1;

    len++,len&=~1;			/* paranoia */
    name[len/sizeof(WCHAR)]=L'\0';	/* paranoia */
#if 1
    /* This doesn't cover "interactive" services [working with real
     * WinSta0's] nor programs started non-interactively by Task
     * Scheduler [those are working with SAWinSta]. */
    if (wcsstr(name,L"Service-0x"))	return 1;
#else
    /* This covers all non-interactive programs such as services. */
    if (!wcsstr(name,L"WinSta0"))	return 1;
#endif
    else				return 0;
}
#endif

static TCHAR msg[128];

static void unimplemented ()
{
#if defined(_WIN32_WINNT) && _WIN32_WINNT>=0x0333
    /* this -------------v--- guards NT-specific calls */
    if (GetVersion() < 0x80000000 && IsService())
    {	HANDLE h = RegisterEventSource(0,_T("OPENSSL"));
	TCHAR *pmsg=msg;
	ReportEvent(h,EVENTLOG_ERROR_TYPE,0,0,0,1,0,&pmsg,0);
	DeregisterEventSource(h);
    }
    else
#endif
    {	MSGBOXPARAMS         m;

	m.cbSize             = sizeof(m);
	m.hwndOwner          = NULL;
	m.lpszCaption        = _T("OpenSSL: FATAL");
	m.dwStyle            = MB_OK;
	m.hInstance          = NULL;
	m.lpszIcon           = IDI_ERROR;
	m.dwContextHelpId    = 0;
	m.lpfnMsgBoxCallback = NULL;
	m.dwLanguageId       = MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US);
	m.lpszText           = msg;

	MessageBoxIndirect (&m);
    }
    ExitProcess (1);
}

void OPENSSL_Uplink (void **table, int index)
{ static HMODULE app=NULL;
  static void **applinktable=NULL;
  int len;

    len = _stprintf (msg,_T("OPENSSL_Uplink(%p,%02X): "),table,index);
    _tcscpy (msg+len,_T("unimplemented function"));
    table [index] = unimplemented;

    if (app==NULL && (app=GetModuleHandle(NULL))==NULL)
    {	app=(HMODULE)-1; _tcscpy (msg+len,_T("no host application"));
	return;
    }
    else if (app==(HMODULE)-1)	{ return; }

    if (applinktable==NULL)
    { void**(*applink)();

	applink=(void**(*)())GetProcAddress(app,"OPENSSL_Applink");
	if (applink==NULL)
	{   app=(HMODULE)-1; _tcscpy (msg+len,_T("no OPENSSL_Applink"));
	    return;
	}
	applinktable = (*applink)();
	if (applinktable==NULL)
	{   app=(HMODULE)-1; _tcscpy (msg+len,_T("no ApplinkTable"));
	    return;
	}
    }

    if (index > (int)applinktable[0])	{ return; }

    if (applinktable[index]) table[index] = applinktable[index];
}    

#if defined(_MSC_VER) && defined(_M_IX86)
#define LAZY(i)		\
__declspec(naked) static void lazy##i () { 	\
	_asm	push i				\
	_asm	push OFFSET OPENSSL_UplinkTable	\
	_asm	call OPENSSL_Uplink		\
	_asm	add  esp,8			\
	_asm	jmp  OPENSSL_UplinkTable+4*i	}

#if APPLINK_MAX>20
#error "Add more stubs..."
#endif
/* make some in advance... */
LAZY(1)  LAZY(2)  LAZY(3)  LAZY(4)  LAZY(5)
LAZY(6)  LAZY(7)  LAZY(8)  LAZY(9)  LAZY(10)
LAZY(11) LAZY(12) LAZY(13) LAZY(14) LAZY(15)
LAZY(16) LAZY(17) LAZY(18) LAZY(19) LAZY(20)
void *OPENSSL_UplinkTable[] = {
	(void *)APPLINK_MAX,
	lazy1, lazy2, lazy3, lazy4, lazy5,
	lazy6, lazy7, lazy8, lazy9, lazy10,
	lazy11,lazy12,lazy13,lazy14,lazy15,
	lazy16,lazy17,lazy18,lazy19,lazy20,
};
#endif

#ifdef SELFTEST
main() {  UP_fprintf(UP_stdout,"hello, world!\n"); }
#endif
