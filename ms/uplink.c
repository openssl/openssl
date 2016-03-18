#if (defined(_WIN64) || defined(_WIN32_WCE)) && !defined(UNICODE)
# define UNICODE
#endif
#if defined(UNICODE) && !defined(_UNICODE)
# define _UNICODE
#endif
#if defined(_UNICODE) && !defined(UNICODE)
# define UNICODE
#endif

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "uplink.h"
void OPENSSL_showfatal(const char *, ...);

static TCHAR msg[128];

static void unimplemented(void)
{
    OPENSSL_showfatal(sizeof(TCHAR) == sizeof(char) ? "%s\n" : "%S\n", msg);
    ExitProcess(1);
}

void OPENSSL_Uplink(volatile void **table, int index)
{
    static HMODULE volatile apphandle = NULL;
    static void **volatile applinktable = NULL;
    int len;
    void (*func) (void) = unimplemented;
    HANDLE h;
    void **p;

    /*
     * Note that the below code is not MT-safe in respect to msg buffer, but
     * what's the worst thing that can happen? Error message might be
     * misleading or corrupted. As error condition is fatal and should never
     * be risen, I accept the risk...
     */
    /*
     * One can argue that I should have used InterlockedExchangePointer or
     * something to update static variables and table[]. Well, store
     * instructions are as atomic as they can get and assigned values are
     * effectively constant... So that volatile qualifier should be
     * sufficient [it prohibits compiler to reorder memory access
     * instructions].
     */
    do {
        len = _sntprintf(msg, sizeof(msg) / sizeof(TCHAR),
                         _T("OPENSSL_Uplink(%p,%02X): "), table, index);
        _tcscpy(msg + len, _T("unimplemented function"));

        if ((h = apphandle) == NULL) {
            if ((h = GetModuleHandle(NULL)) == NULL) {
                apphandle = (HMODULE) - 1;
                _tcscpy(msg + len, _T("no host application"));
                break;
            }
            apphandle = h;
        }
        if ((h = apphandle) == (HMODULE) - 1) /* revalidate */
            break;

        if (applinktable == NULL) {
            void **(*applink) ();

            applink = (void **(*)())GetProcAddress(h, "OPENSSL_Applink");
            if (applink == NULL) {
                apphandle = (HMODULE) - 1;
                _tcscpy(msg + len, _T("no OPENSSL_Applink"));
                break;
            }
            p = (*applink) ();
            if (p == NULL) {
                apphandle = (HMODULE) - 1;
                _tcscpy(msg + len, _T("no ApplinkTable"));
                break;
            }
            applinktable = p;
        } else
            p = applinktable;

        if (index > (int)p[0])
            break;

        if (p[index])
            func = p[index];
    } while (0);

    table[index] = func;
}

#ifdef SELFTEST
main()
{
    UP_fprintf(UP_stdout, "hello, world!\n");
}
#endif
