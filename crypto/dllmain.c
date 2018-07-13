/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib_int.h"

#if defined(_WIN32) || defined(__CYGWIN__)
# ifdef __CYGWIN__
/* pick DLL_[PROCESS|THREAD]_[ATTACH|DETACH] definitions */
#  include <windows.h>
/*
 * this has side-effect of _WIN32 getting defined, which otherwise is
 * mutually exclusive with __CYGWIN__...
 */
# endif

/*
 * All we really need to do is remove the 'error' state when a thread
 * detaches
 */

static CRITICAL_SECTION csThreadStop;
static DWORD stop_key;
static void (*stop_fun)(void *);

int CRYPTO_THREAD_register_stop_function(DWORD key, void (*cleanup)(void *))
{
    if (cleanup == NULL)
        return 1;

    EnterCriticalSection(&csThreadStop);
    if (stop_fun != NULL) {
        /* We handle only one stop function. */
        LeaveCriticalSection(&csThreadStop);
        return 0;
    }

    stop_key = key;
    stop_fun = cleanup;
    LeaveCriticalSection(&csThreadStop);
    return 1;
}

void CRYPTO_THREAD_unregister_stop_function(DWORD key)
{
    EnterCriticalSection(&csThreadStop);
    if (key == stop_key) {
        stop_key = 0;
        stop_fun = NULL;
    }
    LeaveCriticalSection(&csThreadStop);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&csThreadStop);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        EnterCriticalSection(&csThreadStop);
        if (stop_fun != NULL)
            (*stop_fun)(TlsGetValue(stop_key));
        LeaveCriticalSection(&csThreadStop);
        break;
    case DLL_PROCESS_DETACH:
        /* BUG: We cannot call DeleteCriticalSection(&csThreadStop); */
        break;
    }
    return (TRUE);
}
#endif

