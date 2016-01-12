/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "rand_lcl.h"

#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
# include <windows.h>
# ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0400
# endif
# include <wincrypt.h>
# include <tlhelp32.h>

/*
 * Limit the time spent walking through the heap, processes, threads and
 * modules to a maximum of 1000 milliseconds each, unless CryptoGenRandom
 * failed
 */
# define MAXDELAY 1000

/*
 * Intel hardware RNG CSP -- available from
 * http://developer.intel.com/design/security/rng/redist_license.htm
 */
# define PROV_INTEL_SEC 22
# define INTEL_DEF_PROV L"Intel Hardware Cryptographic Service Provider"

static void readtimer(void);

/*
 * It appears like CURSORINFO, PCURSORINFO and LPCURSORINFO are only defined
 * when WINVER is 0x0500 and up, which currently only happens on Win2000.
 * Unfortunately, those are typedefs, so they're a little bit difficult to
 * detect properly.  On the other hand, the macro CURSOR_SHOWING is defined
 * within the same conditional, so it can be use to detect the absence of
 * said typedefs.
 */

# ifndef CURSOR_SHOWING
/*
 * Information about the global cursor.
 */
typedef struct tagCURSORINFO {
    DWORD cbSize;
    DWORD flags;
    HCURSOR hCursor;
    POINT ptScreenPos;
} CURSORINFO, *PCURSORINFO, *LPCURSORINFO;

#  define CURSOR_SHOWING     0x00000001
# endif                         /* CURSOR_SHOWING */

int RAND_poll(void)
{
    MEMORYSTATUS mst;
    HCRYPTPROV hProvider = 0;
    DWORD w;
    BYTE buf[64];

    /* poll the CryptoAPI PRNG */
    /* The CryptoAPI returns sizeof(buf) bytes of randomness */
    if (CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if (CryptGenRandom(hProvider, sizeof(buf), buf) != 0) {
            RAND_add(buf, sizeof(buf), sizeof(buf));
        }
        CryptReleaseContext(hProvider, 0);
    }

    /* poll the Pentium PRG with CryptoAPI */
    if (CryptAcquireContextW(&hProvider, NULL, INTEL_DEF_PROV, PROV_INTEL_SEC, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if (CryptGenRandom(hProvider, sizeof(buf), buf) != 0) {
            RAND_add(buf, sizeof(buf), sizeof(buf));
        }
        CryptReleaseContext(hProvider, 0);
    }

    /* timer data */
    readtimer();

    /* memory usage statistics */
    GlobalMemoryStatus(&mst);
    RAND_add(&mst, sizeof(mst), 1);

    /* process ID */
    w = GetCurrentProcessId();
    RAND_add(&w, sizeof(w), 1);

    return (1);
}

int RAND_event(UINT iMsg, WPARAM wParam, LPARAM lParam)
{
    double add_entropy = 0;

    switch (iMsg) {
    case WM_KEYDOWN:
        {
            static WPARAM key;
            if (key != wParam)
                add_entropy = 0.05;
            key = wParam;
        }
        break;
    case WM_MOUSEMOVE:
        {
            static int lastx, lasty, lastdx, lastdy;
            int x, y, dx, dy;

            x = LOWORD(lParam);
            y = HIWORD(lParam);
            dx = lastx - x;
            dy = lasty - y;
            if (dx != 0 && dy != 0 && dx - lastdx != 0 && dy - lastdy != 0)
                add_entropy = .2;
            lastx = x, lasty = y;
            lastdx = dx, lastdy = dy;
        }
        break;
    }

    readtimer();
    RAND_add(&iMsg, sizeof(iMsg), add_entropy);
    RAND_add(&wParam, sizeof(wParam), 0);
    RAND_add(&lParam, sizeof(lParam), 0);

    return (RAND_status());
}

/* feed timing information to the PRNG */
static void readtimer(void)
{
    DWORD w;
    LARGE_INTEGER l;
    static int have_perfc = 1;
# if defined(_MSC_VER) && defined(_M_X86)
    static int have_tsc = 1;
    DWORD cyclecount;

    if (have_tsc) {
        __try {
            __asm {
            _emit 0x0f _emit 0x31 mov cyclecount, eax}
            RAND_add(&cyclecount, sizeof(cyclecount), 1);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            have_tsc = 0;
        }
    }
# else
#  define have_tsc 0
# endif

    if (have_perfc) {
        if (QueryPerformanceCounter(&l) == 0)
            have_perfc = 0;
        else
            RAND_add(&l, sizeof(l), 0);
    }

    if (!have_tsc && !have_perfc) {
        w = GetTickCount();
        RAND_add(&w, sizeof(w), 0);
    }
}

#endif
