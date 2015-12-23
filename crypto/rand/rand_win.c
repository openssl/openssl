/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
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
static void readscreen(void);

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

void RAND_screen(void)
{                               /* function available for backward
                                 * compatibility */
    RAND_poll();
    readscreen();
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

/* feed screen contents to PRNG */
/*****************************************************************************
 *
 * Created 960901 by Gertjan van Oosten, gertjan@West.NL, West Consulting B.V.
 *
 * Code adapted from
 * <URL:http://support.microsoft.com/default.aspx?scid=kb;[LN];97193>;
 * the original copyright message is:
 *
 *   (C) Copyright Microsoft Corp. 1993.  All rights reserved.
 *
 *   You have a royalty-free right to use, modify, reproduce and
 *   distribute the Sample Files (and/or any modified version) in
 *   any way you find useful, provided that you agree that
 *   Microsoft has no warranty obligations or liability for any
 *   Sample Application Files which are modified.
 */

static void readscreen(void)
{
# if !defined(OPENSSL_SYS_WIN32_CYGWIN)
    HDC hScrDC;                 /* screen DC */
    HBITMAP hBitmap;            /* handle for our bitmap */
    BITMAP bm;                  /* bitmap properties */
    unsigned int size;          /* size of bitmap */
    char *bmbits;               /* contents of bitmap */
    int w;                      /* screen width */
    int h;                      /* screen height */
    int y;                      /* y-coordinate of screen lines to grab */
    int n = 16;                 /* number of screen lines to grab at a time */
    BITMAPINFOHEADER bi;        /* info about the bitmap */

    if (check_winnt() && OPENSSL_isservice() > 0)
        return;

    /* Get a reference to the screen DC */
    hScrDC = GetDC(NULL);

    /* Get screen resolution */
    w = GetDeviceCaps(hScrDC, HORZRES);
    h = GetDeviceCaps(hScrDC, VERTRES);

    /* Create a bitmap compatible with the screen DC */
    hBitmap = CreateCompatibleBitmap(hScrDC, w, n);

    /* Get bitmap properties */
    GetObject(hBitmap, sizeof(BITMAP), (LPSTR) & bm);
    size = (unsigned int)bm.bmWidthBytes * bm.bmHeight * bm.bmPlanes;

    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bm.bmWidth;
    bi.biHeight = bm.bmHeight;
    bi.biPlanes = bm.bmPlanes;
    bi.biBitCount = bm.bmBitsPixel;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;

    bmbits = OPENSSL_malloc(size);
    if (bmbits != NULL) {
        /* Now go through the whole screen, repeatedly grabbing n lines */
        for (y = 0; y < h - n; y += n) {
            unsigned char md[MD_DIGEST_LENGTH];

            /* Copy the bits of the current line range into the buffer */
            GetDIBits(hScrDC, hBitmap, y, n,
                      bmbits, (BITMAPINFO *) & bi, DIB_RGB_COLORS);

            /* Get the hash of the bitmap */
            MD(bmbits, size, md);

            /* Seed the random generator with the hash value */
            RAND_add(md, MD_DIGEST_LENGTH, 0);
        }

        OPENSSL_free(bmbits);
    }

    /* Clean up */
    DeleteObject(hBitmap);
    ReleaseDC(NULL, hScrDC);
# endif                         /* !OPENSSL_SYS_WIN32_CYGWIN */
}

#endif
