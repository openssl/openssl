/* crypto/rand/rand_win.c */
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

#include "cryptlib.h"
#include <openssl/rand.h>
#include "rand_lcl.h"

#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
#include <windows.h>
#ifndef _WIN32_WINNT
# define _WIN32_WINNT 0x0400
#endif
#include <wincrypt.h>
#include <tlhelp32.h>

/* Intel hardware RNG CSP -- available from
 * http://developer.intel.com/design/security/rng/redist_license.htm
 */
#define PROV_INTEL_SEC 22
#define INTEL_DEF_PROV TEXT("Intel Hardware Cryptographic Service Provider")

static void readtimer(void);
static void readscreen(void);

/* It appears like CURSORINFO, PCURSORINFO and LPCURSORINFO are only defined
   when WINVER is 0x0500 and up, which currently only happens on Win2000.
   Unfortunately, those are typedefs, so they're a little bit difficult to
   detect properly.  On the other hand, the macro CURSOR_SHOWING is defined
   within the same conditional, so it can be use to detect the absence of said
   typedefs. */

#ifndef CURSOR_SHOWING
/*
 * Information about the global cursor.
 */
typedef struct tagCURSORINFO
{
    DWORD   cbSize;
    DWORD   flags;
    HCURSOR hCursor;
    POINT   ptScreenPos;
} CURSORINFO, *PCURSORINFO, *LPCURSORINFO;

#define CURSOR_SHOWING     0x00000001
#endif /* CURSOR_SHOWING */

typedef BOOL (WINAPI *CRYPTACQUIRECONTEXT)(HCRYPTPROV *, LPCTSTR, LPCTSTR,
				    DWORD, DWORD);
typedef BOOL (WINAPI *CRYPTGENRANDOM)(HCRYPTPROV, DWORD, BYTE *);
typedef BOOL (WINAPI *CRYPTRELEASECONTEXT)(HCRYPTPROV, DWORD);

typedef HWND (WINAPI *GETFOREGROUNDWINDOW)(VOID);
typedef BOOL (WINAPI *GETCURSORINFO)(PCURSORINFO);
typedef DWORD (WINAPI *GETQUEUESTATUS)(UINT);

typedef HANDLE (WINAPI *CREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);
typedef BOOL (WINAPI *CLOSETOOLHELP32SNAPSHOT)(HANDLE);
typedef BOOL (WINAPI *HEAP32FIRST)(LPHEAPENTRY32, DWORD, DWORD);
typedef BOOL (WINAPI *HEAP32NEXT)(LPHEAPENTRY32);
typedef BOOL (WINAPI *HEAP32LIST)(HANDLE, LPHEAPLIST32);
typedef BOOL (WINAPI *PROCESS32)(HANDLE, LPPROCESSENTRY32);
typedef BOOL (WINAPI *THREAD32)(HANDLE, LPTHREADENTRY32);
typedef BOOL (WINAPI *MODULE32)(HANDLE, LPMODULEENTRY32);

#include <lmcons.h>
#ifndef OPENSSL_SYS_WINCE
#include <lmstats.h>
#endif
#if 1 /* The NET API is Unicode only.  It requires the use of the UNICODE
       * macro.  When UNICODE is defined LPTSTR becomes LPWSTR.  LMSTR was
       * was added to the Platform SDK to allow the NET API to be used in
       * non-Unicode applications provided that Unicode strings were still
       * used for input.  LMSTR is defined as LPWSTR.
       */
typedef NET_API_STATUS (NET_API_FUNCTION * NETSTATGET)
        (LPWSTR, LPWSTR, DWORD, DWORD, LPBYTE*);
typedef NET_API_STATUS (NET_API_FUNCTION * NETFREE)(LPBYTE);
#endif /* 1 */

int RAND_poll(void)
{
	MEMORYSTATUS m;
	HCRYPTPROV hProvider = 0;
	BYTE buf[64];
	DWORD w;
	HWND h;

	HMODULE advapi, kernel, user, netapi;
	CRYPTACQUIRECONTEXT acquire = 0;
	CRYPTGENRANDOM gen = 0;
	CRYPTRELEASECONTEXT release = 0;
#if 1 /* There was previously a problem with NETSTATGET.  Currently, this
       * section is still experimental, but if all goes well, this conditional
       * will be removed
       */
	NETSTATGET netstatget = 0;
	NETFREE netfree = 0;
#endif /* 1 */

	/* Determine the OS version we are on so we can turn off things 
	 * that do not work properly.
	 */
        OSVERSIONINFO osverinfo ;
        osverinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO) ;
        GetVersionEx( &osverinfo ) ;

#if defined(OPENSSL_SYS_WINCE) && WCEPLATFORM!=MS_HPC_PRO
	/* poll the CryptoAPI PRNG */
	/* The CryptoAPI returns sizeof(buf) bytes of randomness */
	if (CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
		if (CryptGenRandom(hProvider, sizeof(buf), buf))
			RAND_add(buf, sizeof(buf), sizeof(buf));
		CryptReleaseContext(hProvider, 0); 
		}
#endif

	/* load functions dynamically - not available on all systems */
	advapi = LoadLibrary(TEXT("ADVAPI32.DLL"));
	kernel = LoadLibrary(TEXT("KERNEL32.DLL"));
	user = LoadLibrary(TEXT("USER32.DLL"));
	netapi = LoadLibrary(TEXT("NETAPI32.DLL"));

#ifndef OPENSSL_SYS_WINCE
#if 1 /* There was previously a problem with NETSTATGET.  Currently, this
       * section is still experimental, but if all goes well, this conditional
       * will be removed
       */
	if (netapi)
		{
		netstatget = (NETSTATGET) GetProcAddress(netapi,TEXT("NetStatisticsGet"));
		netfree = (NETFREE) GetProcAddress(netapi,TEXT("NetApiBufferFree"));
		}

	if (netstatget && netfree)
		{
		LPBYTE outbuf;
		/* NetStatisticsGet() is a Unicode only function
 		 * STAT_WORKSTATION_0 contains 45 fields and STAT_SERVER_0
		 * contains 17 fields.  We treat each field as a source of
		 * one byte of entropy.
                 */

		if (netstatget(NULL, L"LanmanWorkstation", 0, 0, &outbuf) == 0)
			{
			RAND_add(outbuf, sizeof(STAT_WORKSTATION_0), 45);
			netfree(outbuf);
			}
		if (netstatget(NULL, L"LanmanServer", 0, 0, &outbuf) == 0)
			{
			RAND_add(outbuf, sizeof(STAT_SERVER_0), 17);
			netfree(outbuf);
			}
		}

	if (netapi)
		FreeLibrary(netapi);
#endif /* 1 */
#endif /* !OPENSSL_SYS_WINCE */
 
#ifndef OPENSSL_SYS_WINCE
        /* It appears like this can cause an exception deep within ADVAPI32.DLL
         * at random times on Windows 2000.  Reported by Jeffrey Altman.  
         * Only use it on NT.
	 */
	/* Wolfgang Marczy <WMarczy@topcall.co.at> reports that
	 * the RegQueryValueEx call below can hang on NT4.0 (SP6).
	 * So we don't use this at all for now. */
#if 0
        if ( osverinfo.dwPlatformId == VER_PLATFORM_WIN32_NT &&
		osverinfo.dwMajorVersion < 5)
		{
		/* Read Performance Statistics from NT/2000 registry
		 * The size of the performance data can vary from call
		 * to call so we must guess the size of the buffer to use
		 * and increase its size if we get an ERROR_MORE_DATA
		 * return instead of ERROR_SUCCESS.
		 */
		LONG   rc=ERROR_MORE_DATA;
		char * buf=NULL;
		DWORD bufsz=0;
		DWORD length;

		while (rc == ERROR_MORE_DATA)
			{
			buf = realloc(buf,bufsz+8192);
			if (!buf)
				break;
			bufsz += 8192;

			length = bufsz;
			rc = RegQueryValueEx(HKEY_PERFORMANCE_DATA, TEXT("Global"),
				NULL, NULL, buf, &length);
			}
		if (rc == ERROR_SUCCESS)
			{
                        /* For entropy count assume only least significant
			 * byte of each DWORD is random.
			 */
			RAND_add(&length, sizeof(length), 0);
			RAND_add(buf, length, length / 4.0);

			/* Close the Registry Key to allow Windows to cleanup/close
			 * the open handle
			 * Note: The 'HKEY_PERFORMANCE_DATA' key is implicitly opened
			 *       when the RegQueryValueEx above is done.  However, if
			 *       it is not explicitly closed, it can cause disk
			 *       partition manipulation problems.
			 */
			RegCloseKey(HKEY_PERFORMANCE_DATA);
			}
		if (buf)
			free(buf);
		}
#endif
#endif /* !OPENSSL_SYS_WINCE */

	if (advapi)
		{
		acquire = (CRYPTACQUIRECONTEXT) GetProcAddress(advapi,
			TEXT("CryptAcquireContextA"));
		gen = (CRYPTGENRANDOM) GetProcAddress(advapi,
			TEXT("CryptGenRandom"));
		release = (CRYPTRELEASECONTEXT) GetProcAddress(advapi,
			TEXT("CryptReleaseContext"));
		}

	if (acquire && gen && release)
		{
		/* poll the CryptoAPI PRNG */
                /* The CryptoAPI returns sizeof(buf) bytes of randomness */
		if (acquire(&hProvider, 0, 0, PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT))
			{
			if (gen(hProvider, sizeof(buf), buf) != 0)
				{
				RAND_add(buf, sizeof(buf), 0);
#if 0
				printf("randomness from PROV_RSA_FULL\n");
#endif
				}
			release(hProvider, 0); 
			}
		
		/* poll the Pentium PRG with CryptoAPI */
		if (acquire(&hProvider, 0, INTEL_DEF_PROV, PROV_INTEL_SEC, 0))
			{
			if (gen(hProvider, sizeof(buf), buf) != 0)
				{
				RAND_add(buf, sizeof(buf), sizeof(buf));
#if 0
				printf("randomness from PROV_INTEL_SEC\n");
#endif
				}
			release(hProvider, 0);
			}
		}

        if (advapi)
		FreeLibrary(advapi);

	/* timer data */
	readtimer();
	
	/* memory usage statistics */
	GlobalMemoryStatus(&m);
	RAND_add(&m, sizeof(m), 1);

	/* process ID */
	w = GetCurrentProcessId();
	RAND_add(&w, sizeof(w), 1);

	if (user)
		{
		GETCURSORINFO cursor;
		GETFOREGROUNDWINDOW win;
		GETQUEUESTATUS queue;

		win = (GETFOREGROUNDWINDOW) GetProcAddress(user, TEXT("GetForegroundWindow"));
		cursor = (GETCURSORINFO) GetProcAddress(user, TEXT("GetCursorInfo"));
		queue = (GETQUEUESTATUS) GetProcAddress(user, TEXT("GetQueueStatus"));

		if (win)
			{
			/* window handle */
			h = win();
			RAND_add(&h, sizeof(h), 0);
			}
		if (cursor)
			{
			/* unfortunately, its not safe to call GetCursorInfo()
			 * on NT4 even though it exists in SP3 (or SP6) and
			 * higher.
			 */
			if ( osverinfo.dwPlatformId == VER_PLATFORM_WIN32_NT &&
				osverinfo.dwMajorVersion < 5)
				cursor = 0;
			}
		if (cursor)
			{
			/* cursor position */
                        /* assume 2 bytes of entropy */
			CURSORINFO ci;
			ci.cbSize = sizeof(CURSORINFO);
			if (cursor(&ci))
				RAND_add(&ci, ci.cbSize, 2);
			}

		if (queue)
			{
			/* message queue status */
                        /* assume 1 byte of entropy */
			w = queue(QS_ALLEVENTS);
			RAND_add(&w, sizeof(w), 1);
			}

		FreeLibrary(user);
		}

	/* Toolhelp32 snapshot: enumerate processes, threads, modules and heap
	 * http://msdn.microsoft.com/library/psdk/winbase/toolhelp_5pfd.htm
	 * (Win 9x and 2000 only, not available on NT)
	 *
	 * This seeding method was proposed in Peter Gutmann, Software
	 * Generation of Practically Strong Random Numbers,
	 * http://www.usenix.org/publications/library/proceedings/sec98/gutmann.html
	 * revised version at http://www.cryptoengines.com/~peter/06_random.pdf
	 * (The assignment of entropy estimates below is arbitrary, but based
	 * on Peter's analysis the full poll appears to be safe. Additional
	 * interactive seeding is encouraged.)
	 */

	if (kernel)
		{
		CREATETOOLHELP32SNAPSHOT snap;
		CLOSETOOLHELP32SNAPSHOT close_snap;
		HANDLE handle;

		HEAP32FIRST heap_first;
		HEAP32NEXT heap_next;
		HEAP32LIST heaplist_first, heaplist_next;
		PROCESS32 process_first, process_next;
		THREAD32 thread_first, thread_next;
		MODULE32 module_first, module_next;

		HEAPLIST32 hlist;
		HEAPENTRY32 hentry;
		PROCESSENTRY32 p;
		THREADENTRY32 t;
		MODULEENTRY32 m;

		snap = (CREATETOOLHELP32SNAPSHOT)
			GetProcAddress(kernel, TEXT("CreateToolhelp32Snapshot"));
		close_snap = (CLOSETOOLHELP32SNAPSHOT)
			GetProcAddress(kernel, TEXT("CloseToolhelp32Snapshot"));
		heap_first = (HEAP32FIRST) GetProcAddress(kernel, TEXT("Heap32First"));
		heap_next = (HEAP32NEXT) GetProcAddress(kernel, TEXT("Heap32Next"));
		heaplist_first = (HEAP32LIST) GetProcAddress(kernel, TEXT("Heap32ListFirst"));
		heaplist_next = (HEAP32LIST) GetProcAddress(kernel, TEXT("Heap32ListNext"));
		process_first = (PROCESS32) GetProcAddress(kernel, TEXT("Process32First"));
		process_next = (PROCESS32) GetProcAddress(kernel, TEXT("Process32Next"));
		thread_first = (THREAD32) GetProcAddress(kernel, TEXT("Thread32First"));
		thread_next = (THREAD32) GetProcAddress(kernel, TEXT("Thread32Next"));
		module_first = (MODULE32) GetProcAddress(kernel, TEXT("Module32First"));
		module_next = (MODULE32) GetProcAddress(kernel, TEXT("Module32Next"));

		if (snap && heap_first && heap_next && heaplist_first &&
			heaplist_next && process_first && process_next &&
			thread_first && thread_next && module_first &&
			module_next && (handle = snap(TH32CS_SNAPALL,0))
			!= INVALID_HANDLE_VALUE)
			{
			/* heap list and heap walking */
                        /* HEAPLIST32 contains 3 fields that will change with
                         * each entry.  Consider each field a source of 1 byte
                         * of entropy.
                         * HEAPENTRY32 contains 5 fields that will change with 
                         * each entry.  Consider each field a source of 1 byte
                         * of entropy.
                         */
			hlist.dwSize = sizeof(HEAPLIST32);		
			if (heaplist_first(handle, &hlist))
				do
					{
					RAND_add(&hlist, hlist.dwSize, 3);
					hentry.dwSize = sizeof(HEAPENTRY32);
					if (heap_first(&hentry,
						hlist.th32ProcessID,
						hlist.th32HeapID))
						{
						int entrycnt = 80;
						do
							RAND_add(&hentry,
								hentry.dwSize, 5);
						while (heap_next(&hentry)
							&& --entrycnt > 0);
						}
					} while (heaplist_next(handle,
						&hlist));
			
			/* process walking */
                        /* PROCESSENTRY32 contains 9 fields that will change
                         * with each entry.  Consider each field a source of
                         * 1 byte of entropy.
                         */
			p.dwSize = sizeof(PROCESSENTRY32);
			if (process_first(handle, &p))
				do
					RAND_add(&p, p.dwSize, 9);
				while (process_next(handle, &p));

			/* thread walking */
                        /* THREADENTRY32 contains 6 fields that will change
                         * with each entry.  Consider each field a source of
                         * 1 byte of entropy.
                         */
			t.dwSize = sizeof(THREADENTRY32);
			if (thread_first(handle, &t))
				do
					RAND_add(&t, t.dwSize, 6);
				while (thread_next(handle, &t));

			/* module walking */
                        /* MODULEENTRY32 contains 9 fields that will change
                         * with each entry.  Consider each field a source of
                         * 1 byte of entropy.
                         */
			m.dwSize = sizeof(MODULEENTRY32);
			if (module_first(handle, &m))
				do
					RAND_add(&m, m.dwSize, 9);
				while (module_next(handle, &m));
			if (close_snap)
				close_snap(handle);
			else
				CloseHandle(handle);
			}

		FreeLibrary(kernel);
		}

#if 0
	printf("Exiting RAND_poll\n");
#endif

	return(1);
}

int RAND_event(UINT iMsg, WPARAM wParam, LPARAM lParam)
        {
        double add_entropy=0;

        switch (iMsg)
                {
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
                        static int lastx,lasty,lastdx,lastdy;
                        int x,y,dx,dy;

                        x=LOWORD(lParam);
                        y=HIWORD(lParam);
                        dx=lastx-x;
                        dy=lasty-y;
                        if (dx != 0 && dy != 0 && dx-lastdx != 0 && dy-lastdy != 0)
                                add_entropy=.2;
                        lastx=x, lasty=y;
                        lastdx=dx, lastdy=dy;
                        }
		break;
		}

	readtimer();
        RAND_add(&iMsg, sizeof(iMsg), add_entropy);
	RAND_add(&wParam, sizeof(wParam), 0);
	RAND_add(&lParam, sizeof(lParam), 0);
 
	return (RAND_status());
	}


void RAND_screen(void) /* function available for backward compatibility */
{
	RAND_poll();
	readscreen();
}


/* feed timing information to the PRNG */
static void readtimer(void)
{
	DWORD w;
	LARGE_INTEGER l;
	static int have_perfc = 1;
#if defined(_MSC_VER) && !defined(OPENSSL_SYS_WINCE)
	static int have_tsc = 1;
	DWORD cyclecount;

	if (have_tsc) {
	  __try {
	    __asm {
	      _emit 0x0f
	      _emit 0x31
	      mov cyclecount, eax
	      }
	    RAND_add(&cyclecount, sizeof(cyclecount), 1);
	  } __except(EXCEPTION_EXECUTE_HANDLER) {
	    have_tsc = 0;
	  }
	}
#else
# define have_tsc 0
#endif

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
 * <URL:http://www.microsoft.com/kb/developr/win_dk/q97193.htm>;
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
#ifndef OPENSSL_SYS_WINCE
  HDC		hScrDC;		/* screen DC */
  HDC		hMemDC;		/* memory DC */
  HBITMAP	hBitmap;	/* handle for our bitmap */
  HBITMAP	hOldBitmap;	/* handle for previous bitmap */
  BITMAP	bm;		/* bitmap properties */
  unsigned int	size;		/* size of bitmap */
  char		*bmbits;	/* contents of bitmap */
  int		w;		/* screen width */
  int		h;		/* screen height */
  int		y;		/* y-coordinate of screen lines to grab */
  int		n = 16;		/* number of screen lines to grab at a time */

  /* Create a screen DC and a memory DC compatible to screen DC */
  hScrDC = CreateDC(TEXT("DISPLAY"), NULL, NULL, NULL);
  hMemDC = CreateCompatibleDC(hScrDC);

  /* Get screen resolution */
  w = GetDeviceCaps(hScrDC, HORZRES);
  h = GetDeviceCaps(hScrDC, VERTRES);

  /* Create a bitmap compatible with the screen DC */
  hBitmap = CreateCompatibleBitmap(hScrDC, w, n);

  /* Select new bitmap into memory DC */
  hOldBitmap = SelectObject(hMemDC, hBitmap);

  /* Get bitmap properties */
  GetObject(hBitmap, sizeof(BITMAP), (LPSTR)&bm);
  size = (unsigned int)bm.bmWidthBytes * bm.bmHeight * bm.bmPlanes;

  bmbits = OPENSSL_malloc(size);
  if (bmbits) {
    /* Now go through the whole screen, repeatedly grabbing n lines */
    for (y = 0; y < h-n; y += n)
    	{
	unsigned char md[MD_DIGEST_LENGTH];

	/* Bitblt screen DC to memory DC */
	BitBlt(hMemDC, 0, 0, w, n, hScrDC, 0, y, SRCCOPY);

	/* Copy bitmap bits from memory DC to bmbits */
	GetBitmapBits(hBitmap, size, bmbits);

	/* Get the hash of the bitmap */
	MD(bmbits,size,md);

	/* Seed the random generator with the hash value */
	RAND_add(md, MD_DIGEST_LENGTH, 0);
	}

    OPENSSL_free(bmbits);
  }

  /* Select old bitmap back into memory DC */
  hBitmap = SelectObject(hMemDC, hOldBitmap);

  /* Clean up */
  DeleteObject(hBitmap);
  DeleteDC(hMemDC);
  DeleteDC(hScrDC);
#endif /* !OPENSSL_SYS_WINCE */
}

#endif
