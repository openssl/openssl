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


#if defined(WINDOWS) || defined(WIN32)
#include "cryptlib.h"
#include <windows.h>
#include <openssl/rand.h>
/* XXX There are probably other includes missing here ... */


#if !defined(USE_MD5_RAND) && !defined(USE_SHA1_RAND) && !defined(USE_MDC2_RAND) && !defined(USE_MD2_RAND)
#if !defined(NO_SHA) && !defined(NO_SHA1)
#define USE_SHA1_RAND
#elif !defined(NO_MD5)
#define USE_MD5_RAND
#elif !defined(NO_MDC2) && !defined(NO_DES)
#define USE_MDC2_RAND
#elif !defined(NO_MD2)
#define USE_MD2_RAND
#else
#error No message digest algorithm available
#endif
#endif

#if defined(USE_MD5_RAND)
#include <openssl/md5.h>
#define MD_DIGEST_LENGTH	MD5_DIGEST_LENGTH
#define	MD(a,b,c)		MD5(a,b,c)
#elif defined(USE_SHA1_RAND)
#include <openssl/sha.h>
#define MD_DIGEST_LENGTH	SHA_DIGEST_LENGTH
#define	MD(a,b,c)		SHA1(a,b,c)
#elif defined(USE_MDC2_RAND)
#include <openssl/mdc2.h>
#define MD_DIGEST_LENGTH	MDC2_DIGEST_LENGTH
#define	MD(a,b,c)		MDC2(a,b,c)
#elif defined(USE_MD2_RAND)
#include <openssl/md2.h>
#define MD_DIGEST_LENGTH	MD2_DIGEST_LENGTH
#define	MD(a,b,c)		MD2(a,b,c)
#endif


int RAND_event(UINT iMsg, WPARAM wParam, LPARAM lParam)
        {
        double add_entropy=0;
        SYSTEMTIME t;

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

        GetSystemTime(&t);
        RAND_add(&iMsg, sizeof(iMsg), add_entropy);
	RAND_add(&wParam, sizeof(wParam), 0);
	RAND_add(&lParam, sizeof(lParam), 0);
        RAND_add(&t, sizeof(t), 0);

	return (RAND_status());
	}


/*****************************************************************************
 * Initialisation function for the SSL random generator.  Takes the contents
 * of the screen as random seed.
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
/*
 * I have modified the loading of bytes via RAND_seed() mechanism since
 * the original would have been very very CPU intensive since RAND_seed()
 * does an MD5 per 16 bytes of input.  The cost to digest 16 bytes is the same
 * as that to digest 56 bytes.  So under the old system, a screen of
 * 1024*768*256 would have been CPU cost of approximately 49,000 56 byte MD5
 * digests or digesting 2.7 mbytes.  What I have put in place would
 * be 48 16k MD5 digests, or effectively 48*16+48 MD5 bytes or 816 kbytes
 * or about 3.5 times as much.
 * - eric 
 */
void RAND_screen(void)
{
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
  hScrDC = CreateDC("DISPLAY", NULL, NULL, NULL);
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

	/* Get the MD5 of the bitmap */
	MD(bmbits,size,md);

	/* Seed the random generator with the MD5 digest */
	RAND_seed(md, MD_DIGEST_LENGTH);
	}

    OPENSSL_free(bmbits);
  }

  /* Select old bitmap back into memory DC */
  hBitmap = SelectObject(hMemDC, hOldBitmap);

  /* Clean up */
  DeleteObject(hBitmap);
  DeleteDC(hMemDC);
  DeleteDC(hScrDC);
}

#else

# if PEDANTIC
static void *dummy=&dummy;
# endif

#endif
