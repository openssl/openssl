/* crypto/rand/md_rand.c */
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

#define ENTROPY_NEEDED 16  /* require 128 bits = 16 bytes of randomness */

#ifndef MD_RAND_DEBUG
# ifndef NDEBUG
#   define NDEBUG
# endif
#endif

#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "openssl/e_os.h"

#include <openssl/crypto.h>
#include <openssl/err.h>

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

/* Changed how the state buffer used.  I now attempt to 'wrap' such
 * that I don't run over the same locations the next time  go through
 * the 1023 bytes - many thanks to
 * Robert J. LeBlanc <rjl@renaissoft.com> for his comments
 */

#if defined(USE_MD5_RAND)
#include <openssl/md5.h>
#define MD_DIGEST_LENGTH	MD5_DIGEST_LENGTH
#define MD_CTX			MD5_CTX
#define MD_Init(a)		MD5_Init(a)
#define MD_Update(a,b,c)	MD5_Update(a,b,c)
#define	MD_Final(a,b)		MD5_Final(a,b)
#define	MD(a,b,c)		MD5(a,b,c)
#elif defined(USE_SHA1_RAND)
#include <openssl/sha.h>
#define MD_DIGEST_LENGTH	SHA_DIGEST_LENGTH
#define MD_CTX			SHA_CTX
#define MD_Init(a)		SHA1_Init(a)
#define MD_Update(a,b,c)	SHA1_Update(a,b,c)
#define	MD_Final(a,b)		SHA1_Final(a,b)
#define	MD(a,b,c)		SHA1(a,b,c)
#elif defined(USE_MDC2_RAND)
#include <openssl/mdc2.h>
#define MD_DIGEST_LENGTH	MDC2_DIGEST_LENGTH
#define MD_CTX			MDC2_CTX
#define MD_Init(a)		MDC2_Init(a)
#define MD_Update(a,b,c)	MDC2_Update(a,b,c)
#define	MD_Final(a,b)		MDC2_Final(a,b)
#define	MD(a,b,c)		MDC2(a,b,c)
#elif defined(USE_MD2_RAND)
#include <openssl/md2.h>
#define MD_DIGEST_LENGTH	MD2_DIGEST_LENGTH
#define MD_CTX			MD2_CTX
#define MD_Init(a)		MD2_Init(a)
#define MD_Update(a,b,c)	MD2_Update(a,b,c)
#define	MD_Final(a,b)		MD2_Final(a,b)
#define	MD(a,b,c)		MD2(a,b,c)
#endif

#include <openssl/rand.h>

/* #define NORAND	1 */
/* #define PREDICT	1 */

#define STATE_SIZE	1023
static int state_num=0,state_index=0;
static unsigned char state[STATE_SIZE+MD_DIGEST_LENGTH];
static unsigned char md[MD_DIGEST_LENGTH];
static long md_count[2]={0,0};
static double entropy=0;
static int initialized=0;

const char *RAND_version="RAND" OPENSSL_VERSION_PTEXT;

static void ssleay_rand_cleanup(void);
static void ssleay_rand_seed(const void *buf, int num);
static void ssleay_rand_add(const void *buf, int num, double add_entropy);
static int ssleay_rand_bytes(unsigned char *buf, int num);
static int ssleay_rand_pseudo_bytes(unsigned char *buf, int num);

RAND_METHOD rand_ssleay_meth={
	ssleay_rand_seed,
	ssleay_rand_bytes,
	ssleay_rand_cleanup,
	ssleay_rand_add,
	ssleay_rand_pseudo_bytes,
	}; 

RAND_METHOD *RAND_SSLeay(void)
	{
	return(&rand_ssleay_meth);
	}

static void ssleay_rand_cleanup(void)
	{
	memset(state,0,sizeof(state));
	state_num=0;
	state_index=0;
	memset(md,0,MD_DIGEST_LENGTH);
	md_count[0]=0;
	md_count[1]=0;
	entropy=0;
	}

static void ssleay_rand_add(const void *buf, int num, double add)
	{
	int i,j,k,st_idx;
	long md_c[2];
	unsigned char local_md[MD_DIGEST_LENGTH];
	MD_CTX m;

#ifdef NORAND
	return;
#endif

	/*
	 * (Based on the rand(3) manpage)
	 *
	 * The input is chopped up into units of 20 bytes (or less for
	 * the last block).  Each of these blocks is run through the hash
	 * function as follows:  The data passed to the hash function
	 * is the current 'md', the same number of bytes from the 'state'
	 * (the location determined by in incremented looping index) as
	 * the current 'block', the new key data 'block', and 'count'
	 * (which is incremented after each use).
	 * The result of this is kept in 'md' and also xored into the
	 * 'state' at the same locations that were used as input into the
         * hash function.
	 */

	CRYPTO_w_lock(CRYPTO_LOCK_RAND);
	st_idx=state_index;

	/* use our own copies of the counters so that even
	 * if a concurrent thread seeds with exactly the
	 * same data and uses the same subarray there's _some_
	 * difference */
	md_c[0] = md_count[0];
	md_c[1] = md_count[1];

	memcpy(local_md, md, sizeof md);

	/* state_index <= state_num <= STATE_SIZE */
	state_index += num;
	if (state_index >= STATE_SIZE)
		{
		state_index%=STATE_SIZE;
		state_num=STATE_SIZE;
		}
	else if (state_num < STATE_SIZE)	
		{
		if (state_index > state_num)
			state_num=state_index;
		}
	/* state_index <= state_num <= STATE_SIZE */

	/* state[st_idx], ..., state[(st_idx + num - 1) % STATE_SIZE]
	 * are what we will use now, but other threads may use them
	 * as well */

	md_count[1] += (num / MD_DIGEST_LENGTH) + (num % MD_DIGEST_LENGTH > 0);

	CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

	for (i=0; i<num; i+=MD_DIGEST_LENGTH)
		{
		j=(num-i);
		j=(j > MD_DIGEST_LENGTH)?MD_DIGEST_LENGTH:j;

		MD_Init(&m);
		MD_Update(&m,local_md,MD_DIGEST_LENGTH);
		k=(st_idx+j)-STATE_SIZE;
		if (k > 0)
			{
			MD_Update(&m,&(state[st_idx]),j-k);
			MD_Update(&m,&(state[0]),k);
			}
		else
			MD_Update(&m,&(state[st_idx]),j);
			
		MD_Update(&m,buf,j);
		MD_Update(&m,(unsigned char *)&(md_c[0]),sizeof(md_c));
		MD_Final(local_md,&m);
		md_c[1]++;

		buf=(const char *)buf + j;

		for (k=0; k<j; k++)
			{
			/* Parallel threads may interfere with this,
			 * but always each byte of the new state is
			 * the XOR of some previous value of its
			 * and local_md (itermediate values may be lost).
			 * Alway using locking could hurt performance more
			 * than necessary given that conflicts occur only
			 * when the total seeding is longer than the random
			 * state. */
			state[st_idx++]^=local_md[k];
			if (st_idx >= STATE_SIZE)
				st_idx=0;
			}
		}
	memset((char *)&m,0,sizeof(m));

	CRYPTO_w_lock(CRYPTO_LOCK_RAND);
	/* Don't just copy back local_md into md -- this could mean that
	 * other thread's seeding remains without effect (except for
	 * the incremented counter).  By XORing it we keep at least as
	 * much entropy as fits into md. */
	for (k = 0; k < sizeof md; k++)
		{
		md[k] ^= local_md[k];
		}
	if (entropy < ENTROPY_NEEDED) /* stop counting when we have enough */
	    entropy += add;
	CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
	
#ifndef THREADS	
	assert(md_c[1] == md_count[1]);
#endif
	}

static void ssleay_rand_seed(const void *buf, int num)
	{
	ssleay_rand_add(buf, num, num);
	}

static void ssleay_rand_initialize(void)
	{
	unsigned long l;
#ifndef GETPID_IS_MEANINGLESS
	pid_t curr_pid = getpid();
#endif
#ifdef DEVRANDOM
	FILE *fh;
#endif

	CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
	/* put in some default random data, we need more than just this */
#ifndef GETPID_IS_MEANINGLESS
	l=curr_pid;
	RAND_add(&l,sizeof(l),0);
	l=getuid();
	RAND_add(&l,sizeof(l),0);
#endif
	l=time(NULL);
	RAND_add(&l,sizeof(l),0);

#ifdef DEVRANDOM
	/* Use a random entropy pool device. Linux, FreeBSD and OpenBSD
	 * have this. Use /dev/urandom if you can as /dev/random may block
	 * if it runs out of random entries.  */

	if ((fh = fopen(DEVRANDOM, "r")) != NULL)
		{
		unsigned char tmpbuf[ENTROPY_NEEDED];
		int n;
		
		setvbuf(fh, NULL, _IONBF, 0);
		n=fread((unsigned char *)tmpbuf,1,ENTROPY_NEEDED,fh);
		fclose(fh);
		RAND_add(tmpbuf,sizeof tmpbuf,n);
		memset(tmpbuf,0,n);
		}
#endif
#ifdef PURIFY
	memset(state,0,STATE_SIZE);
	memset(md,0,MD_DIGEST_LENGTH);
#endif
	CRYPTO_w_lock(CRYPTO_LOCK_RAND);
	initialized=1;
	}

static int ssleay_rand_bytes(unsigned char *buf, int num)
	{
	int i,j,k,st_num,st_idx;
	int ok;
	long md_c[2];
	unsigned char local_md[MD_DIGEST_LENGTH];
	MD_CTX m;
#ifndef GETPID_IS_MEANINGLESS
	pid_t curr_pid = getpid();
#endif

#ifdef PREDICT
	{
	static unsigned char val=0;

	for (i=0; i<num; i++)
		buf[i]=val++;
	return(1);
	}
#endif

	/*
	 * (Based on the rand(3) manpage:)
	 *
	 * For each group of 10 bytes (or less), we do the following:
	 *
	 * Input into the hash function the top 10 bytes from the
	 * local 'md' (which is initialized from the global 'md'
	 * before any bytes are generated), the bytes that are
	 * to be overwritten by the random bytes, and bytes from the
	 * 'state' (incrementing looping index).  From this digest output
	 * (which is kept in 'md'), the top (up to) 10 bytes are
	 * returned to the caller and the bottom (up to) 10 bytes are xored
	 * into the 'state'.
	 * Finally, after we have finished 'num' random bytes for the
	 * caller, 'count' (which is incremented) and the local and global 'md'
	 * are fed into the hash function and the results are kept in the
	 * global 'md'.
	 */

	CRYPTO_w_lock(CRYPTO_LOCK_RAND);

	if (!initialized)
		ssleay_rand_initialize();

	ok = (entropy >= ENTROPY_NEEDED);
	if (!ok)
		{
		/* If the PRNG state is not yet unpredictable, then seeing
		 * the PRNG output may help attackers to determine the new
		 * state; thus we have to decrease the entropy estimate.
		 * Once we've had enough initial seeding we don't bother to
		 * adjust the entropy count, though, because we're not ambitious
		 * to provide *information-theoretic* randomness.
		 */
		entropy -= num;
		if (entropy < 0)
			entropy = 0;
		}

	st_idx=state_index;
	st_num=state_num;
	md_c[0] = md_count[0];
	md_c[1] = md_count[1];
	memcpy(local_md, md, sizeof md);

	state_index+=num;
	if (state_index > state_num)
		state_index %= state_num;

	/* state[st_idx], ..., state[(st_idx + num - 1) % st_num]
	 * are now ours (but other threads may use them too) */

	md_count[0] += 1;
	CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

	while (num > 0)
		{
		j=(num >= MD_DIGEST_LENGTH/2)?MD_DIGEST_LENGTH/2:num;
		num-=j;
		MD_Init(&m);
#ifndef GETPID_IS_MEANINGLESS
		if (curr_pid) /* just in the first iteration to save time */
			{
			MD_Update(&m,(unsigned char*)&curr_pid,sizeof curr_pid);
			curr_pid = 0;
			}
#endif
		MD_Update(&m,&(local_md[MD_DIGEST_LENGTH/2]),MD_DIGEST_LENGTH/2);
		MD_Update(&m,(unsigned char *)&(md_c[0]),sizeof(md_c));
#ifndef PURIFY
		MD_Update(&m,buf,j); /* purify complains */
#endif
		k=(st_idx+j)-st_num;
		if (k > 0)
			{
			MD_Update(&m,&(state[st_idx]),j-k);
			MD_Update(&m,&(state[0]),k);
			}
		else
			MD_Update(&m,&(state[st_idx]),j);
		MD_Final(local_md,&m);

		for (i=0; i<j; i++)
			{
			state[st_idx++]^=local_md[i]; /* may compete with other threads */
			*(buf++)=local_md[i+MD_DIGEST_LENGTH/2];
			if (st_idx >= st_num)
				st_idx=0;
			}
		}

	MD_Init(&m);
	MD_Update(&m,(unsigned char *)&(md_c[0]),sizeof(md_c));
	MD_Update(&m,local_md,MD_DIGEST_LENGTH);
	CRYPTO_w_lock(CRYPTO_LOCK_RAND);
	MD_Update(&m,md,MD_DIGEST_LENGTH);
	MD_Final(md,&m);
	CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

	memset(&m,0,sizeof(m));
	if (ok)
		return(1);
	else
		{
		RANDerr(RAND_F_SSLEAY_RAND_BYTES,RAND_R_PRNG_NOT_SEEDED);
		return(0);
		}
	}

/* pseudo-random bytes that are guaranteed to be unique but not
   unpredictable */
static int ssleay_rand_pseudo_bytes(unsigned char *buf, int num) 
	{
	int ret, err;

	ret = RAND_bytes(buf, num);
	if (ret == 0)
		{
		err = ERR_peek_error();
		if (ERR_GET_LIB(err) == ERR_LIB_RAND &&
		    ERR_GET_REASON(err) == RAND_R_PRNG_NOT_SEEDED)
			(void)ERR_get_error();
		}
	return (ret);
	}

int RAND_status(void)
	{
	if (!initialized)
		ssleay_rand_initialize();
	return (entropy >= ENTROPY_NEEDED);
	}

#ifdef WINDOWS
#include <windows.h>
#include <openssl/rand.h>

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

  bmbits = Malloc(size);
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

    Free(bmbits);
  }

  /* Select old bitmap back into memory DC */
  hBitmap = SelectObject(hMemDC, hOldBitmap);

  /* Clean up */
  DeleteObject(hBitmap);
  DeleteDC(hMemDC);
  DeleteDC(hScrDC);
}
#endif
