/* crypto/cryptlib.c */
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by 
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include "cryptlib.h"

#ifndef OPENSSL_NO_DEPRECATED
static unsigned long (MS_FAR *id_callback)(void)=0;
#endif
static void (MS_FAR *threadid_callback)(CRYPTO_THREADID *)=0;

/* the memset() here and in set_pointer() seem overkill, but for the sake of
 * CRYPTO_THREADID_cmp() this avoids any platform silliness that might cause two
 * "equal" THREADID structs to not be memcmp()-identical. */
void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val)
	{
	memset(id, 0, sizeof(*id));
	id->val = val;
	}

static const unsigned char hash_coeffs[] = { 3, 5, 7, 11, 13, 17, 19, 23 };
void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr)
	{
	unsigned char *dest = (void *)&id->val;
	unsigned int accum = 0;
	unsigned char dnum = sizeof(id->val);

	memset(id, 0, sizeof(*id));
	id->ptr = ptr;
	if (sizeof(id->val) >= sizeof(id->ptr))
		{
		/* 'ptr' can be embedded in 'val' without loss of uniqueness */
		id->val = (unsigned long)id->ptr;
		return;
		}
	/* hash ptr ==> val. Each byte of 'val' gets the mod-256 total of a
	 * linear function over the bytes in 'ptr', the co-efficients of which
	 * are a sequence of low-primes (hash_coeffs is an 8-element cycle) -
	 * the starting prime for the sequence varies for each byte of 'val'
	 * (unique polynomials unless pointers are >64-bit). For added spice,
	 * the totals accumulate rather than restarting from zero, and the index
	 * of the 'val' byte is added each time (position dependence). If I was
	 * a black-belt, I'd scan big-endian pointers in reverse to give
	 * low-order bits more play, but this isn't crypto and I'd prefer nobody
	 * mistake it as such. Plus I'm lazy. */
	while (dnum--)
		{
		const unsigned char *src = (void *)&id->ptr;
		unsigned char snum = sizeof(id->ptr);
		while (snum--)
			accum += *(src++) * hash_coeffs[(snum + dnum) & 7];
		accum += dnum;
		*(dest++) = accum & 255;
		}
	}

int CRYPTO_THREADID_set_callback(void (*func)(CRYPTO_THREADID *))
	{
	if (threadid_callback)
		return 0;
	threadid_callback = func;
	return 1;
	}

void (*CRYPTO_THREADID_get_callback(void))(CRYPTO_THREADID *)
	{
	return threadid_callback;
	}

void CRYPTO_THREADID_current(CRYPTO_THREADID *id)
	{
	if (threadid_callback)
		{
		threadid_callback(id);
		return;
		}
#ifndef OPENSSL_NO_DEPRECATED
	/* If the deprecated callback was set, fall back to that */
	if (id_callback)
		{
		CRYPTO_THREADID_set_numeric(id, id_callback());
		return;
		}
#endif
	/* Else pick a backup */
#ifdef OPENSSL_SYS_WIN16
	CRYPTO_THREADID_set_numeric(id, (unsigned long)GetCurrentTask());
#elif defined(OPENSSL_SYS_WIN32)
	CRYPTO_THREADID_set_numeric(id, (unsigned long)GetCurrentThreadId());
#else
	/* For everything else, default to using the address of 'errno' */
	CRYPTO_THREADID_set_pointer(id, (void*)&errno);
#endif
	}

int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b)
	{
	return memcmp(a, b, sizeof(*a));
	}

void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src)
	{
	memcpy(dest, src, sizeof(*src));
	}

unsigned long CRYPTO_THREADID_hash(const CRYPTO_THREADID *id)
	{
	return id->val;
	}

#ifndef OPENSSL_NO_DEPRECATED
unsigned long (*CRYPTO_get_id_callback(void))(void)
	{
	return(id_callback);
	}

void CRYPTO_set_id_callback(unsigned long (*func)(void))
	{
	id_callback=func;
	}

unsigned long CRYPTO_thread_id(void)
	{
	unsigned long ret=0;

	if (id_callback == NULL)
		{
#ifdef OPENSSL_SYS_WIN16
		ret=(unsigned long)GetCurrentTask();
#elif defined(OPENSSL_SYS_WIN32)
		ret=(unsigned long)GetCurrentThreadId();
#elif defined(GETPID_IS_MEANINGLESS)
		ret=1L;
#else
		ret=(unsigned long)getpid();
#endif
		}
	else
		ret=id_callback();
	return(ret);
	}
#endif
