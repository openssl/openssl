/* crypto/mem.c */
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

#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include "cryptlib.h"


static int allow_customize = 1;      /* we provide flexible functions for */
static int allow_customize_debug = 1;/* exchanging memory-related functions at
                                      * run-time, but this must be done
                                      * before any blocks are actually
                                      * allocated; or we'll run into huge
                                      * problems when malloc/free pairs
                                      * don't match etc. */

/* may be changed as long as `allow_customize' is set */
static void *(*malloc_locked_func)(size_t)  = malloc;
static void (*free_locked_func)(void *)     = free;
static void *(*malloc_func)(size_t)         = malloc;
static void *(*realloc_func)(void *, size_t)= realloc;
static void (*free_func)(void *)            = free;

/* may be changed as long as `allow_customize_debug' is set */
/* XXX use correct function pointer types */
#ifdef CRYPTO_MDEBUG
  /* use default functions from mem_dbg.c */
  static void (*malloc_debug_func)()= (void (*)())CRYPTO_dbg_malloc;
  static void (*realloc_debug_func)()= (void (*)())CRYPTO_dbg_realloc;
  static void (*free_debug_func)()= (void (*)())CRYPTO_dbg_free;
  static void (*set_debug_options_func)()= (void (*)())CRYPTO_dbg_set_options;
  static long (*get_debug_options_func)()= (long (*)())CRYPTO_dbg_get_options;
#else
  /* applications can use CRYPTO_malloc_debug_init() to select above case
   * at run-time */
  static void (*malloc_debug_func)()= NULL;
  static void (*realloc_debug_func)()= NULL;
  static void (*free_debug_func)()= NULL;
  static void (*set_debug_options_func)()= NULL;
  static long (*get_debug_options_func)()= NULL;
#endif


int CRYPTO_set_mem_functions(void *(*m)(size_t), void *(*r)(void *, size_t),
	void (*f)(void *))
	{
	if (!allow_customize)
		return 0;
	if ((m == NULL) || (r == NULL) || (f == NULL))
		return 0;
	malloc_func=m;
	realloc_func=r;
	free_func=f;
	malloc_locked_func=m;
	free_locked_func=f;
	return 1;
	}

int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*f)(void *))
	{
	if (!allow_customize)
		return 0;
	if ((m == NULL) || (f == NULL))
		return 0;
	malloc_locked_func=m;
	free_locked_func=f;
	return 1;
	}

int CRYPTO_set_mem_debug_functions(void (*m)(), void (*r)(), void (*f)(),void (*so)(),long (*go)())
	{
	if (!allow_customize_debug)
		return 0;
	malloc_debug_func=m;
	realloc_debug_func=r;
	free_debug_func=f;
	set_debug_options_func=so;
	get_debug_options_func=go;
	return 1;
	}

void CRYPTO_get_mem_functions(void *(**m)(size_t), void *(**r)(void *, size_t),
	void (**f)(void *))
	{
	if (m != NULL) *m=malloc_func;
	if (r != NULL) *r=realloc_func;
	if (f != NULL) *f=free_func;
	}

void CRYPTO_get_locked_mem_functions(void *(**m)(size_t), void (**f)(void *))
	{
	if (m != NULL) *m=malloc_locked_func;
	if (f != NULL) *f=free_locked_func;
	}

void CRYPTO_get_mem_debug_functions(void (**m)(), void (**r)(), void (**f)(),void (**so)(),long (**go)())
	{
	if (m != NULL) *m=malloc_debug_func;
	if (r != NULL) *r=realloc_debug_func;
	if (f != NULL) *f=free_debug_func;
	if (so != NULL) *so=set_debug_options_func;
	if (go != NULL) *go=get_debug_options_func;
	}


void *CRYPTO_malloc_locked(int num, const char *file, int line)
	{
	char *ret = NULL;

	allow_customize = 0;
	if (malloc_debug_func != NULL)
		{
		allow_customize_debug = 0;
		malloc_debug_func(NULL, num, file, line, 0);
		}
	ret = malloc_locked_func(num);
#ifdef LEVITTE_DEBUG
	fprintf(stderr, "LEVITTE_DEBUG:         > 0x%p (%d)\n", ret, num);
#endif
	if (malloc_debug_func != NULL)
		malloc_debug_func(ret, num, file, line, 1);

	return ret;
	}

void CRYPTO_free_locked(void *str)
	{
	if (free_debug_func != NULL)
		free_debug_func(str, 0);
#ifdef LEVITTE_DEBUG
	fprintf(stderr, "LEVITTE_DEBUG:         < 0x%p\n", str);
#endif
	free_locked_func(str);
	if (free_debug_func != NULL)
		free_debug_func(NULL, 1);
	}

void *CRYPTO_malloc(int num, const char *file, int line)
	{
	char *ret = NULL;

	allow_customize = 0;
	if (malloc_debug_func != NULL)
		{
		allow_customize_debug = 0;
		malloc_debug_func(NULL, num, file, line, 0);
		}
	ret = malloc_func(num);
#ifdef LEVITTE_DEBUG
	fprintf(stderr, "LEVITTE_DEBUG:         > 0x%p (%d)\n", ret, num);
#endif
	if (malloc_debug_func != NULL)
		malloc_debug_func(ret, num, file, line, 1);

	return ret;
	}

void *CRYPTO_realloc(void *str, int num, const char *file, int line)
	{
	char *ret = NULL;

	if (realloc_debug_func != NULL)
		realloc_debug_func(str, NULL, num, file, line, 0);
	ret = realloc_func(str,num);
#ifdef LEVITTE_DEBUG
	fprintf(stderr, "LEVITTE_DEBUG:         | 0x%p -> 0x%p (%d)\n", str, ret, num);
#endif
	if (realloc_debug_func != NULL)
		realloc_debug_func(str, ret, num, file, line, 1);

	return ret;
	}

void CRYPTO_free(void *str)
	{
	if (free_debug_func != NULL)
		free_debug_func(str, 0);
#ifdef LEVITTE_DEBUG
	fprintf(stderr, "LEVITTE_DEBUG:         < 0x%p\n", str);
#endif
	free_func(str);
	if (free_debug_func != NULL)
		free_debug_func(NULL, 1);
	}

void *CRYPTO_remalloc(void *a, int num, const char *file, int line)
	{
	if (a != NULL) Free(a);
	a=(char *)Malloc(num);
	return(a);
	}


void CRYPTO_set_mem_debug_options(long bits)
	{
	if (set_debug_options_func != NULL)
		set_debug_options_func(bits);
	}

long CRYPTO_get_mem_debug_options(void)
	{
	if (get_debug_options_func != NULL)
		return get_debug_options_func();
	return 0;
	}
