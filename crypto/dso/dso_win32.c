/* dso_win32.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/dso.h>

#ifndef WIN32
DSO_METHOD *DSO_METHOD_win32(void)
	{
	return NULL;
	}
#else

static int win32_load(DSO *dso, const char *filename);
static int win32_unload(DSO *dso);
static int win32_bind(DSO *dso, const char *symname, void **symptr);
#if 0
static int win32_unbind(DSO *dso, char *symname, void *symptr);
static int win32_init(DSO *dso);
static int win32_finish(DSO *dso);
#endif

static DSO_METHOD dso_meth_win32 = {
	"OpenSSL 'win32' shared library method",
	win32_load,
	win32_unload,
	win32_bind,
/* For now, "unbind" doesn't exist */
#if 0
	NULL, /* unbind */
#endif
	NULL, /* init */
	NULL  /* finish */
	};

DSO_METHOD *DSO_METHOD_win32(void)
	{
	return(&dso_meth_win32);
	}

/* For this DSO_METHOD, our meth_data STACK will contain;
 * (i) a pointer to the handle (HINSTANCE) returned from
 *      LoadLibrary(), and copied.
 */

static int win32_load(DSO *dso, const char *filename)
	{
	HINSTANCE h, *p;

	h = LoadLibrary(filename);
	if(h == NULL)
		{
		DSOerr(DSO_F_WIN32_LOAD,DSO_R_LOAD_FAILED);
		return(0);
		}
	p = (HINSTANCE *)Malloc(sizeof(HINSTANCE));
	if(p == NULL)
		{
		DSOerr(DSO_F_WIN32_LOAD,ERR_R_MALLOC_FAILURE);
		FreeLibrary(h);
		return(0);
		}
	*p = h;
	if(!sk_push(dso->meth_data, (char *)p))
		{
		DSOerr(DSO_F_WIN32_LOAD,DSO_R_STACK_ERROR);
		FreeLibrary(h);
		Free(p);
		return(0);
		}
	return(1);
	}

static int win32_unload(DSO *dso)
	{
	HINSTANCE *p;
	if(dso == NULL)
		{
		DSOerr(DSO_F_WIN32_UNLOAD,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if(sk_num(dso->meth_data) < 1)
		{
		DSOerr(DSO_F_WIN32_UNLOAD,DSO_R_STACK_ERROR);
		return(0);
		}
	p = (HINSTANCE *)sk_pop(dso->meth_data);
	if(p == NULL)
		{
		DSOerr(DSO_F_WIN32_UNLOAD,DSO_R_NULL_HANDLE);
		return(0);
		}
	if(!FreeLibrary(p))
		{
		DSOerr(DSO_F_WIN32_UNLOAD,DSO_R_UNLOAD_FAILED);
		/* We should push the value back onto the stack in
		 * case of a retry. */
		sk_push(dso->meth_data, (char *)p);
		return(0);
		}
	/* Cleanup */
	Free(p);
	return(1);
	}

static int win32_bind(DSO *dso, const char *symname, void **symptr)
	{
	HINSTANCE *ptr;
	void *sym;

	if((dso == NULL) || (symptr == NULL) || (symname == NULL))
		{
		DSOerr(DSO_F_WIN32_BIND,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if(sk_num(dso->meth_data) < 1)
		{
		DSOerr(DSO_F_WIN32_BIND,DSO_R_STACK_ERROR);
		return(0);
		}
	ptr = (HINSTANCE *)sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_WIN32_BIND,DSO_R_NULL_HANDLE);
		return(0);
		}
	sym = GetProcAddress(*ptr, symname);
	if(sym == NULL)
		{
		DSOerr(DSO_F_WIN32_BIND,DSO_R_SYM_FAILURE);
		return(0);
		}
	*symptr = sym;
	return(1);
	}

#endif /* WIN32 */
