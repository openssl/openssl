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
#include <string.h>
#include "cryptlib.h"
#include <openssl/dso.h>

#if !defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINCE)
DSO_METHOD *DSO_METHOD_win32(void)
	{
	return NULL;
	}
#else

/* Part of the hack in "win32_load" ... */
#define DSO_MAX_TRANSLATED_SIZE 256

static int win32_load(DSO *dso);
static int win32_unload(DSO *dso);
static void *win32_bind_var(DSO *dso, const char *symname);
static DSO_FUNC_TYPE win32_bind_func(DSO *dso, const char *symname);
#if 0
static int win32_unbind_var(DSO *dso, char *symname, void *symptr);
static int win32_unbind_func(DSO *dso, char *symname, DSO_FUNC_TYPE symptr);
static int win32_init(DSO *dso);
static int win32_finish(DSO *dso);
static long win32_ctrl(DSO *dso, int cmd, long larg, void *parg);
#endif
static char *win32_name_converter(DSO *dso, const char *filename);

static DSO_METHOD dso_meth_win32 = {
	"OpenSSL 'win32' shared library method",
	win32_load,
	win32_unload,
	win32_bind_var,
	win32_bind_func,
/* For now, "unbind" doesn't exist */
#if 0
	NULL, /* unbind_var */
	NULL, /* unbind_func */
#endif
	NULL, /* ctrl */
	win32_name_converter,
	NULL, /* init */
	NULL  /* finish */
	};

DSO_METHOD *DSO_METHOD_win32(void)
	{
	return(&dso_meth_win32);
	}

/* For this DSO_METHOD, our meth_data STACK will contain;
 * (i) a pointer to the handle (HINSTANCE) returned from
 *     LoadLibrary(), and copied.
 */

static int win32_load(DSO *dso)
	{
	HINSTANCE h = NULL, *p = NULL;
	/* See applicable comments from dso_dl.c */
	char *filename = DSO_convert_filename(dso, NULL);

	if(filename == NULL)
		{
		DSOerr(DSO_F_WIN32_LOAD,DSO_R_NO_FILENAME);
		goto err;
		}
	h = LoadLibrary(filename);
	if(h == NULL)
		{
		DSOerr(DSO_F_WIN32_LOAD,DSO_R_LOAD_FAILED);
		ERR_add_error_data(3, "filename(", filename, ")");
		goto err;
		}
	p = (HINSTANCE *)OPENSSL_malloc(sizeof(HINSTANCE));
	if(p == NULL)
		{
		DSOerr(DSO_F_WIN32_LOAD,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	*p = h;
	if(!sk_push(dso->meth_data, (char *)p))
		{
		DSOerr(DSO_F_WIN32_LOAD,DSO_R_STACK_ERROR);
		goto err;
		}
	/* Success */
	dso->loaded_filename = filename;
	return(1);
err:
	/* Cleanup !*/
	if(filename != NULL)
		OPENSSL_free(filename);
	if(p != NULL)
		OPENSSL_free(p);
	if(h != NULL)
		FreeLibrary(h);
	return(0);
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
		return(1);
	p = (HINSTANCE *)sk_pop(dso->meth_data);
	if(p == NULL)
		{
		DSOerr(DSO_F_WIN32_UNLOAD,DSO_R_NULL_HANDLE);
		return(0);
		}
	if(!FreeLibrary(*p))
		{
		DSOerr(DSO_F_WIN32_UNLOAD,DSO_R_UNLOAD_FAILED);
		/* We should push the value back onto the stack in
		 * case of a retry. */
		sk_push(dso->meth_data, (char *)p);
		return(0);
		}
	/* Cleanup */
	OPENSSL_free(p);
	return(1);
	}

/* Using GetProcAddress for variables? TODO: Check this out in
 * the Win32 API docs, there's probably a variant for variables. */
static void *win32_bind_var(DSO *dso, const char *symname)
	{
	HINSTANCE *ptr;
	void *sym;

	if((dso == NULL) || (symname == NULL))
		{
		DSOerr(DSO_F_WIN32_BIND_VAR,ERR_R_PASSED_NULL_PARAMETER);
		return(NULL);
		}
	if(sk_num(dso->meth_data) < 1)
		{
		DSOerr(DSO_F_WIN32_BIND_VAR,DSO_R_STACK_ERROR);
		return(NULL);
		}
	ptr = (HINSTANCE *)sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_WIN32_BIND_VAR,DSO_R_NULL_HANDLE);
		return(NULL);
		}
	sym = GetProcAddress(*ptr, symname);
	if(sym == NULL)
		{
		DSOerr(DSO_F_WIN32_BIND_VAR,DSO_R_SYM_FAILURE);
		ERR_add_error_data(3, "symname(", symname, ")");
		return(NULL);
		}
	return(sym);
	}

static DSO_FUNC_TYPE win32_bind_func(DSO *dso, const char *symname)
	{
	HINSTANCE *ptr;
	void *sym;

	if((dso == NULL) || (symname == NULL))
		{
		DSOerr(DSO_F_WIN32_BIND_FUNC,ERR_R_PASSED_NULL_PARAMETER);
		return(NULL);
		}
	if(sk_num(dso->meth_data) < 1)
		{
		DSOerr(DSO_F_WIN32_BIND_FUNC,DSO_R_STACK_ERROR);
		return(NULL);
		}
	ptr = (HINSTANCE *)sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_WIN32_BIND_FUNC,DSO_R_NULL_HANDLE);
		return(NULL);
		}
	sym = GetProcAddress(*ptr, symname);
	if(sym == NULL)
		{
		DSOerr(DSO_F_WIN32_BIND_FUNC,DSO_R_SYM_FAILURE);
		ERR_add_error_data(3, "symname(", symname, ")");
		return(NULL);
		}
	return((DSO_FUNC_TYPE)sym);
	}

static char *win32_name_converter(DSO *dso, const char *filename)
	{
	char *translated;
	int len, transform;

	len = strlen(filename);
	transform = ((strstr(filename, "/") == NULL) &&
			(strstr(filename, "\\") == NULL) &&
			(strstr(filename, ":") == NULL));
	if(transform)
		/* We will convert this to "%s.dll" */
		translated = OPENSSL_malloc(len + 5);
	else
		/* We will simply duplicate filename */
		translated = OPENSSL_malloc(len + 1);
	if(translated == NULL)
		{
		DSOerr(DSO_F_WIN32_NAME_CONVERTER,
				DSO_R_NAME_TRANSLATION_FAILED); 
		return(NULL);   
		}
	if(transform)
		sprintf(translated, "%s.dll", filename);
	else
		sprintf(translated, "%s", filename);
	return(translated);
	}

#endif /* OPENSSL_SYS_WIN32 */
