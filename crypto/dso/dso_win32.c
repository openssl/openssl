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

#ifndef WIN32
DSO_METHOD *DSO_METHOD_win32(void)
	{
	return NULL;
	}
#else

/* Part of the hack in "win32_load" ... */
#define DSO_MAX_TRANSLATED_SIZE 256

static int win32_load(DSO *dso, const char *filename);
static int win32_unload(DSO *dso);
static void *win32_bind_var(DSO *dso, const char *symname);
static DSO_FUNC_TYPE win32_bind_func(DSO *dso, const char *symname);
#if 0
static int win32_unbind_var(DSO *dso, char *symname, void *symptr);
static int win32_unbind_func(DSO *dso, char *symname, DSO_FUNC_TYPE symptr);
static int win32_init(DSO *dso);
static int win32_finish(DSO *dso);
#endif
static long win32_ctrl(DSO *dso, int cmd, long larg, void *parg);

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
	win32_ctrl,
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

static int win32_load(DSO *dso, const char *filename)
	{
	HINSTANCE h, *p;
	char translated[DSO_MAX_TRANSLATED_SIZE];
	int len;

	/* NB: This is a hideous hack, but I'm not yet sure what
	 * to replace it with. This attempts to convert any filename,
	 * that looks like it has no path information, into a
	 * translated form, e. "blah" -> "blah.dll" ... I'm more
	 * comfortable putting hacks into win32 code though ;-) */
	len = strlen(filename);
	if((dso->flags & DSO_FLAG_NAME_TRANSLATION) &&
			(len + 4 < DSO_MAX_TRANSLATED_SIZE) &&
			(strstr(filename, "/") == NULL) &&
			(strstr(filename, "\\") == NULL) &&
			(strstr(filename, ":") == NULL))
		{
		sprintf(translated, "%s.dll", filename);
		h = LoadLibrary(translated);
		}
	else
		h = LoadLibrary(filename);
	if(h == NULL)
		{
		DSOerr(DSO_F_WIN32_LOAD,DSO_R_LOAD_FAILED);
		return(0);
		}
	p = (HINSTANCE *)OPENSSL_malloc(sizeof(HINSTANCE));
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
		OPENSSL_free(p);
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
		return(NULL);
		}
	return((DSO_FUNC_TYPE)sym);
	}

static long win32_ctrl(DSO *dso, int cmd, long larg, void *parg)
        {
        if(dso == NULL)
                {
                DSOerr(DSO_F_WIN32_CTRL,ERR_R_PASSED_NULL_PARAMETER);
                return(-1);
                }
        switch(cmd)
                {
        case DSO_CTRL_GET_FLAGS:
                return dso->flags;
        case DSO_CTRL_SET_FLAGS:
                dso->flags = (int)larg;
                return(0);
        case DSO_CTRL_OR_FLAGS:
                dso->flags |= (int)larg;
                return(0);
        default:
                break;
                }
        DSOerr(DSO_F_WIN32_CTRL,DSO_R_UNKNOWN_COMMAND);
        return(-1);
        }

#endif /* WIN32 */
