/* dso_dl.c */
/* Written by Richard Levitte (levitte@openssl.org) for the OpenSSL
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

#ifndef DSO_DL
DSO_METHOD *DSO_METHOD_dl(void)
       {
       return NULL;
       }
#else

#include <dl.h>

/* Part of the hack in "dl_load" ... */
#define DSO_MAX_TRANSLATED_SIZE 256

static int dl_load(DSO *dso, const char *filename);
static int dl_unload(DSO *dso);
static void *dl_bind_var(DSO *dso, const char *symname);
static DSO_FUNC_TYPE dl_bind_func(DSO *dso, const char *symname);
#if 0
static int dl_unbind_var(DSO *dso, char *symname, void *symptr);
static int dl_unbind_func(DSO *dso, char *symname, DSO_FUNC_TYPE symptr);
static int dl_init(DSO *dso);
static int dl_finish(DSO *dso);
#endif
static int dl_ctrl(DSO *dso, int cmd, long larg, void *parg);

static DSO_METHOD dso_meth_dl = {
	"OpenSSL 'dl' shared library method",
	dl_load,
	dl_unload,
	dl_bind_var,
	dl_bind_func,
/* For now, "unbind" doesn't exist */
#if 0
	NULL, /* unbind_var */
	NULL, /* unbind_func */
#endif
	dl_ctrl,
	NULL, /* init */
	NULL  /* finish */
	};

DSO_METHOD *DSO_METHOD_dl(void)
	{
	return(&dso_meth_dl);
	}

/* For this DSO_METHOD, our meth_data STACK will contain;
 * (i) the handle (shl_t) returned from shl_load().
 * NB: I checked on HPUX11 and shl_t is itself a pointer
 * type so the cast is safe.
 */

static int dl_load(DSO *dso, const char *filename)
	{
	shl_t ptr;
	char translated[DSO_MAX_TRANSLATED_SIZE];
	int len;

	/* The same comment as in dlfcn_load applies here. bleurgh. */
	len = strlen(filename);
	if((dso->flags & DSO_FLAG_NAME_TRANSLATION) &&
			(len + 6 < DSO_MAX_TRANSLATED_SIZE) &&
			(strstr(filename, "/") == NULL))
		{
		sprintf(translated, "lib%s.so", filename);
		ptr = shl_load(translated, BIND_IMMEDIATE, NULL);
		}
	else
		ptr = shl_load(filename, BIND_IMMEDIATE, NULL);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_DL_LOAD,DSO_R_LOAD_FAILED);
		return(0);
		}
	if(!sk_push(dso->meth_data, (char *)ptr))
		{
		DSOerr(DSO_F_DL_LOAD,DSO_R_STACK_ERROR);
		shl_unload(ptr);
		return(0);
		}
	return(1);
	}

static int dl_unload(DSO *dso)
	{
	shl_t ptr;
	if(dso == NULL)
		{
		DSOerr(DSO_F_DL_UNLOAD,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if(sk_num(dso->meth_data) < 1)
		return(1);
	/* Is this statement legal? */
	ptr = (shl_t)sk_pop(dso->meth_data);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_DL_UNLOAD,DSO_R_NULL_HANDLE);
		/* Should push the value back onto the stack in
		 * case of a retry. */
		sk_push(dso->meth_data, (char *)ptr);
		return(0);
		}
	shl_unload(ptr);
	return(1);
	}

static void *dl_bind_var(DSO *dso, const char *symname)
	{
	shl_t ptr;
	void *sym;

	if((dso == NULL) || (symname == NULL))
		{
		DSOerr(DSO_F_DL_BIND_VAR,ERR_R_PASSED_NULL_PARAMETER);
		return(NULL);
		}
	if(sk_num(dso->meth_data) < 1)
		{
		DSOerr(DSO_F_DL_BIND_VAR,DSO_R_STACK_ERROR);
		return(NULL);
		}
	ptr = (shl_t)sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_DL_BIND_VAR,DSO_R_NULL_HANDLE);
		return(NULL);
		}
	if (shl_findsym(ptr, symname, TYPE_UNDEFINED, &sym) < 0)
		{
		DSOerr(DSO_F_DL_BIND_VAR,DSO_R_SYM_FAILURE);
		return(NULL);
		}
	return(sym);
	}

static DSO_FUNC_TYPE dl_bind_func(DSO *dso, const char *symname)
	{
	shl_t ptr;
	void *sym;

	if((dso == NULL) || (symname == NULL))
		{
		DSOerr(DSO_F_DL_BIND_FUNC,ERR_R_PASSED_NULL_PARAMETER);
		return(NULL);
		}
	if(sk_num(dso->meth_data) < 1)
		{
		DSOerr(DSO_F_DL_BIND_FUNC,DSO_R_STACK_ERROR);
		return(NULL);
		}
	ptr = (shl_t)sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_DL_BIND_FUNC,DSO_R_NULL_HANDLE);
		return(NULL);
		}
	if (shl_findsym(ptr, symname, TYPE_UNDEFINED, &sym) < 0)
		{
		DSOerr(DSO_F_DL_BIND_FUNC,DSO_R_SYM_FAILURE);
		return(NULL);
		}
	return((DSO_FUNC_TYPE)sym);
	}

static int dl_ctrl(DSO *dso, int cmd, long larg, void *parg)
	{
	if(dso == NULL)
		{
		DSOerr(DSO_F_DL_CTRL,ERR_R_PASSED_NULL_PARAMETER);
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
	DSOerr(DSO_F_DL_CTRL,DSO_R_UNKNOWN_COMMAND);
	return(-1);
	}

#endif /* DSO_DL */
