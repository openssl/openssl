/* dso_dlfcn.c */
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

#ifndef DSO_DLFCN
DSO_METHOD *DSO_METHOD_dlfcn(void)
	{
	return NULL;
	}
#else

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

/* Part of the hack in "dlfcn_load" ... */
#define DSO_MAX_TRANSLATED_SIZE 256

static int dlfcn_load(DSO *dso, const char *filename);
static int dlfcn_unload(DSO *dso);
static void *dlfcn_bind_var(DSO *dso, const char *symname);
static DSO_FUNC_TYPE dlfcn_bind_func(DSO *dso, const char *symname);
#if 0
static int dlfcn_unbind(DSO *dso, char *symname, void *symptr);
static int dlfcn_init(DSO *dso);
static int dlfcn_finish(DSO *dso);
#endif
static long dlfcn_ctrl(DSO *dso, int cmd, long larg, void *parg);

static DSO_METHOD dso_meth_dlfcn = {
	"OpenSSL 'dlfcn' shared library method",
	dlfcn_load,
	dlfcn_unload,
	dlfcn_bind_var,
	dlfcn_bind_func,
/* For now, "unbind" doesn't exist */
#if 0
	NULL, /* unbind_var */
	NULL, /* unbind_func */
#endif
	dlfcn_ctrl,
	NULL, /* init */
	NULL  /* finish */
	};

DSO_METHOD *DSO_METHOD_dlfcn(void)
	{
	return(&dso_meth_dlfcn);
	}

/* Prior to using the dlopen() function, we should decide on the flag
 * we send. There's a few different ways of doing this and it's a
 * messy venn-diagram to match up which platforms support what. So
 * as we don't have autoconf yet, I'm implementing a hack that could
 * be hacked further relatively easily to deal with cases as we find
 * them. Initially this is to cope with OpenBSD. */
#ifdef __OpenBSD__
#	ifdef DL_LAZY
#		define DLOPEN_FLAG DL_LAZY
#	else
#		ifdef RTLD_NOW
#			define DLOPEN_FLAG RTLD_NOW
#		else
#			define DLOPEN_FLAG 0
#		endif
#	endif
#else
#	define DLOPEN_FLAG RTLD_NOW /* Hope this works everywhere else */
#endif

/* For this DSO_METHOD, our meth_data STACK will contain;
 * (i) the handle (void*) returned from dlopen().
 */

static int dlfcn_load(DSO *dso, const char *filename)
	{
	void *ptr;
	char translated[DSO_MAX_TRANSLATED_SIZE];
	int len;

	/* NB: This is a hideous hack, but I'm not yet sure what
	 * to replace it with. This attempts to convert any filename,
	 * that looks like it has no path information, into a
	 * translated form, e. "blah" -> "libblah.so" */
	len = strlen(filename);
	if((dso->flags & DSO_FLAG_NAME_TRANSLATION) &&
			(len + 6 < DSO_MAX_TRANSLATED_SIZE) &&
			(strstr(filename, "/") == NULL))
		{
		sprintf(translated, "lib%s.so", filename);
		ptr = dlopen(translated, DLOPEN_FLAG);
		}
	else
		{
		ptr = dlopen(filename, DLOPEN_FLAG);
		}
	if(ptr == NULL)
		{
		DSOerr(DSO_F_DLFCN_LOAD,DSO_R_LOAD_FAILED);
		return(0);
		}
	if(!sk_push(dso->meth_data, (char *)ptr))
		{
		DSOerr(DSO_F_DLFCN_LOAD,DSO_R_STACK_ERROR);
		dlclose(ptr);
		return(0);
		}
	return(1);
	}

static int dlfcn_unload(DSO *dso)
	{
	void *ptr;
	if(dso == NULL)
		{
		DSOerr(DSO_F_DLFCN_UNLOAD,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if(sk_num(dso->meth_data) < 1)
		return(1);
	ptr = (void *)sk_pop(dso->meth_data);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_DLFCN_UNLOAD,DSO_R_NULL_HANDLE);
		/* Should push the value back onto the stack in
		 * case of a retry. */
		sk_push(dso->meth_data, (char *)ptr);
		return(0);
		}
	/* For now I'm not aware of any errors associated with dlclose() */
	dlclose(ptr);
	return(1);
	}

static void *dlfcn_bind_var(DSO *dso, const char *symname)
	{
	void *ptr, *sym;

	if((dso == NULL) || (symname == NULL))
		{
		DSOerr(DSO_F_DLFCN_BIND_VAR,ERR_R_PASSED_NULL_PARAMETER);
		return(NULL);
		}
	if(sk_num(dso->meth_data) < 1)
		{
		DSOerr(DSO_F_DLFCN_BIND_VAR,DSO_R_STACK_ERROR);
		return(NULL);
		}
	ptr = (void *)sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_DLFCN_BIND_VAR,DSO_R_NULL_HANDLE);
		return(NULL);
		}
	sym = dlsym(ptr, symname);
	if(sym == NULL)
		{
		DSOerr(DSO_F_DLFCN_BIND_VAR,DSO_R_SYM_FAILURE);
		return(NULL);
		}
	return(sym);
	}

static DSO_FUNC_TYPE dlfcn_bind_func(DSO *dso, const char *symname)
	{
	void *ptr;
	DSO_FUNC_TYPE sym;

	if((dso == NULL) || (symname == NULL))
		{
		DSOerr(DSO_F_DLFCN_BIND_FUNC,ERR_R_PASSED_NULL_PARAMETER);
		return(NULL);
		}
	if(sk_num(dso->meth_data) < 1)
		{
		DSOerr(DSO_F_DLFCN_BIND_FUNC,DSO_R_STACK_ERROR);
		return(NULL);
		}
	ptr = (void *)sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_DLFCN_BIND_FUNC,DSO_R_NULL_HANDLE);
		return(NULL);
		}
	sym = (DSO_FUNC_TYPE)dlsym(ptr, symname);
	if(sym == NULL)
		{
		DSOerr(DSO_F_DLFCN_BIND_FUNC,DSO_R_SYM_FAILURE);
		return(NULL);
		}
	return(sym);
	}

static long dlfcn_ctrl(DSO *dso, int cmd, long larg, void *parg)
	{
	if(dso == NULL)
		{
		DSOerr(DSO_F_DLFCN_CTRL,ERR_R_PASSED_NULL_PARAMETER);
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
	DSOerr(DSO_F_DLFCN_CTRL,DSO_R_UNKNOWN_COMMAND);
	return(-1);
	}

#endif /* DSO_DLFCN */
