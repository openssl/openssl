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

#include <dlfcn.h>

static int dlfcn_load(DSO *dso, char *filename);
static int dlfcn_unload(DSO *dso);
static int dlfcn_bind(DSO *dso, char *symname, void **symptr);
#if 0
static int dlfcn_unbind(DSO *dso, char *symname, void *symptr);
static int dlfcn_init(DSO *dso);
static int dlfcn_finish(DSO *dso);
#endif

static DSO_METHOD dso_meth_dlfcn = {
	"OpenSSL 'dlfcn' shared library method",
	dlfcn_load,
	dlfcn_unload,
	dlfcn_bind,
/* For now, "unbind" doesn't exist */
#if 0
	NULL, /* unbind */
#endif
	NULL, /* init */
	NULL  /* finish */
	};

DSO_METHOD *DSO_METHOD_dlfcn(void)
	{
	return(&dso_meth_dlfcn);
	}

/* For this DSO_METHOD, our meth_data STACK will contain;
 * (i) the handle (void*) returned from dlopen().
 */

static int dlfcn_load(DSO *dso, char *filename)
	{
	void *ptr;

	ptr = dlopen(filename, RTLD_NOW);
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
		{
		DSOerr(DSO_F_DLFCN_UNLOAD,DSO_R_STACK_ERROR);
		return(0);
		}
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

static int dlfcn_bind(DSO *dso, char *symname, void **symptr)
	{
	void *ptr, *sym;

	if((dso == NULL) || (symptr == NULL) || (symname == NULL))
		{
		DSOerr(DSO_F_DLFCN_BIND,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if(sk_num(dso->meth_data) < 1)
		{
		DSOerr(DSO_F_DLFCN_BIND,DSO_R_STACK_ERROR);
		return(0);
		}
	ptr = (void *)sk_value(dso->meth_data, sk_num(dso->meth_data) - 1);
	if(ptr == NULL)
		{
		DSOerr(DSO_F_DLFCN_BIND,DSO_R_NULL_HANDLE);
		return(0);
		}
	sym = dlsym(ptr, symname);
	if(sym == NULL)
		{
		DSOerr(DSO_F_DLFCN_BIND,DSO_R_SYM_FAILURE);
		return(0);
		}
	*symptr = sym;
	return(1);
	}

#endif /* DSO_DLFCN */
