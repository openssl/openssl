/* v3_lib.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
/* X509 v3 extension utilities */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/x509v3.h>

static STACK *ext_list = NULL;

static int ext_cmp(X509V3_EXT_METHOD **a, X509V3_EXT_METHOD **b);
static void ext_list_free(X509V3_EXT_METHOD *ext);

int X509V3_EXT_add(X509V3_EXT_METHOD *ext)
{
	if(!ext_list && !(ext_list = sk_new(ext_cmp))) {
		X509V3err(X509V3_F_X509V3_EXT_ADD,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if(!sk_push(ext_list, (char *)ext)) {
		X509V3err(X509V3_F_X509V3_EXT_ADD,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	return 1;
}

static int ext_cmp(X509V3_EXT_METHOD **a, X509V3_EXT_METHOD **b)
{
	return ((*a)->ext_nid - (*b)->ext_nid);
}

X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid)
{
	X509V3_EXT_METHOD tmp;
	int idx;
	tmp.ext_nid = nid;
	if(!ext_list || (tmp.ext_nid < 0) ) return NULL;
	idx = sk_find(ext_list, (char *)&tmp);
	if(idx == -1) return NULL;
	return (X509V3_EXT_METHOD *)sk_value(ext_list, idx);
}

X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext)
{
	int nid;
	if((nid = OBJ_obj2nid(ext->object)) == NID_undef) return NULL;
	return X509V3_EXT_get_nid(nid);
}


int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist)
{
	for(;extlist->ext_nid!=-1;extlist++) 
			if(!X509V3_EXT_add(extlist)) return 0;
	return 1;
}

int X509V3_EXT_add_alias(int nid_to, int nid_from)
{
	X509V3_EXT_METHOD *ext, *tmpext;
	if(!(ext = X509V3_EXT_get_nid(nid_from))) {
		X509V3err(X509V3_F_X509V3_EXT_ADD_ALIAS,X509V3_R_EXTENSION_NOT_FOUND);
		return 0;
	}
	if(!(tmpext = (X509V3_EXT_METHOD *)Malloc(sizeof(X509V3_EXT_METHOD)))) {
		X509V3err(X509V3_F_X509V3_EXT_ADD_ALIAS,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	*tmpext = *ext;
	tmpext->ext_nid = nid_to;
	tmpext->ext_flags |= X509V3_EXT_DYNAMIC;
	return 1;
}

void X509V3_EXT_cleanup(void)
{
	sk_pop_free(ext_list, ext_list_free);
	ext_list = NULL;
}

static void ext_list_free(X509V3_EXT_METHOD *ext)
{
	if(ext->ext_flags & X509V3_EXT_DYNAMIC) Free(ext);
}

extern X509V3_EXT_METHOD v3_bcons, v3_nscert, v3_key_usage, v3_ext_ku;
extern X509V3_EXT_METHOD v3_pkey_usage_period, v3_sxnet;
extern X509V3_EXT_METHOD v3_ns_ia5_list[], v3_alt[], v3_skey_id, v3_akey_id;

extern X509V3_EXT_METHOD v3_crl_num, v3_crl_reason, v3_cpols, v3_crld;

int X509V3_add_standard_extensions(void)
{
	X509V3_EXT_add_list(v3_ns_ia5_list);
	X509V3_EXT_add_list(v3_alt);
	X509V3_EXT_add(&v3_bcons);
	X509V3_EXT_add(&v3_nscert);
	X509V3_EXT_add(&v3_key_usage);
	X509V3_EXT_add(&v3_ext_ku);
	X509V3_EXT_add(&v3_skey_id);
	X509V3_EXT_add(&v3_akey_id);
	X509V3_EXT_add(&v3_pkey_usage_period);
	X509V3_EXT_add(&v3_crl_num);
	X509V3_EXT_add(&v3_sxnet);
	X509V3_EXT_add(&v3_crl_reason);
	X509V3_EXT_add(&v3_cpols);
	X509V3_EXT_add(&v3_crld);
	return 1;
}

/* Return an extension internal structure */

void *X509V3_EXT_d2i(X509_EXTENSION *ext)
{
	X509V3_EXT_METHOD *method;
	unsigned char *p;
	if(!(method = X509V3_EXT_get(ext)) || !method->d2i) return NULL;
	p = ext->value->data;
	return method->d2i(NULL, &p, ext->value->length);
}

