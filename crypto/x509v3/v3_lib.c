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

#include "ext_dat.h"

static STACK_OF(X509V3_EXT_METHOD) *ext_list = NULL;

static int ext_cmp(const X509V3_EXT_METHOD * const *a,
		const X509V3_EXT_METHOD * const *b);
static void ext_list_free(X509V3_EXT_METHOD *ext);

int X509V3_EXT_add(X509V3_EXT_METHOD *ext)
{
	if(!ext_list && !(ext_list = sk_X509V3_EXT_METHOD_new(ext_cmp))) {
		X509V3err(X509V3_F_X509V3_EXT_ADD,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if(!sk_X509V3_EXT_METHOD_push(ext_list, ext)) {
		X509V3err(X509V3_F_X509V3_EXT_ADD,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	return 1;
}

static int ext_cmp(const X509V3_EXT_METHOD * const *a,
		const X509V3_EXT_METHOD * const *b)
{
	return ((*a)->ext_nid - (*b)->ext_nid);
}

X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid)
{
	X509V3_EXT_METHOD tmp, *t = &tmp, **ret;
	int idx;
	if(nid < 0) return NULL;
	tmp.ext_nid = nid;
	ret = (X509V3_EXT_METHOD **) OBJ_bsearch((char *)&t,
			(char *)standard_exts, STANDARD_EXTENSION_COUNT,
			sizeof(X509V3_EXT_METHOD *), (int (*)(const void *, const void *))ext_cmp);
	if(ret) return *ret;
	if(!ext_list) return NULL;
	idx = sk_X509V3_EXT_METHOD_find(ext_list, &tmp);
	if(idx == -1) return NULL;
	return sk_X509V3_EXT_METHOD_value(ext_list, idx);
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
	if(!(tmpext = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD)))) {
		X509V3err(X509V3_F_X509V3_EXT_ADD_ALIAS,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	*tmpext = *ext;
	tmpext->ext_nid = nid_to;
	tmpext->ext_flags |= X509V3_EXT_DYNAMIC;
	return X509V3_EXT_add(tmpext);
}

void X509V3_EXT_cleanup(void)
{
	sk_X509V3_EXT_METHOD_pop_free(ext_list, ext_list_free);
	ext_list = NULL;
}

static void ext_list_free(X509V3_EXT_METHOD *ext)
{
	if(ext->ext_flags & X509V3_EXT_DYNAMIC) OPENSSL_free(ext);
}

/* Legacy function: we don't need to add standard extensions
 * any more because they are now kept in ext_dat.h.
 */

int X509V3_add_standard_extensions(void)
{
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

/* Get critical flag and decoded version of extension from a NID.
 * The "idx" variable returns the last found extension and can
 * be used to retrieve multiple extensions of the same NID.
 * However multiple extensions with the same NID is usually
 * due to a badly encoded certificate so if idx is NULL we
 * choke if multiple extensions exist.
 * The "crit" variable is set to the critical value.
 * The return value is the decoded extension or NULL on
 * error. The actual error can have several different causes,
 * the value of *crit reflects the cause:
 * >= 0, extension found but not decoded (reflects critical value).
 * -1 extension not found.
 * -2 extension occurs more than once.
 */

void *X509V3_get_d2i(STACK_OF(X509_EXTENSION) *x, int nid, int *crit, int *idx)
{
	int lastpos, i;
	X509_EXTENSION *ex, *found_ex = NULL;
	if(!x) {
		if(idx) *idx = -1;
		if(crit) *crit = -1;
		return NULL;
	}
	if(idx) lastpos = *idx + 1;
	else lastpos = 0;
	if(lastpos < 0) lastpos = 0;
	for(i = lastpos; i < sk_X509_EXTENSION_num(x); i++)
	{
		ex = sk_X509_EXTENSION_value(x, i);
		if(OBJ_obj2nid(ex->object) == nid) {
			if(idx) {
				*idx = i;
				break;
			} else if(found_ex) {
				/* Found more than one */
				if(crit) *crit = -2;
				return NULL;
			}
			found_ex = ex;
		}
	}
	if(found_ex) {
		/* Found it */
		if(crit) *crit = found_ex->critical;
		return X509V3_EXT_d2i(found_ex);
	}

	/* Extension not found */
	if(idx) *idx = -1;
	if(crit) *crit = -1;
	return NULL;
}

IMPLEMENT_STACK_OF(X509V3_EXT_METHOD)
