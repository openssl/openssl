/* x509_trs.c */
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/x509v3.h>


static int tr_cmp(X509_TRUST **a, X509_TRUST **b);
static void trtable_free(X509_TRUST *p);

static int trust_1bit(X509_TRUST *trust, X509 *x, int flags);
static int trust_any(X509_TRUST *trust, X509 *x, int flags);

static X509_TRUST trstandard[] = {
{X509_TRUST_ANY, 0, trust_any, "Any", 0, NULL},
{X509_TRUST_SSL_CLIENT, 0, trust_1bit, "SSL Client", X509_TRUST_BIT_SSL_CLIENT, NULL},
{X509_TRUST_SSL_SERVER, 0, trust_1bit, "SSL Client", X509_TRUST_BIT_SSL_SERVER, NULL},
{X509_TRUST_EMAIL, 0, trust_1bit, "S/MIME email", X509_TRUST_BIT_EMAIL, NULL},
{X509_TRUST_OBJECT_SIGN, 0, trust_1bit, "Object Signing", X509_TRUST_BIT_OBJECT_SIGN, NULL},
{0, 0, NULL, NULL, 0, NULL}
};

IMPLEMENT_STACK_OF(X509_TRUST)

static STACK_OF(X509_TRUST) *trtable = NULL;

static int tr_cmp(X509_TRUST **a, X509_TRUST **b)
{
	return (*a)->trust_id - (*b)->trust_id;
}

int X509_check_trust(X509 *x, int id, int flags)
{
	int idx;
	X509_TRUST *pt;
	if(id == -1) return 1;
	idx = X509_TRUST_get_by_id(id);
	if(idx == -1) return -1;
	pt = sk_X509_TRUST_value(trtable, idx);
	return pt->check_trust(pt, x, flags);
}

int X509_TRUST_get_count(void)
{
	return sk_X509_TRUST_num(trtable);
}

X509_TRUST * X509_TRUST_iget(int idx)
{
	return sk_X509_TRUST_value(trtable, idx);
}

int X509_TRUST_get_by_id(int id)
{
	X509_TRUST tmp;
	tmp.trust_id = id;
	if(!trtable) return -1;
	return sk_X509_TRUST_find(trtable, &tmp);
}

int X509_TRUST_add(X509_TRUST *xp)
{
	int idx;
	if(!trtable)
		{
		trtable = sk_X509_TRUST_new(tr_cmp);
		if (!trtable) 
			{
			X509err(X509_F_X509_TRUST_ADD,ERR_R_MALLOC_FAILURE);
			return 0;
			}
		}
			
	idx = X509_TRUST_get_by_id(xp->trust_id);
	if(idx != -1) {
		trtable_free(sk_X509_TRUST_value(trtable, idx));
		sk_X509_TRUST_set(trtable, idx, xp);
	} else {
		if (!sk_X509_TRUST_push(trtable, xp)) {
			X509err(X509_F_X509_TRUST_ADD,ERR_R_MALLOC_FAILURE);
			return 0;
		}
	}
	return 1;
}

static void trtable_free(X509_TRUST *p)
	{
	if(!p) return;
	if (p->trust_flags & X509_TRUST_DYNAMIC) 
		{
		if (p->trust_flags & X509_TRUST_DYNAMIC_NAME)
			Free(p->trust_name);
		Free(p);
		}
	}

void X509_TRUST_cleanup(void)
{
	sk_X509_TRUST_pop_free(trtable, trtable_free);
	trtable = NULL;
}

void X509_TRUST_add_standard(void)
{
	X509_TRUST *xp;
	for(xp = trstandard; xp->trust_name; xp++)
		X509_TRUST_add(xp);
}

int X509_TRUST_get_id(X509_TRUST *xp)
{
	return xp->trust_id;
}

char *X509_TRUST_iget_name(X509_TRUST *xp)
{
	return xp->trust_name;
}

int X509_TRUST_get_trust(X509_TRUST *xp)
{
	return xp->trust_id;
}

static int trust_1bit(X509_TRUST *trust, X509 *x, int flags)
{
	X509_CERT_AUX *ax;
	ax = x->aux;
	if(ax) {
		if(ax->reject
			&& ( ASN1_BIT_STRING_get_bit(ax->reject, X509_TRUST_BIT_ALL)
			|| ASN1_BIT_STRING_get_bit(ax->reject, trust->arg1)))
							return X509_TRUST_REJECTED;
		if(ax->trust && (ASN1_BIT_STRING_get_bit(ax->trust, X509_TRUST_BIT_ALL)
			|| ASN1_BIT_STRING_get_bit(ax->trust, trust->arg1)))
							return X509_TRUST_TRUSTED;
		return X509_TRUST_UNTRUSTED;
	}
	/* we don't have any trust settings: for compatability
	 * we return trusted if it is self signed
	 */
	X509_check_purpose(x, -1, 0);
	if(x->ex_flags & EXFLAG_SS) return X509_TRUST_TRUSTED;
	else return X509_TRUST_UNTRUSTED;
}

static int trust_any(X509_TRUST *trust, X509 *x, int flags)
{
	return X509_TRUST_TRUSTED;
}
