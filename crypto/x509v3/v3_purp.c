/* v3_purp.c */
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


static int x509_purpose_get_idx(int id);
void x509v3_cache_extensions(X509 *x);

static int ca_check(X509 *x);
static int check_purpose_ssl_client(X509_PURPOSE *xp, X509 *x, int ca);
static int check_purpose_ssl_server(X509_PURPOSE *xp, X509 *x, int ca);
static int check_purpose_ns_ssl_server(X509_PURPOSE *xp, X509 *x, int ca);
static int purpose_smime(X509 *x, int ca);
static int check_purpose_smime_sign(X509_PURPOSE *xp, X509 *x, int ca);
static int check_purpose_smime_encrypt(X509_PURPOSE *xp, X509 *x, int ca);
static int check_purpose_crl_sign(X509_PURPOSE *xp, X509 *x, int ca);

static int xp_cmp(X509_PURPOSE **a, X509_PURPOSE **b);

static X509_PURPOSE xstandard[] = {
{1, check_purpose_ssl_client, "SSL client", NULL},
{2, check_purpose_ssl_server, "SSL server", NULL},
{3, check_purpose_ns_ssl_server, "Netscape SSL server", NULL},
{4, check_purpose_smime_sign, "S/MIME signing", NULL},
{5, check_purpose_smime_encrypt, "S/MIME encryption", NULL},
{6, check_purpose_crl_sign, "CRL signing", NULL},
{-1, NULL, NULL, NULL}
};

IMPLEMENT_STACK_OF(X509_PURPOSE)

static STACK_OF(X509_PURPOSE) *xptable;

static int xp_cmp(X509_PURPOSE **a, X509_PURPOSE **b)
{
	return (*a)->purpose_id - (*b)->purpose_id;
}

int X509_check_purpose(X509 *x, int id, int ca)
{
	int idx;
	X509_PURPOSE *pt;
	if(!(x->ex_flags & EXFLAG_SET)) {
		CRYPTO_w_lock(CRYPTO_LOCK_X509);
		x509v3_cache_extensions(x);
		CRYPTO_w_unlock(CRYPTO_LOCK_X509);
	}
	idx = x509_purpose_get_idx(id);
	if(idx == -1) return -1;
	pt = sk_X509_PURPOSE_value(xptable, idx);
	return pt->check_purpose(pt, x,ca);
}
			
	


static int x509_purpose_get_idx(int id)
{
	X509_PURPOSE tmp;
	tmp.purpose_id = id;
	if(!xptable) return -1;
	return sk_X509_PURPOSE_find(xptable, &tmp);
}

int X509_PURPOSE_add(X509_PURPOSE *xp)
{
	int idx;
	if(!xptable) xptable = sk_X509_PURPOSE_new(xp_cmp);
	idx = x509_purpose_get_idx(xp->purpose_id);
	if(idx != -1) sk_X509_PURPOSE_set(xptable, idx, xp);
	else sk_X509_PURPOSE_push(xptable, xp);
	return 1;
}

void X509_PURPOSE_add_standard(void)
{
	X509_PURPOSE *xp;
	for(xp = xstandard; xp->purpose_name; xp++)
		X509_PURPOSE_add(xp);
}

int X509_PURPOSE_enum(int (*efunc)(X509_PURPOSE *, void *), void *usr)
{
	int i;
	X509_PURPOSE *xp;
	if(!xptable) return 0;
	for(i = 0; i < sk_X509_PURPOSE_num(xptable); i++) {
		xp = sk_X509_PURPOSE_value(xptable, i);
		if(!efunc(xp, usr)) return i;
	}
	return i;
}


int X509_PURPOSE_get_id(X509_PURPOSE *xp)
{
	return xp->purpose_id;
}

char *X509_PURPOSE_get_name(X509_PURPOSE *xp)
{
	return xp->purpose_name;
}

void x509v3_cache_extensions(X509 *x)
{
	BASIC_CONSTRAINTS *bs;
	ASN1_BIT_STRING *usage;
	ASN1_BIT_STRING *ns;
	STACK_OF(ASN1_OBJECT) *extusage;
	int i;
	if(x->ex_flags & EXFLAG_SET) return;
	/* Does subject name match issuer ? */
	if(X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)))
			 x->ex_flags |= EXFLAG_SS;
	/* V1 should mean no extensions ... */
	if(!X509_get_version(x)) x->ex_flags |= EXFLAG_V1;
	/* Handle basic constraints */
	if((bs=X509V3_X509_get_d2i(x, NID_basic_constraints, NULL, NULL))) {
		if(bs->ca) x->ex_flags |= EXFLAG_CA;
		if(bs->pathlen) {
			if((bs->pathlen->type == V_ASN1_NEG_INTEGER)
						|| !bs->ca) {
				x->ex_flags |= EXFLAG_INVALID;
				x->ex_pathlen = 0;
			} else x->ex_pathlen = ASN1_INTEGER_get(bs->pathlen);
		} else x->ex_pathlen = -1;
		BASIC_CONSTRAINTS_free(bs);
		x->ex_flags |= EXFLAG_BCONS;
	}
	/* Handle key usage */
	if((usage=X509V3_X509_get_d2i(x, NID_key_usage, NULL, NULL))) {
		if(usage->length > 0) {
			x->ex_kusage = usage->data[0];
			if(usage->length > 1) 
				x->ex_kusage |= usage->data[1] << 8;
		} else x->ex_kusage = 0;
		x->ex_flags |= EXFLAG_KUSAGE;
		ASN1_BIT_STRING_free(usage);
	}
	x->ex_xkusage = 0;
	if((extusage=X509V3_X509_get_d2i(x, NID_ext_key_usage, NULL, NULL))) {
		x->ex_flags |= EXFLAG_XKUSAGE;
		for(i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
			switch(OBJ_obj2nid(sk_ASN1_OBJECT_value(extusage,i))) {
				case NID_server_auth:
				x->ex_xkusage |= XKU_SSL_SERVER;
				break;

				case NID_client_auth:
				x->ex_xkusage |= XKU_SSL_CLIENT;
				break;

				case NID_email_protect:
				x->ex_xkusage |= XKU_SMIME;
				break;

				case NID_code_sign:
				x->ex_xkusage |= XKU_CODE_SIGN;
				break;

				case NID_ms_sgc:
				case NID_ns_sgc:
				x->ex_xkusage |= XKU_SGC;
			}
		}
		sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
	}

	if((ns=X509V3_X509_get_d2i(x, NID_netscape_cert_type, NULL, NULL))) {
		if(ns->length > 0) x->ex_nscert = ns->data[0];
		else x->ex_nscert = 0;
		x->ex_flags |= EXFLAG_NSCERT;
		ASN1_BIT_STRING_free(ns);
	}
	x->ex_flags |= EXFLAG_SET;
}

/* CA checks common to all purposes
 * return codes:
 * 0 not a CA
 * 1 is a CA
 * 2 basicConstraints absent so "maybe" a CA
 * 3 basicConstraints absent but self signed V1.
 */

#define V1_ROOT (EXFLAG_V1|EXFLAG_SS)
#define ku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))
#define xku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_XKUSAGE) && !((x)->ex_xkusage & (usage)))
#define ns_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_NSCERT) && !((x)->ex_nscert & (usage)))

static int ca_check(X509 *x)
{
	/* keyUsage if present should allow cert signing */
	if(ku_reject(x, KU_KEY_CERT_SIGN)) return 0;
	if(x->ex_flags & EXFLAG_BCONS) {
		if(x->ex_flags & EXFLAG_CA) return 1;
		/* If basicConstraints says not a CA then say so */
		else return 0;
	} else {
		if((x->ex_flags & V1_ROOT) == V1_ROOT) return 3;
		else return 2;
	}
}


static int check_purpose_ssl_client(X509_PURPOSE *xp, X509 *x, int ca)
{
	if(xku_reject(x,XKU_SSL_CLIENT)) return 0;
	if(ca) {
		int ca_ret;
		ca_ret = ca_check(x);
		if(!ca_ret) return 0;
		/* check nsCertType if present */
		if(x->ex_flags & EXFLAG_NSCERT) {
			if(x->ex_nscert & NS_SSL_CA) return ca_ret;
			return 0;
		}
		if(ca_ret != 2) return ca_ret;
		else return 0;
	}
	/* We need to do digital signatures with it */
	if(ku_reject(x,KU_DIGITAL_SIGNATURE)) return 0;
	/* nsCertType if present should allow SSL client use */	
	if(ns_reject(x, NS_SSL_CLIENT)) return 0;
	return 1;
}

static int check_purpose_ssl_server(X509_PURPOSE *xp, X509 *x, int ca)
{
	if(xku_reject(x,XKU_SSL_SERVER|XKU_SGC)) return 0;
	/* Otherwise same as SSL client for a CA */
	if(ca) return check_purpose_ssl_client(xp, x, 1);

	if(ns_reject(x, NS_SSL_SERVER)) return 0;
	/* Now as for keyUsage: we'll at least need to sign OR encipher */
	if(ku_reject(x, KU_DIGITAL_SIGNATURE|KU_KEY_ENCIPHERMENT)) return 0;
	
	return 1;

}

static int check_purpose_ns_ssl_server(X509_PURPOSE *xp, X509 *x, int ca)
{
	int ret;
	ret = check_purpose_ssl_server(xp, x, ca);
	if(!ret || ca) return ret;
	/* We need to encipher or Netscape complains */
	if(ku_reject(x, KU_KEY_ENCIPHERMENT)) return 0;
	return ret;
}

/* common S/MIME checks */
static int purpose_smime(X509 *x, int ca)
{
	if(xku_reject(x,XKU_SMIME)) return 0;
	if(ca) {
		int ca_ret;
		ca_ret = ca_check(x);
		if(!ca_ret) return 0;
		/* check nsCertType if present */
		if(x->ex_flags & EXFLAG_NSCERT) {
			if(x->ex_nscert & NS_SMIME_CA) return ca_ret;
			return 0;
		}
		if(ca_ret != 2) return ca_ret;
		else return 0;
	}
	if(x->ex_flags & EXFLAG_NSCERT) {
		if(x->ex_nscert & NS_SMIME) return 1;
		/* Workaround for some buggy certificates */
		if(x->ex_nscert & NS_SSL_CLIENT) return 2;
		return 0;
	}
	return 1;
}

static int check_purpose_smime_sign(X509_PURPOSE *xp, X509 *x, int ca)
{
	int ret;
	ret = purpose_smime(x, ca);
	if(!ret || ca) return ret;
	if(ku_reject(x, KU_DIGITAL_SIGNATURE)) return 0;
	return ret;
}

static int check_purpose_smime_encrypt(X509_PURPOSE *xp, X509 *x, int ca)
{
	int ret;
	ret = purpose_smime(x, ca);
	if(!ret || ca) return ret;
	if(ku_reject(x, KU_KEY_ENCIPHERMENT)) return 0;
	return ret;
}

static int check_purpose_crl_sign(X509_PURPOSE *xp, X509 *x, int ca)
{
	if(ca) {
		int ca_ret;
		if((ca_ret = ca_check(x)) != 2) return ca_ret;
		else return 0;
	}
	if(ku_reject(x, KU_CRL_SIGN)) return 0;
	return 1;
}
