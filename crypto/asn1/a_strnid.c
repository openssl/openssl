/* a_strnid.c */
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
#include <ctype.h>
#include "cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/objects.h>


static STACK_OF(ASN1_STRING_TABLE) *stable = NULL;
static void st_free(ASN1_STRING_TABLE *tbl);
static int sk_table_cmp(ASN1_STRING_TABLE **a, ASN1_STRING_TABLE **b);

/* The following function generates an ASN1_STRING based on limits in a table.
 * Frequently the types and length of an ASN1_STRING are restricted by a 
 * corresponding OID. For example certificates and certificate requests.
 */

ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out, const unsigned char *in,
					int inlen, int inform, int nid)
{
	ASN1_STRING_TABLE *tbl;
	ASN1_STRING *str = NULL;
	int ret;
	if(!out) out = &str;
	if(!stable) ASN1_STRING_TABLE_add_standard();
	tbl = ASN1_STRING_TABLE_get(nid);
	if(tbl) ret = ASN1_mbstring_ncopy(out, in, inlen, inform, tbl->mask,
					tbl->minsize, tbl->maxsize);
	else ret = ASN1_mbstring_copy(out, in, inlen, inform, 0);
	if(ret <= 0) return NULL;
	return *out;
}

/* Now the tables and helper functions for the string table:
 */

/* size limits: this stuff is taken straight from RFC2459 */

#define ub_name				32768
#define ub_common_name			64
#define ub_locality_name		128
#define ub_state_name			128
#define ub_organization_name		64
#define ub_organization_unit_name	64
#define ub_title			64
#define ub_email_address		128

static ASN1_STRING_TABLE tbl_standard[] = {
{NID_name,			1, ub_name, 0, 0},
{NID_surname,			1, ub_name, 0, 0},
{NID_givenName,			1, ub_name, 0, 0},
{NID_initials,			1, ub_name, 0, 0},
{NID_commonName,		1, ub_common_name, 0, 0},
{NID_localityName,		1, ub_locality_name, 0, 0},
{NID_stateOrProvinceName,	1, ub_state_name, 0, 0},
{NID_organizationName,		1, ub_organization_name, 0, 0},
{NID_organizationalUnitName,	1, ub_organization_unit_name, 0, 0},
{NID_dnQualifier,		-1, -1, B_ASN1_PRINTABLESTRING, 0},
{NID_countryName,		2, 2, B_ASN1_PRINTABLESTRING, 0},
{NID_pkcs9_emailAddress,	1, ub_email_address, B_ASN1_IA5STRING, 0},
{NID_undef, 0, 0, 0, 0}
};

int ASN1_STRING_TABLE_add_standard(void)
{
	static int done = 0;
	ASN1_STRING_TABLE *tmp;
	if(done) return 1;
	if(!stable) stable = sk_ASN1_STRING_TABLE_new(sk_table_cmp);
	if(!stable) {
		ASN1err(ASN1_F_ASN1_STRING_TABLE_ADD_STANDARD,
						ERR_R_MALLOC_FAILURE);
		return 0;
	}
	for(tmp = tbl_standard; tmp->nid != NID_undef; tmp++) {
		if(!sk_ASN1_STRING_TABLE_push(stable, tmp)) {
			ASN1err(ASN1_F_ASN1_STRING_TABLE_ADD_STANDARD,
							ERR_R_MALLOC_FAILURE);
			return 0;
		}
	}
	return 1;
}

static int sk_table_cmp(ASN1_STRING_TABLE **a, ASN1_STRING_TABLE **b)
{
	return (*a)->nid - (*b)->nid;
}

ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid)
{
	int idx;
	ASN1_STRING_TABLE fnd;
	fnd.nid = nid;
	idx = sk_ASN1_STRING_TABLE_find(stable, &fnd);
	if(idx < 0) return NULL;
	return sk_ASN1_STRING_TABLE_value(stable, idx);
}
	
int ASN1_STRING_TABLE_add(int nid,
		 long minsize, long maxsize, unsigned long mask,
				unsigned long flags)
{
	ASN1_STRING_TABLE *tmp;
	char new_nid = 0;
	if(!stable) stable = sk_ASN1_STRING_TABLE_new(sk_table_cmp);
	if(!stable) {
		ASN1err(ASN1_F_ASN1_STRING_TABLE_ADD, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if(!(tmp = ASN1_STRING_TABLE_get(nid))) {
		tmp = Malloc(sizeof(ASN1_STRING_TABLE));
		if(!tmp) {
			ASN1err(ASN1_F_ASN1_STRING_TABLE_ADD,
							ERR_R_MALLOC_FAILURE);
			return 0;
		}
		tmp->flags = STABLE_FLAGS_MALLOC;
		tmp->nid = nid;
		new_nid = 1;
	}
	if(minsize != -1) tmp->minsize = minsize;
	if(maxsize != -1) tmp->maxsize = maxsize;
	tmp->mask = mask;
	tmp->flags = flags & ~STABLE_FLAGS_MALLOC;
	if(new_nid) sk_ASN1_STRING_TABLE_push(stable, tmp);
	return 1;
}

void ASN1_STRING_TABLE_cleanup(void)
{
	STACK_OF(ASN1_STRING_TABLE) *tmp;
	tmp = stable;
	if(!tmp) return;
	stable = NULL;
	sk_ASN1_STRING_TABLE_pop_free(tmp, st_free);
}

static void st_free(ASN1_STRING_TABLE *tbl)
{
	if(tbl->flags & STABLE_FLAGS_MALLOC) Free(tbl);
}

IMPLEMENT_STACK_OF(ASN1_STRING_TABLE)
