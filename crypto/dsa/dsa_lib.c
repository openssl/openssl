/* crypto/dsa/dsa_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* Origional version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

#include <stdio.h>
#include "cryptlib.h"
#include "bn.h"
#include "dsa.h"
#include "asn1.h"

char *DSA_version="\0DSA part of SSLeay 0.9.0b 29-Jun-1998";

DSA *DSA_new()
	{
	DSA *ret;

	ret=(DSA *)Malloc(sizeof(DSA));
	if (ret == NULL)
		{
		DSAerr(DSA_F_DSA_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->pad=0;
	ret->version=0;
	ret->write_params=1;
	ret->p=NULL;
	ret->q=NULL;
	ret->g=NULL;

	ret->pub_key=NULL;
	ret->priv_key=NULL;

	ret->kinv=NULL;
	ret->r=NULL;

	ret->references=1;
	return(ret);
	}

void DSA_free(r)
DSA *r;
	{
	int i;

	if (r == NULL) return;

	i=CRYPTO_add(&r->references,-1,CRYPTO_LOCK_DSA);
#ifdef REF_PRINT
	REF_PRINT("DSA",r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"DSA_free, bad reference count\n");
		abort();
		}
#endif

	if (r->p != NULL) BN_clear_free(r->p);
	if (r->q != NULL) BN_clear_free(r->q);
	if (r->g != NULL) BN_clear_free(r->g);
	if (r->pub_key != NULL) BN_clear_free(r->pub_key);
	if (r->priv_key != NULL) BN_clear_free(r->priv_key);
	if (r->kinv != NULL) BN_clear_free(r->kinv);
	if (r->r != NULL) BN_clear_free(r->r);
	Free(r);
	}

int DSA_size(r)
DSA *r;
	{
	int ret,i;
	ASN1_INTEGER bs;
	unsigned char buf[4];

	i=BN_num_bits(r->q);
	bs.length=(i+7)/8;
	bs.data=buf;
	bs.type=V_ASN1_INTEGER;
	/* If the top bit is set the asn1 encoding is 1 larger. */
	buf[0]=0xff;	

	i=i2d_ASN1_INTEGER(&bs,NULL);
	i+=i; /* r and s */
	ret=ASN1_object_size(1,i,V_ASN1_SEQUENCE);
	return(ret);
	}

