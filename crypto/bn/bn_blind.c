/* crypto/bn/bn_blind.c */
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

#include <stdio.h>
#include "cryptlib.h"
#include "bn_lcl.h"

BN_BLINDING *BN_BLINDING_new(BIGNUM *A, BIGNUM *Ai, BIGNUM *mod)
	{
	BN_BLINDING *ret=NULL;

	bn_check_top(Ai);
	bn_check_top(mod);

	if ((ret=(BN_BLINDING *)OPENSSL_malloc(sizeof(BN_BLINDING))) == NULL)
		{
		BNerr(BN_F_BN_BLINDING_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	memset(ret,0,sizeof(BN_BLINDING));
	if ((ret->A=BN_new()) == NULL) goto err;
	if ((ret->Ai=BN_new()) == NULL) goto err;
	if (!BN_copy(ret->A,A)) goto err;
	if (!BN_copy(ret->Ai,Ai)) goto err;
	ret->mod=mod;
	return(ret);
err:
	if (ret != NULL) BN_BLINDING_free(ret);
	return(NULL);
	}

void BN_BLINDING_free(BN_BLINDING *r)
	{
	if(r == NULL)
	    return;

	if (r->A  != NULL) BN_free(r->A );
	if (r->Ai != NULL) BN_free(r->Ai);
	OPENSSL_free(r);
	}

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
	{
	int ret=0;

	if ((b->A == NULL) || (b->Ai == NULL))
		{
		BNerr(BN_F_BN_BLINDING_UPDATE,BN_R_NOT_INITIALIZED);
		goto err;
		}
		
	if (!BN_mod_mul(b->A,b->A,b->A,b->mod,ctx)) goto err;
	if (!BN_mod_mul(b->Ai,b->Ai,b->Ai,b->mod,ctx)) goto err;

	ret=1;
err:
	return(ret);
	}

int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)
	{
	bn_check_top(n);

	if ((b->A == NULL) || (b->Ai == NULL))
		{
		BNerr(BN_F_BN_BLINDING_CONVERT,BN_R_NOT_INITIALIZED);
		return(0);
		}
	return(BN_mod_mul(n,n,b->A,b->mod,ctx));
	}

int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)
	{
	int ret;

	bn_check_top(n);
	if ((b->A == NULL) || (b->Ai == NULL))
		{
		BNerr(BN_F_BN_BLINDING_INVERT,BN_R_NOT_INITIALIZED);
		return(0);
		}
	if ((ret=BN_mod_mul(n,n,b->Ai,b->mod,ctx)) >= 0)
		{
		if (!BN_BLINDING_update(b,ctx))
			return(0);
		}
	return(ret);
	}

