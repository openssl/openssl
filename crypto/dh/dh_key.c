/* crypto/dh/dh_key.c */
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
#include "bn.h"
#include "rand.h"
#include "dh.h"

int DH_generate_key(dh)
DH *dh;
	{
	int ok=0;
	unsigned int i;
	BN_CTX *ctx=NULL;
	BIGNUM *pub_key=NULL,*priv_key=NULL;

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;

	if (dh->priv_key == NULL)
		{
		i=dh->length;
		if (i == 0)
			{
			/* Make the number p-1 bits long */
			i=BN_num_bits(dh->p)-1;
			}
		priv_key=BN_new();
		if (priv_key == NULL) goto err;
		if (!BN_rand(priv_key,i,0,0)) goto err;
		}
	else
		priv_key=dh->priv_key;

	if (dh->pub_key == NULL)
		{
		pub_key=BN_new();
		if (pub_key == NULL) goto err;
		}
	else
		pub_key=dh->pub_key;

	if (!BN_mod_exp(pub_key,dh->g,priv_key,dh->p,ctx)) goto err;
		
	dh->pub_key=pub_key;
	dh->priv_key=priv_key;
	ok=1;
err:
	if (ok != 1)
		DHerr(DH_F_DH_GENERATE_KEY,ERR_R_BN_LIB);

	if ((pub_key != NULL)  && (dh->pub_key == NULL))  BN_free(pub_key);
	if ((priv_key != NULL) && (dh->priv_key == NULL)) BN_free(priv_key);
	if (ctx != NULL) BN_CTX_free(ctx);
	return(ok);
	}

int DH_compute_key(key,pub_key,dh)
unsigned char *key;
BIGNUM *pub_key;
DH *dh;
	{
	BN_CTX *ctx;
	BIGNUM *tmp;
	int ret= -1;

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;
	tmp=ctx->bn[ctx->tos++];
	
	if (dh->priv_key == NULL)
		{
		DHerr(DH_F_DH_COMPUTE_KEY,DH_R_NO_PRIVATE_VALUE);
		goto err;
		}
	if (!BN_mod_exp(tmp,pub_key,dh->priv_key,dh->p,ctx))
		{
		DHerr(DH_F_DH_COMPUTE_KEY,ERR_R_BN_LIB);
		goto err;
		}

	ret=BN_bn2bin(tmp,key);
err:
	if (ctx != NULL) BN_CTX_free(ctx);
	return(ret);
	}
