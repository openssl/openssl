/* crypto/rsa/rsa_lib.c */
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
#include "crypto.h"
#include "cryptlib.h"
#include "lhash.h"
#include "bn.h"
#include "rsa.h"

char *RSA_version="RSA part of SSLeay 0.9.0b 29-Jun-1998";

static RSA_METHOD *default_RSA_meth=NULL;
static int rsa_meth_num=0;
static STACK *rsa_meth=NULL;

RSA *RSA_new()
	{
	return(RSA_new_method(NULL));
	}

void RSA_set_default_method(meth)
RSA_METHOD *meth;
	{
	default_RSA_meth=meth;
	}

RSA *RSA_new_method(meth)
RSA_METHOD *meth;
	{
	RSA *ret;

	if (default_RSA_meth == NULL)
		{
#ifdef RSAref
		default_RSA_meth=RSA_PKCS1_RSAref();
#else
		default_RSA_meth=RSA_PKCS1_SSLeay();
#endif
		}
	ret=(RSA *)Malloc(sizeof(RSA));
	if (ret == NULL)
		{
		RSAerr(RSA_F_RSA_NEW_METHOD,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}

	if (meth == NULL)
		ret->meth=default_RSA_meth;
	else
		ret->meth=meth;

	ret->pad=0;
	ret->version=0;
	ret->n=NULL;
	ret->e=NULL;
	ret->d=NULL;
	ret->p=NULL;
	ret->q=NULL;
	ret->dmp1=NULL;
	ret->dmq1=NULL;
	ret->iqmp=NULL;
	ret->references=1;
	ret->method_mod_n=NULL;
	ret->method_mod_p=NULL;
	ret->method_mod_q=NULL;
	ret->blinding=NULL;
	ret->flags=ret->meth->flags;
	if ((ret->meth->init != NULL) && !ret->meth->init(ret))
		{
		Free(ret);
		ret=NULL;
		}
	CRYPTO_new_ex_data(rsa_meth,(char *)ret,&ret->ex_data);
	return(ret);
	}

void RSA_free(r)
RSA *r;
	{
	int i;

	if (r == NULL) return;

	i=CRYPTO_add(&r->references,-1,CRYPTO_LOCK_RSA);
#ifdef REF_PRINT
	REF_PRINT("RSA",r);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"RSA_free, bad reference count\n");
		abort();
		}
#endif

	CRYPTO_free_ex_data(rsa_meth,(char *)r,&r->ex_data);

	if (r->meth->finish != NULL)
		r->meth->finish(r);

	if (r->n != NULL) BN_clear_free(r->n);
	if (r->e != NULL) BN_clear_free(r->e);
	if (r->d != NULL) BN_clear_free(r->d);
	if (r->p != NULL) BN_clear_free(r->p);
	if (r->q != NULL) BN_clear_free(r->q);
	if (r->dmp1 != NULL) BN_clear_free(r->dmp1);
	if (r->dmq1 != NULL) BN_clear_free(r->dmq1);
	if (r->iqmp != NULL) BN_clear_free(r->iqmp);
	if (r->blinding != NULL) BN_BLINDING_free(r->blinding);
	Free(r);
	}

int RSA_get_ex_new_index(argl,argp,new_func,dup_func,free_func)
long argl;
char *argp;
int (*new_func)();
int (*dup_func)();
void (*free_func)();
        {
	rsa_meth_num++;
	return(CRYPTO_get_ex_new_index(rsa_meth_num-1,
		&rsa_meth,argl,argp,new_func,dup_func,free_func));
        }

int RSA_set_ex_data(r,idx,arg)
RSA *r;
int idx;
char *arg;
	{
	return(CRYPTO_set_ex_data(&r->ex_data,idx,arg));
	}

char *RSA_get_ex_data(r,idx)
RSA *r;
int idx;
	{
	return(CRYPTO_get_ex_data(&r->ex_data,idx));
	}

int RSA_size(r)
RSA *r;
	{
	return(BN_num_bytes(r->n));
	}

int RSA_public_encrypt(flen, from, to, rsa, padding)
int flen;
unsigned char *from;
unsigned char *to;
RSA *rsa;
int padding;
	{
	return(rsa->meth->rsa_pub_enc(flen, from, to, rsa, padding));
	}

int RSA_private_encrypt(flen, from, to, rsa, padding)
int flen;
unsigned char *from;
unsigned char *to;
RSA *rsa;
int padding;
	{
	return(rsa->meth->rsa_priv_enc(flen, from, to, rsa, padding));
	}

int RSA_private_decrypt(flen, from, to, rsa, padding)
int flen;
unsigned char *from;
unsigned char *to;
RSA *rsa;
int padding;
	{
	return(rsa->meth->rsa_priv_dec(flen, from, to, rsa, padding));
	}

int RSA_public_decrypt(flen, from, to, rsa, padding)
int flen;
unsigned char *from;
unsigned char *to;
RSA *rsa;
int padding;
	{
	return(rsa->meth->rsa_pub_dec(flen, from, to, rsa, padding));
	}

int RSA_flags(r)
RSA *r;
	{
	return((r == NULL)?0:r->meth->flags);
	}

void RSA_blinding_off(rsa)
RSA *rsa;
	{
	if (rsa->blinding != NULL)
		{
		BN_BLINDING_free(rsa->blinding);
		rsa->blinding=NULL;
		}
	rsa->flags&= ~RSA_FLAG_BLINDING;
	}

int RSA_blinding_on(rsa,p_ctx)
RSA *rsa;
BN_CTX *p_ctx;
	{
	BIGNUM *A,*Ai;
	BN_CTX *ctx;
	int ret=0;

	if (p_ctx == NULL)
		{
		if ((ctx=BN_CTX_new()) == NULL) goto err;
		}
	else
		ctx=p_ctx;

	if (rsa->blinding != NULL)
		BN_BLINDING_free(rsa->blinding);

	A=ctx->bn[0];
	ctx->tos++;
	if (!BN_rand(A,BN_num_bits(rsa->n)-1,1,0)) goto err;
	if ((Ai=BN_mod_inverse(A,rsa->n,ctx)) == NULL) goto err;

	if (!rsa->meth->bn_mod_exp(A,A,rsa->e,rsa->n,ctx,
		(char *)rsa->method_mod_n)) goto err;
	rsa->blinding=BN_BLINDING_new(A,Ai,rsa->n);
	ctx->tos--;
	rsa->flags|=RSA_FLAG_BLINDING;
	BN_free(Ai);
	ret=1;
err:
	if (ctx != p_ctx) BN_CTX_free(ctx);
	return(ret);
	}

