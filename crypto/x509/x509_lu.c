/* crypto/x509/x509_lu.c */
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
#include <openssl/lhash.h>
#include <openssl/x509.h>

static STACK_OF(CRYPTO_EX_DATA_FUNCS) *x509_store_meth=NULL;
static STACK_OF(CRYPTO_EX_DATA_FUNCS) *x509_store_ctx_meth=NULL;

X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method)
	{
	X509_LOOKUP *ret;

	ret=(X509_LOOKUP *)Malloc(sizeof(X509_LOOKUP));
	if (ret == NULL) return(NULL);

	ret->init=0;
	ret->skip=0;
	ret->method=method;
	ret->method_data=NULL;
	ret->store_ctx=NULL;
	if ((method->new_item != NULL) && !method->new_item(ret))
		{
		Free(ret);
		return(NULL);
		}
	return(ret);
	}

void X509_LOOKUP_free(X509_LOOKUP *ctx)
	{
	if (ctx == NULL) return;
	if (	(ctx->method != NULL) &&
		(ctx->method->free != NULL))
		ctx->method->free(ctx);
	Free(ctx);
	}

int X509_LOOKUP_init(X509_LOOKUP *ctx)
	{
	if (ctx->method == NULL) return(0);
	if (ctx->method->init != NULL)
		return(ctx->method->init(ctx));
	else
		return(1);
	}

int X509_LOOKUP_shutdown(X509_LOOKUP *ctx)
	{
	if (ctx->method == NULL) return(0);
	if (ctx->method->shutdown != NULL)
		return(ctx->method->shutdown(ctx));
	else
		return(1);
	}

int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
	     char **ret)
	{
	if (ctx->method == NULL) return(-1);
	if (ctx->method->ctrl != NULL)
		return(ctx->method->ctrl(ctx,cmd,argc,argl,ret));
	else
		return(1);
	}

int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name,
	     X509_OBJECT *ret)
	{
	if ((ctx->method == NULL) || (ctx->method->get_by_subject == NULL))
		return(X509_LU_FAIL);
	if (ctx->skip) return(0);
	return(ctx->method->get_by_subject(ctx,type,name,ret));
	}

int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, int type, X509_NAME *name,
	     ASN1_INTEGER *serial, X509_OBJECT *ret)
	{
	if ((ctx->method == NULL) ||
		(ctx->method->get_by_issuer_serial == NULL))
		return(X509_LU_FAIL);
	return(ctx->method->get_by_issuer_serial(ctx,type,name,serial,ret));
	}

int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, int type,
	     unsigned char *bytes, int len, X509_OBJECT *ret)
	{
	if ((ctx->method == NULL) || (ctx->method->get_by_fingerprint == NULL))
		return(X509_LU_FAIL);
	return(ctx->method->get_by_fingerprint(ctx,type,bytes,len,ret));
	}

int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, int type, char *str, int len,
	     X509_OBJECT *ret)
	{
	if ((ctx->method == NULL) || (ctx->method->get_by_alias == NULL))
		return(X509_LU_FAIL);
	return(ctx->method->get_by_alias(ctx,type,str,len,ret));
	}

static unsigned long x509_object_hash(X509_OBJECT *a)
	{
	unsigned long h;

	switch (a->type)
		{
	case X509_LU_X509:
		h=X509_NAME_hash(a->data.x509->cert_info->subject);
		break;
	case X509_LU_CRL:
		h=X509_NAME_hash(a->data.crl->crl->issuer);
		break;
	default:
		abort();
		}
	return(h);
	}

static int x509_object_cmp(X509_OBJECT *a, X509_OBJECT *b)
	{
	int ret;

	ret=(a->type - b->type);
	if (ret) return(ret);
	switch (a->type)
		{
	case X509_LU_X509:
		ret=X509_subject_name_cmp(a->data.x509,b->data.x509);
		break;
	case X509_LU_CRL:
		ret=X509_CRL_cmp(a->data.crl,b->data.crl);
		break;
	default:
		abort();
		}
	return(ret);
	}

X509_STORE *X509_STORE_new(void)
	{
	X509_STORE *ret;

	if ((ret=(X509_STORE *)Malloc(sizeof(X509_STORE))) == NULL)
		return(NULL);
	ret->certs=lh_new(x509_object_hash,x509_object_cmp);
	ret->cache=1;
	ret->get_cert_methods=sk_X509_LOOKUP_new_null();
	ret->verify=NULL;
	ret->verify_cb=NULL;
	memset(&ret->ex_data,0,sizeof(CRYPTO_EX_DATA));
	ret->references=1;
	ret->depth=0;
	return(ret);
	}

static void cleanup(X509_OBJECT *a)
	{
	if (a->type == X509_LU_X509)
		{
		X509_free(a->data.x509);
		}
	else if (a->type == X509_LU_CRL)
		{
		X509_CRL_free(a->data.crl);
		}
	else
		abort();

	Free(a);
	}

void X509_STORE_free(X509_STORE *vfy)
	{
	int i;
	STACK_OF(X509_LOOKUP) *sk;
	X509_LOOKUP *lu;

	if(vfy == NULL)
	    return;

	sk=vfy->get_cert_methods;
	for (i=0; i<sk_X509_LOOKUP_num(sk); i++)
		{
		lu=sk_X509_LOOKUP_value(sk,i);
		X509_LOOKUP_shutdown(lu);
		X509_LOOKUP_free(lu);
		}
	sk_X509_LOOKUP_free(sk);

	CRYPTO_free_ex_data(x509_store_meth,vfy,&vfy->ex_data);
	lh_doall(vfy->certs,cleanup);
	lh_free(vfy->certs);
	Free(vfy);
	}

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m)
	{
	int i;
	STACK_OF(X509_LOOKUP) *sk;
	X509_LOOKUP *lu;

	sk=v->get_cert_methods;
	for (i=0; i<sk_X509_LOOKUP_num(sk); i++)
		{
		lu=sk_X509_LOOKUP_value(sk,i);
		if (m == lu->method)
			{
			return(lu);
			}
		}
	/* a new one */
	lu=X509_LOOKUP_new(m);
	if (lu == NULL)
		return(NULL);
	else
		{
		lu->store_ctx=v;
		if (sk_X509_LOOKUP_push(v->get_cert_methods,lu))
			return(lu);
		else
			{
			X509_LOOKUP_free(lu);
			return(NULL);
			}
		}
	}

int X509_STORE_get_by_subject(X509_STORE_CTX *vs, int type, X509_NAME *name,
	     X509_OBJECT *ret)
	{
	X509_STORE *ctx=vs->ctx;
	X509_LOOKUP *lu;
	X509_OBJECT stmp,*tmp;
	int i,j;

	tmp=X509_OBJECT_retrieve_by_subject(ctx->certs,type,name);

	if (tmp == NULL)
		{
		for (i=vs->current_method; i<sk_X509_LOOKUP_num(ctx->get_cert_methods); i++)
			{
			lu=sk_X509_LOOKUP_value(ctx->get_cert_methods,i);
			j=X509_LOOKUP_by_subject(lu,type,name,&stmp);
			if (j < 0)
				{
				vs->current_method=j;
				return(j);
				}
			else if (j)
				{
				tmp= &stmp;
				break;
				}
			}
		vs->current_method=0;
		if (tmp == NULL)
			return(0);
		}

/*	if (ret->data.ptr != NULL)
		X509_OBJECT_free_contents(ret); */

	ret->type=tmp->type;
	ret->data.ptr=tmp->data.ptr;

	X509_OBJECT_up_ref_count(ret);

	return(1);
	}

void X509_OBJECT_up_ref_count(X509_OBJECT *a)
	{
	switch (a->type)
		{
	case X509_LU_X509:
		CRYPTO_add(&a->data.x509->references,1,CRYPTO_LOCK_X509);
		break;
	case X509_LU_CRL:
		CRYPTO_add(&a->data.crl->references,1,CRYPTO_LOCK_X509_CRL);
		break;
		}
	}

void X509_OBJECT_free_contents(X509_OBJECT *a)
	{
	switch (a->type)
		{
	case X509_LU_X509:
		X509_free(a->data.x509);
		break;
	case X509_LU_CRL:
		X509_CRL_free(a->data.crl);
		break;
		}
	}

X509_OBJECT *X509_OBJECT_retrieve_by_subject(LHASH *h, int type,
	     X509_NAME *name)
	{
	X509_OBJECT stmp,*tmp;
	X509 x509_s;
	X509_CINF cinf_s;
	X509_CRL crl_s;
	X509_CRL_INFO crl_info_s;

	stmp.type=type;
	switch (type)
		{
	case X509_LU_X509:
		stmp.data.x509= &x509_s;
		x509_s.cert_info= &cinf_s;
		cinf_s.subject=name;
		break;
	case X509_LU_CRL:
		stmp.data.crl= &crl_s;
		crl_s.crl= &crl_info_s;
		crl_info_s.issuer=name;
		break;
	default:
		abort();
		}

	tmp=(X509_OBJECT *)lh_retrieve(h,&stmp);
	return(tmp);
	}

X509_STORE_CTX *X509_STORE_CTX_new(void)
{
	X509_STORE_CTX *ctx;
	ctx = (X509_STORE_CTX *)Malloc(sizeof(X509_STORE_CTX));
	if(ctx) memset(ctx, 0, sizeof(X509_STORE_CTX));
	return ctx;
}

void X509_STORE_CTX_free(X509_STORE_CTX *ctx)
{
	X509_STORE_CTX_cleanup(ctx);
	Free(ctx);
}

void X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509,
	     STACK_OF(X509) *chain)
	{
	ctx->ctx=store;
	ctx->current_method=0;
	ctx->cert=x509;
	ctx->untrusted=chain;
	ctx->last_untrusted=0;
	ctx->purpose=0;
	ctx->trust=0;
	ctx->valid=0;
	ctx->chain=NULL;
	ctx->depth=9;
	ctx->error=0;
	ctx->current_cert=NULL;
	memset(&(ctx->ex_data),0,sizeof(CRYPTO_EX_DATA));
	}

void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx)
	{
	if (ctx->chain != NULL)
		{
		sk_X509_pop_free(ctx->chain,X509_free);
		ctx->chain=NULL;
		}
	CRYPTO_free_ex_data(x509_store_ctx_meth,ctx,&(ctx->ex_data));
	memset(&ctx->ex_data,0,sizeof(CRYPTO_EX_DATA));
	}

IMPLEMENT_STACK_OF(X509_LOOKUP)
