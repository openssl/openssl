/* ssl/ssl_cert.c */
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
#include "objects.h"
#include "bio.h"
#include "pem.h"
#include "ssl_locl.h"

CERT *ssl_cert_new()
	{
	CERT *ret;

	ret=(CERT *)Malloc(sizeof(CERT));
	if (ret == NULL)
		{
		SSLerr(SSL_F_SSL_CERT_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	memset(ret,0,sizeof(CERT));
/*
	ret->valid=0;
	ret->mask=0;
	ret->export_mask=0;
	ret->cert_type=0;
	ret->key->x509=NULL;
	ret->key->publickey=NULL;
	ret->key->privatekey=NULL; */

	ret->key= &(ret->pkeys[SSL_PKEY_RSA_ENC]);
	ret->references=1;

	return(ret);
	}

void ssl_cert_free(c)
CERT *c;
	{
	int i;

	i=CRYPTO_add(&c->references,-1,CRYPTO_LOCK_SSL_CERT);
#ifdef REF_PRINT
	REF_PRINT("CERT",c);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"ssl_cert_free, bad reference count\n");
		abort(); /* ok */
		}
#endif

#ifndef NO_RSA
	if (c->rsa_tmp) RSA_free(c->rsa_tmp);
#endif
#ifndef NO_DH
	if (c->dh_tmp) DH_free(c->dh_tmp);
#endif

	for (i=0; i<SSL_PKEY_NUM; i++)
		{
		if (c->pkeys[i].x509 != NULL)
			X509_free(c->pkeys[i].x509);
		if (c->pkeys[i].privatekey != NULL)
			EVP_PKEY_free(c->pkeys[i].privatekey);
#if 0
		if (c->pkeys[i].publickey != NULL)
			EVP_PKEY_free(c->pkeys[i].publickey);
#endif
		}
	if (c->cert_chain != NULL)
		sk_pop_free(c->cert_chain,X509_free);
	Free(c);
	}

int ssl_set_cert_type(c, type)
CERT *c;
int type;
	{
	c->cert_type=type;
	return(1);
	}

int ssl_verify_cert_chain(s,sk)
SSL *s;
STACK *sk;
	{
	X509 *x;
	int i;
	X509_STORE_CTX ctx;

	if ((sk == NULL) || (sk_num(sk) == 0))
		return(0);

	x=(X509 *)sk_value(sk,0);
	X509_STORE_CTX_init(&ctx,s->ctx->cert_store,x,sk);
	X509_STORE_CTX_set_app_data(&ctx,(char *)s);

	if (s->ctx->app_verify_callback != NULL)
		i=s->ctx->app_verify_callback(&ctx);
	else
		i=X509_verify_cert(&ctx);

	X509_STORE_CTX_cleanup(&ctx);
	s->verify_result=ctx.error;

	return(i);
	}

static void set_client_CA_list(ca_list,list)
STACK **ca_list;
STACK *list;
	{
	if (*ca_list != NULL)
		sk_pop_free(*ca_list,X509_NAME_free);

	*ca_list=list;
	}

STACK *SSL_dup_CA_list(sk)
STACK *sk;
	{
	int i;
	STACK *ret;
	X509_NAME *name;

	ret=sk_new_null();
	for (i=0; i<sk_num(sk); i++)
		{
		name=X509_NAME_dup((X509_NAME *)sk_value(sk,i));
		if ((name == NULL) || !sk_push(ret,(char *)name))
			{
			sk_pop_free(ret,X509_NAME_free);
			return(NULL);
			}
		}
	return(ret);
	}

void SSL_set_client_CA_list(s,list)
SSL *s;
STACK *list;
	{
	set_client_CA_list(&(s->client_CA),list);
	}

void SSL_CTX_set_client_CA_list(ctx,list)
SSL_CTX *ctx;
STACK *list;
	{
	set_client_CA_list(&(ctx->client_CA),list);
	}

STACK *SSL_CTX_get_client_CA_list(ctx)
SSL_CTX *ctx;
	{
	return(ctx->client_CA);
	}

STACK *SSL_get_client_CA_list(s)
SSL *s;
	{
	if (s->type == SSL_ST_CONNECT)
		{ /* we are in the client */
		if (((s->version>>8) == SSL3_VERSION_MAJOR) &&
			(s->s3 != NULL))
			return(s->s3->tmp.ca_names);
		else
			return(NULL);
		}
	else
		{
		if (s->client_CA != NULL)
			return(s->client_CA);
		else
			return(s->ctx->client_CA);
		}
	}

static int add_client_CA(sk,x)
STACK **sk;
X509 *x;
	{
	X509_NAME *name;

	if (x == NULL) return(0);
	if ((*sk == NULL) && ((*sk=sk_new_null()) == NULL))
		return(0);
		
	if ((name=X509_NAME_dup(X509_get_subject_name(x))) == NULL)
		return(0);

	if (!sk_push(*sk,(char *)name))
		{
		X509_NAME_free(name);
		return(0);
		}
	return(1);
	}

int SSL_add_client_CA(ssl,x)
SSL *ssl;
X509 *x;
	{
	return(add_client_CA(&(ssl->client_CA),x));
	}

int SSL_CTX_add_client_CA(ctx,x)
SSL_CTX *ctx;
X509 *x;
	{
	return(add_client_CA(&(ctx->client_CA),x));
	}

static int name_cmp(a,b)
X509_NAME **a,**b;
	{
	return(X509_NAME_cmp(*a,*b));
	}

#ifndef NO_STDIO
STACK *SSL_load_client_CA_file(file)
char *file;
	{
	BIO *in;
	X509 *x=NULL;
	X509_NAME *xn=NULL;
	STACK *ret,*sk;

	ret=sk_new(NULL);
	sk=sk_new(name_cmp);

	in=BIO_new(BIO_s_file_internal());

	if ((ret == NULL) || (sk == NULL) || (in == NULL))
		{
		SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	
	if (!BIO_read_filename(in,file))
		goto err;

	for (;;)
		{
		if (PEM_read_bio_X509(in,&x,NULL) == NULL)
			break;
		if ((xn=X509_get_subject_name(x)) == NULL) goto err;
		/* check for duplicates */
		xn=X509_NAME_dup(xn);
		if (xn == NULL) goto err;
		if (sk_find(sk,(char *)xn) >= 0)
			X509_NAME_free(xn);
		else
			{
			sk_push(sk,(char *)xn);
			sk_push(ret,(char *)xn);
			}
		}

	if (0)
		{
err:
		if (ret != NULL) sk_pop_free(ret,X509_NAME_free);
		ret=NULL;
		}
	if (sk != NULL) sk_free(sk);
	if (in != NULL) BIO_free(in);
	if (x != NULL) X509_free(x);
	return(ret);
	}
#endif

