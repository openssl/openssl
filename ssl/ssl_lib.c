/* ssl/ssl_lib.c */
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
#include "lhash.h"
#include "ssl_locl.h"

char *SSL_version_str="SSLeay 0.9.0b 29-Jun-1998";

static STACK *ssl_meth=NULL;
static STACK *ssl_ctx_meth=NULL;
static int ssl_meth_num=0;
static int ssl_ctx_meth_num=0;

SSL3_ENC_METHOD ssl3_undef_enc_method={
	ssl_undefined_function,
	ssl_undefined_function,
	ssl_undefined_function,
	ssl_undefined_function,
	ssl_undefined_function,
	ssl_undefined_function,
	};

void SSL_clear(s)
SSL *s;
	{
	int state;

	if (s->method == NULL) return;

	s->error=0;
	s->hit=0;

	/* This is set if we are doing dynamic renegotiation so keep
	 * the old cipher.  It is sort of a SSL_clear_lite :-) */
	if (s->new_session) return;

	state=s->state; /* Keep to check if we throw away the session-id */
	s->type=0;

	s->version=s->method->version;
	s->rwstate=SSL_NOTHING;
	s->state=SSL_ST_BEFORE;
	s->rstate=SSL_ST_READ_HEADER;
	s->read_ahead=s->ctx->default_read_ahead;

/*	s->shutdown=(SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN); */

	if (s->init_buf != NULL)
		{
		BUF_MEM_free(s->init_buf);
		s->init_buf=NULL;
		}

	ssl_clear_cipher_ctx(s);

	if (ssl_clear_bad_session(s))
		{
		SSL_SESSION_free(s->session);
		s->session=NULL;
		}

	s->shutdown=(SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
	s->first_packet=0;

	s->method->ssl_clear(s);
	}

/* Used to change an SSL_CTXs default SSL method type */
int SSL_CTX_set_ssl_version(ctx,meth)
SSL_CTX *ctx;
SSL_METHOD *meth;
	{
	STACK *sk;

	ctx->method=meth;

	sk=ssl_create_cipher_list(ctx->method,&(ctx->cipher_list),
		&(ctx->cipher_list_by_id),SSL_DEFAULT_CIPHER_LIST);
	if ((sk == NULL) || (sk_num(sk) <= 0))
		{
		SSLerr(SSL_F_SSL_CTX_SET_SSL_VERSION,SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS);
		return(0);
		}
	return(1);
	}

SSL *SSL_new(ctx)
SSL_CTX *ctx;
	{
	SSL *s;

	if (ctx == NULL)
		{
		SSLerr(SSL_F_SSL_NEW,SSL_R_NULL_SSL_CTX);
		return(NULL);
		}
	if (ctx->method == NULL)
		{
		SSLerr(SSL_F_SSL_NEW,SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION);
		return(NULL);
		}

	s=(SSL *)Malloc(sizeof(SSL));
	if (s == NULL) goto err;
	memset(s,0,sizeof(SSL));

	if (ctx->default_cert != NULL)
		{
		CRYPTO_add(&ctx->default_cert->references,1,
			CRYPTO_LOCK_SSL_CERT);
		s->cert=ctx->default_cert;
		}
	else
		s->cert=NULL;
	s->verify_mode=ctx->default_verify_mode;
	s->verify_callback=ctx->default_verify_callback;
	CRYPTO_add(&ctx->references,1,CRYPTO_LOCK_SSL_CTX);
	s->ctx=ctx;

	s->verify_result=X509_V_OK;

	s->method=ctx->method;

	if (!s->method->ssl_new(s))
		{
		SSL_CTX_free(ctx);
		Free(s);
		goto err;
		}

	s->quiet_shutdown=ctx->quiet_shutdown;
	s->references=1;
	s->options=ctx->options;
	SSL_clear(s);

	CRYPTO_new_ex_data(ssl_meth,(char *)s,&s->ex_data);

	return(s);
err:
	SSLerr(SSL_F_SSL_NEW,ERR_R_MALLOC_FAILURE);
	return(NULL);
	}

void SSL_free(s)
SSL *s;
	{
	int i;

	i=CRYPTO_add(&s->references,-1,CRYPTO_LOCK_SSL);
#ifdef REF_PRINT
	REF_PRINT("SSL",s);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"SSL_free, bad reference count\n");
		abort(); /* ok */
		}
#endif

	CRYPTO_free_ex_data(ssl_meth,(char *)s,&s->ex_data);

	if (s->bbio != NULL)
		{
		/* If the buffering BIO is in place, pop it off */
		if (s->bbio == s->wbio)
			{
			s->wbio=BIO_pop(s->wbio);
			}
		BIO_free(s->bbio);
		s->bbio=NULL;
		}
	if (s->rbio != NULL)
		BIO_free_all(s->rbio);
	if ((s->wbio != NULL) && (s->wbio != s->rbio))
		BIO_free_all(s->wbio);

	if (s->init_buf != NULL) BUF_MEM_free(s->init_buf);

	/* add extra stuff */
	if (s->cipher_list != NULL) sk_free(s->cipher_list);
	if (s->cipher_list_by_id != NULL) sk_free(s->cipher_list_by_id);

	/* Make the next call work :-) */
	if (s->session != NULL)
		{
		ssl_clear_bad_session(s);
		SSL_SESSION_free(s->session);
		}

	ssl_clear_cipher_ctx(s);

	if (s->cert != NULL) ssl_cert_free(s->cert);
	/* Free up if allocated */

	if (s->ctx) SSL_CTX_free(s->ctx);

	if (s->client_CA != NULL)
		sk_pop_free(s->client_CA,X509_NAME_free);

	if (s->method != NULL) s->method->ssl_free(s);

	Free((char *)s);
	}

void SSL_set_bio(s, rbio,wbio)
SSL *s;
BIO *rbio;
BIO *wbio;
	{
	/* If the output buffering BIO is still in place, remove it
	 */
	if (s->bbio != NULL)
		{
		if (s->wbio == s->bbio)
			{
			s->wbio=s->wbio->next_bio;
			s->bbio->next_bio=NULL;
			}
		}
	if ((s->rbio != NULL) && (s->rbio != rbio))
		BIO_free_all(s->rbio);
	if ((s->wbio != NULL) && (s->wbio != wbio) && (s->rbio != s->wbio))
		BIO_free_all(s->wbio);
	s->rbio=rbio;
	s->wbio=wbio;
	}

BIO *SSL_get_rbio(s)
SSL *s;
	{ return(s->rbio); }

BIO *SSL_get_wbio(s)
SSL *s;
	{ return(s->wbio); }

int SSL_get_fd(s)
SSL *s;
	{
	int ret= -1;
	BIO *b,*r;

	b=SSL_get_rbio(s);
	r=BIO_find_type(b,BIO_TYPE_DESCRIPTOR);
	if (r != NULL)
		BIO_get_fd(r,&ret);
	return(ret);
	}

#ifndef NO_SOCK
int SSL_set_fd(s, fd)
SSL *s;
int fd;
	{
	int ret=0;
	BIO *bio=NULL;

	bio=BIO_new(BIO_s_socket());

	if (bio == NULL)
		{
		SSLerr(SSL_F_SSL_SET_FD,ERR_R_BUF_LIB);
		goto err;
		}
	BIO_set_fd(bio,fd,BIO_NOCLOSE);
	SSL_set_bio(s,bio,bio);
	ret=1;
err:
	return(ret);
	}

int SSL_set_wfd(s, fd)
SSL *s;
int fd;
	{
	int ret=0;
	BIO *bio=NULL;

	if ((s->rbio == NULL) || (BIO_method_type(s->rbio) != BIO_TYPE_SOCKET)
		|| ((int)BIO_get_fd(s->rbio,NULL) != fd))
		{
		bio=BIO_new(BIO_s_socket());

		if (bio == NULL)
			{ SSLerr(SSL_F_SSL_SET_WFD,ERR_R_BUF_LIB); goto err; }
		BIO_set_fd(bio,fd,BIO_NOCLOSE);
		SSL_set_bio(s,SSL_get_rbio(s),bio);
		}
	else
		SSL_set_bio(s,SSL_get_rbio(s),SSL_get_rbio(s));
	ret=1;
err:
	return(ret);
	}

int SSL_set_rfd(s, fd)
SSL *s;
int fd;
	{
	int ret=0;
	BIO *bio=NULL;

	if ((s->wbio == NULL) || (BIO_method_type(s->wbio) != BIO_TYPE_SOCKET)
		|| ((int)BIO_get_fd(s->wbio,NULL) != fd))
		{
		bio=BIO_new(BIO_s_socket());

		if (bio == NULL)
			{
			SSLerr(SSL_F_SSL_SET_RFD,ERR_R_BUF_LIB);
			goto err;
			}
		BIO_set_fd(bio,fd,BIO_NOCLOSE);
		SSL_set_bio(s,bio,SSL_get_wbio(s));
		}
	else
		SSL_set_bio(s,SSL_get_wbio(s),SSL_get_wbio(s));
	ret=1;
err:
	return(ret);
	}
#endif

int SSL_get_verify_mode(s)
SSL *s;
	{
	return(s->verify_mode);
	}

int (*SSL_get_verify_callback(s))()
SSL *s;
	{
	return(s->verify_callback);
	}

int SSL_CTX_get_verify_mode(ctx)
SSL_CTX *ctx;
	{
	return(ctx->default_verify_mode);
	}

int (*SSL_CTX_get_verify_callback(ctx))()
SSL_CTX *ctx;
	{
	return(ctx->default_verify_callback);
	}

void SSL_set_verify(s, mode, callback)
SSL *s;
int mode;
int (*callback)();
	{
	s->verify_mode=mode;
	if (callback != NULL)
		s->verify_callback=callback;
	}

void SSL_set_read_ahead(s, yes)
SSL *s;
int yes;
	{
	s->read_ahead=yes;
	}

int SSL_get_read_ahead(s)
SSL *s;
	{
	return(s->read_ahead);
	}

int SSL_pending(s)
SSL *s;
	{
	return(s->method->ssl_pending(s));
	}

X509 *SSL_get_peer_certificate(s)
SSL *s;
	{
	X509 *r;
	
	if ((s == NULL) || (s->session == NULL))
		r=NULL;
	else
		r=s->session->peer;

	if (r == NULL) return(r);

	CRYPTO_add(&r->references,1,CRYPTO_LOCK_X509);

	return(r);
	}

STACK *SSL_get_peer_cert_chain(s)
SSL *s;
	{
	STACK *r;
	
	if ((s == NULL) || (s->session == NULL) || (s->session->cert == NULL))
		r=NULL;
	else
		r=s->session->cert->cert_chain;

	return(r);
	}

/* Now in theory, since the calling process own 't' it should be safe to
 * modify.  We need to be able to read f without being hassled */
void SSL_copy_session_id(t,f)
SSL *t,*f;
	{
	CERT *tmp;

	/* Do we need to to SSL locking? */
	SSL_set_session(t,SSL_get_session(f));

	/* what if we are setup as SSLv2 but want to talk SSLv3 or
	 * vice-versa */
	if (t->method != f->method)
		{
		t->method->ssl_free(t);	/* cleanup current */
		t->method=f->method;	/* change method */
		t->method->ssl_new(t);	/* setup new */
		}

	tmp=t->cert;
	if (f->cert != NULL)
		{
		CRYPTO_add(&f->cert->references,1,CRYPTO_LOCK_SSL_CERT);
		t->cert=f->cert;
		}
	else
		t->cert=NULL;
	if (tmp != NULL) ssl_cert_free(tmp);
	}

/* Fix this so it checks all the valid key/cert options */
int SSL_CTX_check_private_key(ctx)
SSL_CTX *ctx;
	{
	if (	(ctx == NULL) ||
		(ctx->default_cert == NULL) ||
		(ctx->default_cert->key->x509 == NULL))
		{
		SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY,SSL_R_NO_CERTIFICATE_ASSIGNED);
		return(0);
		}
	if 	(ctx->default_cert->key->privatekey == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY,SSL_R_NO_PRIVATE_KEY_ASSIGNED);
		return(0);
		}
	return(X509_check_private_key(ctx->default_cert->key->x509, ctx->default_cert->key->privatekey));
	}

/* Fix this function so that it takes an optional type parameter */
int SSL_check_private_key(ssl)
SSL *ssl;
	{
	if (ssl == NULL)
		{
		SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if (ssl->cert == NULL)
		return(SSL_CTX_check_private_key(ssl->ctx));
	if (ssl->cert->key->x509 == NULL)
		{
		SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY,SSL_R_NO_CERTIFICATE_ASSIGNED);
		return(0);
		}
	if (ssl->cert->key->privatekey == NULL)
		{
		SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY,SSL_R_NO_PRIVATE_KEY_ASSIGNED);
		return(0);
		}
	return(X509_check_private_key(ssl->cert->key->x509,
		ssl->cert->key->privatekey));
	}

int SSL_accept(s)
SSL *s;
	{
	return(s->method->ssl_accept(s));
	}

int SSL_connect(s)
SSL *s;
	{
	return(s->method->ssl_connect(s));
	}

long SSL_get_default_timeout(s)
SSL *s;
	{
	return(s->method->get_timeout());
	}

int SSL_read(s,buf,num)
SSL *s;
char *buf;
int num;
	{
	if (s->shutdown & SSL_RECEIVED_SHUTDOWN)
		{
		s->rwstate=SSL_NOTHING;
		return(0);
		}
	return(s->method->ssl_read(s,buf,num));
	}

int SSL_peek(s,buf,num)
SSL *s;
char *buf;
int num;
	{
	if (s->shutdown & SSL_RECEIVED_SHUTDOWN)
		{
		return(0);
		}
	return(s->method->ssl_peek(s,buf,num));
	}

int SSL_write(s,buf,num)
SSL *s;
char *buf;
int num;
	{
	if (s->shutdown & SSL_SENT_SHUTDOWN)
		{
		s->rwstate=SSL_NOTHING;
		SSLerr(SSL_F_SSL_WRITE,SSL_R_PROTOCOL_IS_SHUTDOWN);
		return(-1);
		}
	return(s->method->ssl_write(s,buf,num));
	}

int SSL_shutdown(s)
SSL *s;
	{
	if ((s != NULL) && !SSL_in_init(s))
		return(s->method->ssl_shutdown(s));
	else
		return(1);
	}

int SSL_renegotiate(s)
SSL *s;
	{
	s->new_session=1;
	return(s->method->ssl_renegotiate(s));
	}

long SSL_ctrl(s,cmd,larg,parg)
SSL *s;
int cmd;
long larg;
char *parg;
	{
	return(s->method->ssl_ctrl(s,cmd,larg,parg));
	}

long SSL_CTX_ctrl(ctx,cmd,larg,parg)
SSL_CTX *ctx;
int cmd;
long larg;
char *parg;
	{
	return(ctx->method->ssl_ctx_ctrl(ctx,cmd,larg,parg));
	}

int ssl_cipher_id_cmp(a,b)
SSL_CIPHER *a,*b;
	{
	long l;

	l=a->id-b->id;
	if (l == 0L)
		return(0);
	else
		return((l > 0)?1:-1);
	}

int ssl_cipher_ptr_id_cmp(ap,bp)
SSL_CIPHER **ap,**bp;
	{
	long l;

	l=(*ap)->id-(*bp)->id;
	if (l == 0L)
		return(0);
	else
		return((l > 0)?1:-1);
	}

/* return a STACK of the ciphers available for the SSL and in order of
 * preference */
STACK *SSL_get_ciphers(s)
SSL *s;
	{
	if ((s != NULL) && (s->cipher_list != NULL))
		{
		return(s->cipher_list);
		}
	else if ((s->ctx != NULL) &&
		(s->ctx->cipher_list != NULL))
		{
		return(s->ctx->cipher_list);
		}
	return(NULL);
	}

/* return a STACK of the ciphers available for the SSL and in order of
 * algorithm id */
STACK *ssl_get_ciphers_by_id(s)
SSL *s;
	{
	if ((s != NULL) && (s->cipher_list_by_id != NULL))
		{
		return(s->cipher_list_by_id);
		}
	else if ((s != NULL) && (s->ctx != NULL) &&
		(s->ctx->cipher_list_by_id != NULL))
		{
		return(s->ctx->cipher_list_by_id);
		}
	return(NULL);
	}

/* The old interface to get the same thing as SSL_get_ciphers() */
char *SSL_get_cipher_list(s,n)
SSL *s;
int n;
	{
	SSL_CIPHER *c;
	STACK *sk;

	if (s == NULL) return(NULL);
	sk=SSL_get_ciphers(s);
	if ((sk == NULL) || (sk_num(sk) <= n))
		return(NULL);
	c=(SSL_CIPHER *)sk_value(sk,n);
	if (c == NULL) return(NULL);
	return(c->name);
	}

/* specify the ciphers to be used by defaut by the SSL_CTX */
int SSL_CTX_set_cipher_list(ctx,str)
SSL_CTX *ctx;
char *str;
	{
	STACK *sk;
	
	sk=ssl_create_cipher_list(ctx->method,&ctx->cipher_list,
		&ctx->cipher_list_by_id,str);
/* XXXX */
	return((sk == NULL)?0:1);
	}

/* specify the ciphers to be used by the SSL */
int SSL_set_cipher_list(s, str)
SSL *s;
char *str;
	{
	STACK *sk;
	
	sk=ssl_create_cipher_list(s->ctx->method,&s->cipher_list,
		&s->cipher_list_by_id,str);
/* XXXX */
	return((sk == NULL)?0:1);
	}

/* works well for SSLv2, not so good for SSLv3 */
char *SSL_get_shared_ciphers(s,buf,len)
SSL *s;
char *buf;
int len;
	{
	char *p,*cp;
	STACK *sk;
	SSL_CIPHER *c;
	int i;

	if ((s->session == NULL) || (s->session->ciphers == NULL) ||
		(len < 2))
		return(NULL);

	p=buf;
	sk=s->session->ciphers;
	for (i=0; i<sk_num(sk); i++)
		{
		/* Decrement for either the ':' or a '\0' */
		len--;
		c=(SSL_CIPHER *)sk_value(sk,i);
		for (cp=c->name; *cp; )
			{
			if (len-- == 0)
				{
				*p='\0';
				return(buf);
				}
			else
				*(p++)= *(cp++);
			}
		*(p++)=':';
		}
	p[-1]='\0';
	return(buf);
	}

int ssl_cipher_list_to_bytes(s,sk,p)
SSL *s;
STACK *sk;
unsigned char *p;
	{
	int i,j=0;
	SSL_CIPHER *c;
	unsigned char *q;

	if (sk == NULL) return(0);
	q=p;

	for (i=0; i<sk_num(sk); i++)
		{
		c=(SSL_CIPHER *)sk_value(sk,i);
		j=ssl_put_cipher_by_char(s,c,p);
		p+=j;
		}
	return(p-q);
	}

STACK *ssl_bytes_to_cipher_list(s,p,num,skp)
SSL *s;
unsigned char *p;
int num;
STACK **skp;
	{
	SSL_CIPHER *c;
	STACK *sk;
	int i,n;

	n=ssl_put_cipher_by_char(s,NULL,NULL);
	if ((num%n) != 0)
		{
		SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST);
		return(NULL);
		}
	if ((skp == NULL) || (*skp == NULL))
		sk=sk_new(NULL); /* change perhaps later */
	else
		{
		sk= *skp;
		sk_zero(sk);
		}

	for (i=0; i<num; i+=n)
		{
		c=ssl_get_cipher_by_char(s,p);
		p+=n;
		if (c != NULL)
			{
			if (!sk_push(sk,(char *)c))
				{
				SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,ERR_R_MALLOC_FAILURE);
				goto err;
				}
			}
		}

	if (skp != NULL)
		*skp=sk;
	return(sk);
err:
	if ((skp == NULL) || (*skp == NULL))
		sk_free(sk);
	return(NULL);
	}

unsigned long SSL_SESSION_hash(a)
SSL_SESSION *a;
	{
	unsigned long l;

	l=      (a->session_id[0]     )|(a->session_id[1]<< 8L)|
		(a->session_id[2]<<16L)|(a->session_id[3]<<24L);
	return(l);
	}

int SSL_SESSION_cmp(a, b)
SSL_SESSION *a;
SSL_SESSION *b;
	{
	if (a->ssl_version != b->ssl_version)
		return(1);
	if (a->session_id_length != b->session_id_length)
		return(1);
	return(memcmp(a->session_id,b->session_id,a->session_id_length));
	}

SSL_CTX *SSL_CTX_new(meth)
SSL_METHOD *meth;
	{
	SSL_CTX *ret;
	
	if (meth == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_NEW,SSL_R_NULL_SSL_METHOD_PASSED);
		return(NULL);
		}
	ret=(SSL_CTX *)Malloc(sizeof(SSL_CTX));
	if (ret == NULL)
		goto err;

	memset(ret,0,sizeof(SSL_CTX));

	ret->method=meth;

	ret->cert_store=NULL;
	ret->session_cache_mode=SSL_SESS_CACHE_SERVER;
	ret->session_cache_size=SSL_SESSION_CACHE_MAX_SIZE_DEFAULT;
	ret->session_cache_head=NULL;
	ret->session_cache_tail=NULL;

	/* We take the system default */
	ret->session_timeout=meth->get_timeout();

	ret->new_session_cb=NULL;
	ret->remove_session_cb=NULL;
	ret->get_session_cb=NULL;

	ret->sess_connect=0;
	ret->sess_connect_good=0;
	ret->sess_accept=0;
	ret->sess_accept_renegotiate=0;
	ret->sess_connect_renegotiate=0;
	ret->sess_accept_good=0;
	ret->sess_miss=0;
	ret->sess_timeout=0;
	ret->sess_cache_full=0;
	ret->sess_hit=0;
	ret->sess_cb_hit=0;

	ret->references=1;
	ret->quiet_shutdown=0;

/*	ret->cipher=NULL;*/
/*	ret->s2->challenge=NULL;
	ret->master_key=NULL;
	ret->key_arg=NULL;
	ret->s2->conn_id=NULL; */

	ret->info_callback=NULL;

	ret->app_verify_callback=NULL;
	ret->app_verify_arg=NULL;

	ret->default_read_ahead=0;
	ret->default_verify_mode=SSL_VERIFY_NONE;
	ret->default_verify_callback=NULL;
	if ((ret->default_cert=ssl_cert_new()) == NULL)
		goto err;

	ret->default_passwd_callback=NULL;
	ret->client_cert_cb=NULL;

	ret->sessions=lh_new(SSL_SESSION_hash,SSL_SESSION_cmp);
	if (ret->sessions == NULL) goto err;
	ret->cert_store=X509_STORE_new();
	if (ret->cert_store == NULL) goto err;

	ssl_create_cipher_list(ret->method,
		&ret->cipher_list,&ret->cipher_list_by_id,
		SSL_DEFAULT_CIPHER_LIST);
	if ((ret->cipher_list == NULL) || (sk_num(ret->cipher_list) <= 0))
		{
		SSLerr(SSL_F_SSL_CTX_NEW,SSL_R_LIBRARY_HAS_NO_CIPHERS);
		goto err2;
		}

	if ((ret->rsa_md5=EVP_get_digestbyname("ssl2-md5")) == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_NEW,SSL_R_UNABLE_TO_LOAD_SSL2_MD5_ROUTINES);
		goto err2;
		}
	if ((ret->md5=EVP_get_digestbyname("ssl3-md5")) == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_NEW,SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES);
		goto err2;
		}
	if ((ret->sha1=EVP_get_digestbyname("ssl3-sha1")) == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_NEW,SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES);
		goto err2;
		}

	if ((ret->client_CA=sk_new_null()) == NULL)
		goto err;

	CRYPTO_new_ex_data(ssl_ctx_meth,(char *)ret,&ret->ex_data);

	return(ret);
err:
	SSLerr(SSL_F_SSL_CTX_NEW,ERR_R_MALLOC_FAILURE);
err2:
	if (ret != NULL) SSL_CTX_free(ret);
	return(NULL);
	}

void SSL_CTX_free(a)
SSL_CTX *a;
	{
	int i;

	if (a == NULL) return;

	i=CRYPTO_add(&a->references,-1,CRYPTO_LOCK_SSL_CTX);
#ifdef REF_PRINT
	REF_PRINT("SSL_CTX",a);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"SSL_CTX_free, bad reference count\n");
		abort(); /* ok */
		}
#endif
	CRYPTO_free_ex_data(ssl_ctx_meth,(char *)a,&a->ex_data);

	if (a->sessions != NULL)
		{
		SSL_CTX_flush_sessions(a,0);
		lh_free(a->sessions);
		}
	if (a->cert_store != NULL)
		X509_STORE_free(a->cert_store);
	if (a->cipher_list != NULL)
		sk_free(a->cipher_list);
	if (a->cipher_list_by_id != NULL)
		sk_free(a->cipher_list_by_id);
	if (a->default_cert != NULL)
		ssl_cert_free(a->default_cert);
	if (a->client_CA != NULL)
		sk_pop_free(a->client_CA,X509_NAME_free);
	Free((char *)a);
	}

void SSL_CTX_set_default_passwd_cb(ctx,cb)
SSL_CTX *ctx;
int (*cb)();
	{
	ctx->default_passwd_callback=cb;
	}

void SSL_CTX_set_cert_verify_cb(ctx,cb,arg)
SSL_CTX *ctx;
int (*cb)();
char *arg;
	{
	ctx->app_verify_callback=cb;
	ctx->app_verify_arg=arg;
	}

void SSL_CTX_set_verify(ctx,mode,cb)
SSL_CTX *ctx;
int mode;
int (*cb)();
	{
	ctx->default_verify_mode=mode;
	ctx->default_verify_callback=cb;
	/* This needs cleaning up EAY EAY EAY */
	X509_STORE_set_verify_cb_func(ctx->cert_store,cb);
	}

void ssl_set_cert_masks(c)
CERT *c;
	{
	CERT_PKEY *cpk;
	int rsa_enc,rsa_tmp,rsa_sign,dh_tmp,dh_rsa,dh_dsa,dsa_sign;
	int rsa_enc_export,dh_rsa_export,dh_dsa_export;
	int rsa_tmp_export,dh_tmp_export;
	unsigned long mask,emask;

	if ((c == NULL) || (c->valid)) return;

#ifndef NO_RSA
	rsa_tmp=((c->rsa_tmp != NULL) || (c->rsa_tmp_cb != NULL))?1:0;
	rsa_tmp_export=((c->rsa_tmp_cb != NULL) ||
		(rsa_tmp && (RSA_size(c->rsa_tmp)*8 <= 512)))?1:0;
#else
	rsa_tmp=rsa_tmp_export=0;
#endif
#ifndef NO_DH
	dh_tmp=((c->dh_tmp != NULL) || (c->dh_tmp_cb != NULL))?1:0;
	dh_tmp_export=((c->dh_tmp_cb != NULL) ||
		(dh_tmp && (DH_size(c->dh_tmp)*8 <= 512)))?1:0;
#else
	dh_tmp=dh_tmp_export=0;
#endif

	cpk= &(c->pkeys[SSL_PKEY_RSA_ENC]);
	rsa_enc= ((cpk->x509 != NULL) && (cpk->privatekey != NULL))?1:0;
	rsa_enc_export=(rsa_enc && (EVP_PKEY_size(cpk->privatekey)*8 <= 512))?1:0;
	cpk= &(c->pkeys[SSL_PKEY_RSA_SIGN]);
	rsa_sign=((cpk->x509 != NULL) && (cpk->privatekey != NULL))?1:0;
	cpk= &(c->pkeys[SSL_PKEY_DSA_SIGN]);
	dsa_sign=((cpk->x509 != NULL) && (cpk->privatekey != NULL))?1:0;
	cpk= &(c->pkeys[SSL_PKEY_DH_RSA]);
	dh_rsa=  ((cpk->x509 != NULL) && (cpk->privatekey != NULL))?1:0;
	dh_rsa_export=(dh_rsa && (EVP_PKEY_size(cpk->privatekey)*8 <= 512))?1:0;
	cpk= &(c->pkeys[SSL_PKEY_DH_DSA]);
/* FIX THIS EAY EAY EAY */
	dh_dsa=  ((cpk->x509 != NULL) && (cpk->privatekey != NULL))?1:0;
	dh_dsa_export=(dh_dsa && (EVP_PKEY_size(cpk->privatekey)*8 <= 512))?1:0;

	mask=0;
	emask=0;

#ifdef CIPHER_DEBUG
	printf("rt=%d dht=%d re=%d rs=%d ds=%d dhr=%d dhd=%d\n",
		rsa_tmp,dh_tmp,
		rsa_enc,rsa_sign,dsa_sign,dh_rsa,dh_dsa);
#endif

	if (rsa_enc || (rsa_tmp && rsa_sign))
		mask|=SSL_kRSA;
	if (rsa_enc_export || (rsa_tmp_export && rsa_sign))
		emask|=SSL_kRSA;

#if 0
	/* The match needs to be both kEDH and aRSA or aDSA, so don't worry */
	if (	(dh_tmp || dh_rsa || dh_dsa) && 
		(rsa_enc || rsa_sign || dsa_sign))
		mask|=SSL_kEDH;
	if ((dh_tmp_export || dh_rsa_export || dh_dsa_export) &&
		(rsa_enc || rsa_sign || dsa_sign))
		emask|=SSL_kEDH;
#endif

	if (dh_tmp_export) 
		emask|=SSL_kEDH;

	if (dh_tmp)
		mask|=SSL_kEDH;

	if (dh_rsa) mask|=SSL_kDHr;
	if (dh_rsa_export) emask|=SSL_kDHr;

	if (dh_dsa) mask|=SSL_kDHd;
	if (dh_dsa_export) emask|=SSL_kDHd;

	if (rsa_enc || rsa_sign)
		{
		mask|=SSL_aRSA;
		emask|=SSL_aRSA;
		}

	if (dsa_sign)
		{
		mask|=SSL_aDSS;
		emask|=SSL_aDSS;
		}

#ifdef SSL_ALLOW_ADH
	mask|=SSL_aNULL;
	emask|=SSL_aNULL;
#endif

	c->mask=mask;
	c->export_mask=emask;
	c->valid=1;
	}

/* THIS NEEDS CLEANING UP */
X509 *ssl_get_server_send_cert(s)
SSL *s;
	{
	unsigned long alg,mask,kalg;
	CERT *c;
	int i,export;

	c=s->cert;
	ssl_set_cert_masks(c);
	alg=s->s3->tmp.new_cipher->algorithms;
	export=(alg & SSL_EXPORT)?1:0;
	mask=(export)?c->export_mask:c->mask;
	kalg=alg&(SSL_MKEY_MASK|SSL_AUTH_MASK);

	if 	(kalg & SSL_kDHr)
		i=SSL_PKEY_DH_RSA;
	else if (kalg & SSL_kDHd)
		i=SSL_PKEY_DH_DSA;
	else if (kalg & SSL_aDSS)
		i=SSL_PKEY_DSA_SIGN;
	else if (kalg & SSL_aRSA)
		{
		if (c->pkeys[SSL_PKEY_RSA_ENC].x509 == NULL)
			i=SSL_PKEY_RSA_SIGN;
		else
			i=SSL_PKEY_RSA_ENC;
		}
	else /* if (kalg & SSL_aNULL) */
		{
		SSLerr(SSL_F_SSL_GET_SERVER_SEND_CERT,SSL_R_INTERNAL_ERROR);
		return(NULL);
		}
	if (c->pkeys[i].x509 == NULL) return(NULL);
	return(c->pkeys[i].x509);
	}

EVP_PKEY *ssl_get_sign_pkey(s,cipher)
SSL *s;
SSL_CIPHER *cipher;
	{
	unsigned long alg;
	CERT *c;

	alg=cipher->algorithms;
	c=s->cert;

	if ((alg & SSL_aDSS) &&
		(c->pkeys[SSL_PKEY_DSA_SIGN].privatekey != NULL))
		return(c->pkeys[SSL_PKEY_DSA_SIGN].privatekey);
	else if (alg & SSL_aRSA)
		{
		if (c->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL)
			return(c->pkeys[SSL_PKEY_RSA_SIGN].privatekey);
		else if (c->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL)
			return(c->pkeys[SSL_PKEY_RSA_ENC].privatekey);
		else
			return(NULL);
		}
	else /* if (alg & SSL_aNULL) */
		{
		SSLerr(SSL_F_SSL_GET_SIGN_PKEY,SSL_R_INTERNAL_ERROR);
		return(NULL);
		}
	}

void ssl_update_cache(s,mode)
SSL *s;
int mode;
	{
	int i;

	/* If the session_id_length is 0, we are not supposed to cache it,
	 * and it would be rather hard to do anyway :-) */
	if (s->session->session_id_length == 0) return;

	if ((s->ctx->session_cache_mode & mode)
		&& (!s->hit)
		&& SSL_CTX_add_session(s->ctx,s->session)
		&& (s->ctx->new_session_cb != NULL))
		{
		CRYPTO_add(&s->session->references,1,CRYPTO_LOCK_SSL_SESSION);
		if (!s->ctx->new_session_cb(s,s->session))
			SSL_SESSION_free(s->session);
		}

	/* auto flush every 255 connections */
	i=s->ctx->session_cache_mode;
	if ((!(i & SSL_SESS_CACHE_NO_AUTO_CLEAR)) &&
		((i & mode) == mode))
		{
		if (  (((mode & SSL_SESS_CACHE_CLIENT)
			?s->ctx->sess_connect_good
			:s->ctx->sess_accept_good) & 0xff) == 0xff)
			{
			SSL_CTX_flush_sessions(s->ctx,time(NULL));
			}
		}
	}

SSL_METHOD *SSL_get_ssl_method(s)
SSL *s;
	{
	return(s->method);
	}

int SSL_set_ssl_method(s,meth)
SSL *s;
SSL_METHOD *meth;
	{
	int conn= -1;
	int ret=1;

	if (s->method != meth)
		{
		if (s->handshake_func != NULL)
			conn=(s->handshake_func == s->method->ssl_connect);

		if (s->method->version == meth->version)
			s->method=meth;
		else
			{
			s->method->ssl_free(s);
			s->method=meth;
			ret=s->method->ssl_new(s);
			}

		if (conn == 1)
			s->handshake_func=meth->ssl_connect;
		else if (conn == 0)
			s->handshake_func=meth->ssl_accept;
		}
	return(ret);
	}

int SSL_get_error(s,i)
SSL *s;
int i;
	{
	int reason;
	BIO *bio;

	if (i > 0) return(SSL_ERROR_NONE);

	if (ERR_peek_error() != 0)
		return(SSL_ERROR_SSL);

	if ((i < 0) && SSL_want_read(s))
		{
		bio=SSL_get_rbio(s);
		if (BIO_should_read(bio))
			return(SSL_ERROR_WANT_READ);
		else if (BIO_should_write(bio))
			return(SSL_ERROR_WANT_WRITE);
		else if (BIO_should_io_special(bio))
			{
			reason=BIO_get_retry_reason(bio);
			if (reason == BIO_RR_CONNECT)
				return(SSL_ERROR_WANT_CONNECT);
			else
				return(SSL_ERROR_SYSCALL); /* unknown */
			}
		}

	if ((i < 0) && SSL_want_write(s))
		{
		bio=SSL_get_wbio(s);
		if (BIO_should_write(bio))
			return(SSL_ERROR_WANT_WRITE);
		else if (BIO_should_read(bio))
			return(SSL_ERROR_WANT_READ);
		else if (BIO_should_io_special(bio))
			{
			reason=BIO_get_retry_reason(bio);
			if (reason == BIO_RR_CONNECT)
				return(SSL_ERROR_WANT_CONNECT);
			else
				return(SSL_ERROR_SYSCALL);
			}
		}
	if ((i < 0) && SSL_want_x509_lookup(s))
		{
		return(SSL_ERROR_WANT_X509_LOOKUP);
		}

	if (i == 0)
		{
		if (s->version == SSL2_VERSION)
			{
			/* assume it is the socket being closed */
			return(SSL_ERROR_ZERO_RETURN);
			}
		else
			{
			if ((s->shutdown & SSL_RECEIVED_SHUTDOWN) &&
				(s->s3->warn_alert == SSL_AD_CLOSE_NOTIFY))
				return(SSL_ERROR_ZERO_RETURN);
			}
		}
	return(SSL_ERROR_SYSCALL);
	}

int SSL_do_handshake(s)
SSL *s;
	{
	int ret=1;

	if (s->handshake_func == NULL)
		{
		SSLerr(SSL_F_SSL_DO_HANDSHAKE,SSL_R_CONNECTION_TYPE_NOT_SET);
		return(-1);
		}
	if (s->s3->renegotiate) ssl3_renegotiate_check(s);
	if (SSL_in_init(s) || SSL_in_before(s))
		{
		ret=s->handshake_func(s);
		}
	return(ret);
	}

/* For the next 2 functions, SSL_clear() sets shutdown and so
 * one of these calls will reset it */
void SSL_set_accept_state(s)
SSL *s;
	{
	s->shutdown=0;
	s->state=SSL_ST_ACCEPT|SSL_ST_BEFORE;
	s->handshake_func=s->method->ssl_accept;
	/* clear the current cipher */
	ssl_clear_cipher_ctx(s);
	}

void SSL_set_connect_state(s)
SSL *s;
	{
	s->shutdown=0;
	s->state=SSL_ST_CONNECT|SSL_ST_BEFORE;
	s->handshake_func=s->method->ssl_connect;
	/* clear the current cipher */
	ssl_clear_cipher_ctx(s);
	}

int ssl_undefined_function(s)
SSL *s;
	{
	SSLerr(SSL_F_SSL_UNDEFINED_FUNCTION,ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
	return(0);
	}

SSL_METHOD *ssl_bad_method(ver)
int ver;
	{
	SSLerr(SSL_F_SSL_BAD_METHOD,ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
	return(NULL);
	}

char *SSL_get_version(s)
SSL *s;
	{
	if (s->version == TLS1_VERSION)
		return("TLSv1");
	else if (s->version == SSL3_VERSION)
		return("SSLv3");
	else if (s->version == SSL2_VERSION)
		return("SSLv2");
	else
		return("unknown");
	}

SSL *SSL_dup(s)
SSL *s;
        {
	STACK *sk;
	X509_NAME *xn;
        SSL *ret;
	int i;
		 
	if ((ret=SSL_new(SSL_get_SSL_CTX(s))) == NULL) return(NULL);
			  
	/* This copies version, session-id, SSL_METHOD and 'cert' */
	SSL_copy_session_id(ret,s);

	SSL_set_read_ahead(ret,SSL_get_read_ahead(s));
	SSL_set_verify(ret,SSL_get_verify_mode(s),
		SSL_get_verify_callback(s));

	SSL_set_info_callback(ret,SSL_get_info_callback(s));
	
	ret->debug=s->debug;
	ret->options=s->options;

	/* copy app data, a little dangerous perhaps */
	if (!CRYPTO_dup_ex_data(ssl_meth,&ret->ex_data,&s->ex_data))
		goto err;

	/* setup rbio, and wbio */
	if (s->rbio != NULL)
		{
		if (!BIO_dup_state(s->rbio,(char *)&ret->rbio))
			goto err;
		}
	if (s->wbio != NULL)
		{
		if (s->wbio != s->rbio)
			{
			if (!BIO_dup_state(s->wbio,(char *)&ret->wbio))
				goto err;
			}
		else
			ret->wbio=ret->rbio;
		}

	/* dup the cipher_list and cipher_list_by_id stacks */
	if (s->cipher_list != NULL)
		{
		if ((ret->cipher_list=sk_dup(s->cipher_list)) == NULL)
			goto err;
		}
	if (s->cipher_list_by_id != NULL)
		if ((ret->cipher_list_by_id=sk_dup(s->cipher_list_by_id))
			== NULL)
			goto err;

	/* Dup the client_CA list */
	if (s->client_CA != NULL)
		{
		if ((sk=sk_dup(s->client_CA)) == NULL) goto err;
		ret->client_CA=sk;
		for (i=0; i<sk_num(sk); i++)
			{
			xn=(X509_NAME *)sk_value(sk,i);
			if ((sk_value(sk,i)=(char *)X509_NAME_dup(xn)) == NULL)
				{
				X509_NAME_free(xn);
				goto err;
				}
			}
		}

	ret->shutdown=s->shutdown;
	ret->state=s->state;
	ret->handshake_func=s->handshake_func;

	if (0)
		{
err:
		if (ret != NULL) SSL_free(ret);
		ret=NULL;
		}
	return(ret);
	}

void ssl_clear_cipher_ctx(s)
SSL *s;
	{
        if (s->enc_read_ctx != NULL)
                {
                EVP_CIPHER_CTX_cleanup(s->enc_read_ctx);
                Free(s->enc_read_ctx);
                s->enc_read_ctx=NULL;
                }
        if (s->enc_write_ctx != NULL)
                {
                EVP_CIPHER_CTX_cleanup(s->enc_write_ctx);
                Free(s->enc_write_ctx);
                s->enc_write_ctx=NULL;
                }
	}

/* Fix this function so that it takes an optional type parameter */
X509 *SSL_get_certificate(s)
SSL *s;
	{
	if (s->cert != NULL)
		return(s->cert->key->x509);
	else
		return(NULL);
	}

/* Fix this function so that it takes an optional type parameter */
EVP_PKEY *SSL_get_privatekey(s)
SSL *s;
	{
	if (s->cert != NULL)
		return(s->cert->key->privatekey);
	else
		return(NULL);
	}

SSL_CIPHER *SSL_get_current_cipher(s)
SSL *s;
	{
        if ((s->session != NULL) && (s->session->cipher != NULL))
                return(s->session->cipher);
        return(NULL);
	}

int ssl_init_wbio_buffer(s,push)
SSL *s;
int push;
	{
	BIO *bbio;

	if (s->bbio == NULL)
		{
		bbio=BIO_new(BIO_f_buffer());
		if (bbio == NULL) return(0);
		s->bbio=bbio;
		}
	else
		{
		bbio=s->bbio;
		if (s->bbio == s->wbio)
			s->wbio=BIO_pop(s->wbio);
		}
	BIO_reset(bbio);
/*	if (!BIO_set_write_buffer_size(bbio,16*1024)) */
	if (!BIO_set_read_buffer_size(bbio,1))
		{
		SSLerr(SSL_F_SSL_INIT_WBIO_BUFFER,ERR_R_BUF_LIB);
		return(0);
		}
	if (push)
		{
		if (s->wbio != bbio)
			s->wbio=BIO_push(bbio,s->wbio);
		}
	else
		{
		if (s->wbio == bbio)
			s->wbio=BIO_pop(bbio);
		}
	return(1);
	}
	
void SSL_CTX_set_quiet_shutdown(ctx,mode)
SSL_CTX *ctx;
int mode;
	{
	ctx->quiet_shutdown=mode;
	}

int SSL_CTX_get_quiet_shutdown(ctx)
SSL_CTX *ctx;
	{
	return(ctx->quiet_shutdown);
	}

void SSL_set_quiet_shutdown(s,mode)
SSL *s;
int mode;
	{
	s->quiet_shutdown=mode;
	}

int SSL_get_quiet_shutdown(s)
SSL *s;
	{
	return(s->quiet_shutdown);
	}

void SSL_set_shutdown(s,mode)
SSL *s;
int mode;
	{
	s->shutdown=mode;
	}

int SSL_get_shutdown(s)
SSL *s;
	{
	return(s->shutdown);
	}

int SSL_version(s)
SSL *s;
	{
	return(s->version);
	}

SSL_CTX *SSL_get_SSL_CTX(ssl)
SSL *ssl;
	{
	return(ssl->ctx);
	}

int SSL_CTX_set_default_verify_paths(ctx)
SSL_CTX *ctx;
	{
	return(X509_STORE_set_default_paths(ctx->cert_store));
	}

int SSL_CTX_load_verify_locations(ctx,CAfile,CApath)
SSL_CTX *ctx;
char *CAfile;
char *CApath;
	{
	return(X509_STORE_load_locations(ctx->cert_store,CAfile,CApath));
	}

void SSL_set_info_callback(ssl,cb)
SSL *ssl;
void (*cb)();
	{
	ssl->info_callback=cb;
	}

void (*SSL_get_info_callback(ssl))()
SSL *ssl;
	{
	return(ssl->info_callback);
	}

int SSL_state(ssl)
SSL *ssl;
	{
	return(ssl->state);
	}

void SSL_set_verify_result(ssl,arg)
SSL *ssl;
long arg;
	{
	ssl->verify_result=arg;
	}

long SSL_get_verify_result(ssl)
SSL *ssl;
	{
	return(ssl->verify_result);
	}

int SSL_get_ex_new_index(argl,argp,new_func,dup_func,free_func)
long argl;
char *argp;
int (*new_func)();
int (*dup_func)();
void (*free_func)();
        {
	ssl_meth_num++;
	return(CRYPTO_get_ex_new_index(ssl_meth_num-1,
		&ssl_meth,argl,argp,new_func,dup_func,free_func));
        }

int SSL_set_ex_data(s,idx,arg)
SSL *s;
int idx;
char *arg;
	{
	return(CRYPTO_set_ex_data(&s->ex_data,idx,arg));
	}

char *SSL_get_ex_data(s,idx)
SSL *s;
int idx;
	{
	return(CRYPTO_get_ex_data(&s->ex_data,idx));
	}

int SSL_CTX_get_ex_new_index(argl,argp,new_func,dup_func,free_func)
long argl;
char *argp;
int (*new_func)();
int (*dup_func)();
void (*free_func)();
        {
	ssl_ctx_meth_num++;
	return(CRYPTO_get_ex_new_index(ssl_ctx_meth_num-1,
		&ssl_ctx_meth,argl,argp,new_func,dup_func,free_func));
        }

int SSL_CTX_set_ex_data(s,idx,arg)
SSL_CTX *s;
int idx;
char *arg;
	{
	return(CRYPTO_set_ex_data(&s->ex_data,idx,arg));
	}

char *SSL_CTX_get_ex_data(s,idx)
SSL_CTX *s;
int idx;
	{
	return(CRYPTO_get_ex_data(&s->ex_data,idx));
	}

#if defined(_WINDLL) && defined(WIN16)
#include "../crypto/bio/bss_file.c"
#endif

