/* ssl/ssl_sess.c */
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
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include "ssl_locl.h"

static void SSL_SESSION_list_remove(SSL_CTX *ctx, SSL_SESSION *s);
static void SSL_SESSION_list_add(SSL_CTX *ctx,SSL_SESSION *s);
static int remove_session_lock(SSL_CTX *ctx, SSL_SESSION *c, int lck);
static int ssl_session_num=0;
static STACK_OF(CRYPTO_EX_DATA_FUNCS) *ssl_session_meth=NULL;

SSL_SESSION *SSL_get_session(SSL *ssl)
/* aka SSL_get0_session; gets 0 objects, just returns a copy of the pointer */
	{
	return(ssl->session);
	}

SSL_SESSION *SSL_get1_session(SSL *ssl)
/* variant of SSL_get_session: caller really gets something */
	{
	SSL_SESSION *sess;
	/* Need to lock this all up rather than just use CRYPTO_add so that
	 * somebody doesn't free ssl->session between when we check it's
	 * non-null and when we up the reference count. */
	CRYPTO_r_lock(CRYPTO_LOCK_SSL_SESSION);
	sess = ssl->session;
	if(sess)
		sess->references++;
	CRYPTO_r_unlock(CRYPTO_LOCK_SSL_SESSION);
	return(sess);
	}

int SSL_SESSION_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	     CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
	{
	ssl_session_num++;
	return(CRYPTO_get_ex_new_index(ssl_session_num-1,
		&ssl_session_meth,
		argl,argp,new_func,dup_func,free_func));
	}

int SSL_SESSION_set_ex_data(SSL_SESSION *s, int idx, void *arg)
	{
	return(CRYPTO_set_ex_data(&s->ex_data,idx,arg));
	}

void *SSL_SESSION_get_ex_data(SSL_SESSION *s, int idx)
	{
	return(CRYPTO_get_ex_data(&s->ex_data,idx));
	}

SSL_SESSION *SSL_SESSION_new(void)
	{
	SSL_SESSION *ss;

	ss=(SSL_SESSION *)OPENSSL_malloc(sizeof(SSL_SESSION));
	if (ss == NULL)
		{
		SSLerr(SSL_F_SSL_SESSION_NEW,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	memset(ss,0,sizeof(SSL_SESSION));

	ss->verify_result = 1; /* avoid 0 (= X509_V_OK) just in case */
	ss->references=1;
	ss->timeout=60*5+4; /* 5 minute timeout by default */
	ss->time=time(NULL);
	ss->prev=NULL;
	ss->next=NULL;
	ss->compress_meth=0;
	CRYPTO_new_ex_data(ssl_session_meth,ss,&ss->ex_data);
	return(ss);
	}

int ssl_get_new_session(SSL *s, int session)
	{
	/* This gets used by clients and servers. */

	SSL_SESSION *ss=NULL;

	if ((ss=SSL_SESSION_new()) == NULL) return(0);

	/* If the context has a default timeout, use it */
	if (s->ctx->session_timeout == 0)
		ss->timeout=SSL_get_default_timeout(s);
	else
		ss->timeout=s->ctx->session_timeout;

	if (s->session != NULL)
		{
		SSL_SESSION_free(s->session);
		s->session=NULL;
		}

	if (session)
		{
		if (s->version == SSL2_VERSION)
			{
			ss->ssl_version=SSL2_VERSION;
			ss->session_id_length=SSL2_SSL_SESSION_ID_LENGTH;
			}
		else if (s->version == SSL3_VERSION)
			{
			ss->ssl_version=SSL3_VERSION;
			ss->session_id_length=SSL3_SSL_SESSION_ID_LENGTH;
			}
		else if (s->version == TLS1_VERSION)
			{
			ss->ssl_version=TLS1_VERSION;
			ss->session_id_length=SSL3_SSL_SESSION_ID_LENGTH;
			}
		else
			{
			SSLerr(SSL_F_SSL_GET_NEW_SESSION,SSL_R_UNSUPPORTED_SSL_VERSION);
			SSL_SESSION_free(ss);
			return(0);
			}

		for (;;)
			{
			SSL_SESSION *r;

			RAND_pseudo_bytes(ss->session_id,ss->session_id_length);
			CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
			r=(SSL_SESSION *)lh_retrieve(s->ctx->sessions, ss);
			CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
			if (r == NULL) break;
			/* else - woops a session_id match */
			/* XXX We should also check the external cache --
			 * but the probability of a collision is negligible, and
			 * we could not prevent the concurrent creation of sessions
			 * with identical IDs since we currently don't have means
			 * to atomically check whether a session ID already exists
			 * and make a reservation for it if it does not
			 * (this problem applies to the internal cache as well).
			 */
			}
		}
	else
		{
		ss->session_id_length=0;
		}

	memcpy(ss->sid_ctx,s->sid_ctx,s->sid_ctx_length);
	ss->sid_ctx_length=s->sid_ctx_length;
	s->session=ss;
	ss->ssl_version=s->version;
	ss->verify_result = X509_V_OK;

	return(1);
	}

int ssl_get_prev_session(SSL *s, unsigned char *session_id, int len)
	{
	/* This is used only by servers. */

	SSL_SESSION *ret=NULL,data;
	int fatal = 0;

	data.ssl_version=s->version;
	data.session_id_length=len;
	if (len > SSL_MAX_SSL_SESSION_ID_LENGTH)
		goto err;
	memcpy(data.session_id,session_id,len);

	if (!(s->ctx->session_cache_mode & SSL_SESS_CACHE_NO_INTERNAL_LOOKUP))
		{
		CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
		ret=(SSL_SESSION *)lh_retrieve(s->ctx->sessions,&data);
		if (ret != NULL)
		    /* don't allow other threads to steal it: */
		    CRYPTO_add(&ret->references,1,CRYPTO_LOCK_SSL_SESSION);
		CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
		}

	if (ret == NULL)
		{
		int copy=1;
	
		s->ctx->stats.sess_miss++;
		ret=NULL;
		if (s->ctx->get_session_cb != NULL
		    && (ret=s->ctx->get_session_cb(s,session_id,len,&copy))
		       != NULL)
			{
			s->ctx->stats.sess_cb_hit++;

			/* Increment reference count now if the session callback
			 * asks us to do so (note that if the session structures
			 * returned by the callback are shared between threads,
			 * it must handle the reference count itself [i.e. copy == 0],
			 * or things won't be thread-safe). */
			if (copy)
				CRYPTO_add(&ret->references,1,CRYPTO_LOCK_SSL_SESSION);

			/* The following should not return 1, otherwise,
			 * things are very strange */
			SSL_CTX_add_session(s->ctx,ret);
			}
		if (ret == NULL)
			goto err;
		}

	/* Now ret is non-NULL, and we own one of its reference counts. */

	if((s->verify_mode&SSL_VERIFY_PEER)
	   && (!s->sid_ctx_length || ret->sid_ctx_length != s->sid_ctx_length
	       || memcmp(ret->sid_ctx,s->sid_ctx,ret->sid_ctx_length)))
	    {
		/* We've found the session named by the client, but we don't
		 * want to use it in this context. */
		
		if (s->sid_ctx_length == 0)
			{
			/* application should have used SSL[_CTX]_set_session_id_context
			 * -- we could tolerate this and just pretend we never heard
			 * of this session, but then applications could effectively
			 * disable the session cache by accident without anyone noticing */

			SSLerr(SSL_F_SSL_GET_PREV_SESSION,SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED);
			fatal = 1;
			goto err;
			}
		else
			{
#if 0 /* The client cannot always know when a session is not appropriate,
	   * so we shouldn't generate an error message. */

			SSLerr(SSL_F_SSL_GET_PREV_SESSION,SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
#endif
			goto err; /* treat like cache miss */
			}
		}

	if (ret->cipher == NULL)
		{
		unsigned char buf[5],*p;
		unsigned long l;

		p=buf;
		l=ret->cipher_id;
		l2n(l,p);
		if ((ret->ssl_version>>8) == SSL3_VERSION_MAJOR)
			ret->cipher=ssl_get_cipher_by_char(s,&(buf[2]));
		else 
			ret->cipher=ssl_get_cipher_by_char(s,&(buf[1]));
		if (ret->cipher == NULL)
			goto err;
		}


#if 0 /* This is way too late. */

	/* If a thread got the session, then 'swaped', and another got
	 * it and then due to a time-out decided to 'OPENSSL_free' it we could
	 * be in trouble.  So I'll increment it now, then double decrement
	 * later - am I speaking rubbish?. */
	CRYPTO_add(&ret->references,1,CRYPTO_LOCK_SSL_SESSION);
#endif

	if ((long)(ret->time+ret->timeout) < (long)time(NULL)) /* timeout */
		{
		s->ctx->stats.sess_timeout++;
		/* remove it from the cache */
		SSL_CTX_remove_session(s->ctx,ret);
		goto err;
		}

	s->ctx->stats.sess_hit++;

	/* ret->time=time(NULL); */ /* rezero timeout? */
	/* again, just leave the session 
	 * if it is the same session, we have just incremented and
	 * then decremented the reference count :-) */
	if (s->session != NULL)
		SSL_SESSION_free(s->session);
	s->session=ret;
	s->verify_result = s->session->verify_result;
	return(1);

 err:
	if (ret != NULL)
		SSL_SESSION_free(ret);
	if (fatal)
		return -1;
	else
		return 0;
	}

int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)
	{
	int ret=0;
	SSL_SESSION *s;

	/* add just 1 reference count for the SSL_CTX's session cache
	 * even though it has two ways of access: each session is in a
	 * doubly linked list and an lhash */
	CRYPTO_add(&c->references,1,CRYPTO_LOCK_SSL_SESSION);
	/* if session c is in already in cache, we take back the increment later */

	CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
	s=(SSL_SESSION *)lh_insert(ctx->sessions,c);
	
	/* s != NULL iff we already had a session with the given PID.
	 * In this case, s == c should hold (then we did not really modify
	 * ctx->sessions), or we're in trouble. */
	if (s != NULL && s != c)
		{
		/* We *are* in trouble ... */
		SSL_SESSION_list_remove(ctx,s);
		SSL_SESSION_free(s);
		/* ... so pretend the other session did not exist in cache
		 * (we cannot handle two SSL_SESSION structures with identical
		 * session ID in the same cache, which could happen e.g. when
		 * two threads concurrently obtain the same session from an external
		 * cache) */
		s = NULL;
		}

 	/* Put at the head of the queue unless it is already in the cache */
	if (s == NULL)
		SSL_SESSION_list_add(ctx,c);

	if (s != NULL)
		{
		/* existing cache entry -- decrement previously incremented reference
		 * count because it already takes into account the cache */

		SSL_SESSION_free(s); /* s == c */
		ret=0;
		}
	else
		{
		/* new cache entry -- remove old ones if cache has become too large */
		
		ret=1;

		if (SSL_CTX_sess_get_cache_size(ctx) > 0)
			{
			while (SSL_CTX_sess_number(ctx) >
				SSL_CTX_sess_get_cache_size(ctx))
				{
				if (!remove_session_lock(ctx,
					ctx->session_cache_tail, 0))
					break;
				else
					ctx->stats.sess_cache_full++;
				}
			}
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
	return(ret);
	}

int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *c)
{
	return remove_session_lock(ctx, c, 1);
}

static int remove_session_lock(SSL_CTX *ctx, SSL_SESSION *c, int lck)
	{
	SSL_SESSION *r;
	int ret=0;

	if ((c != NULL) && (c->session_id_length != 0))
		{
		if(lck) CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
		r=(SSL_SESSION *)lh_delete(ctx->sessions,c);
		if (r != NULL)
			{
			ret=1;
			SSL_SESSION_list_remove(ctx,c);
			}

		if(lck) CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);

		if (ret)
			{
			r->not_resumable=1;
			if (ctx->remove_session_cb != NULL)
				ctx->remove_session_cb(ctx,r);
			SSL_SESSION_free(r);
			}
		}
	else
		ret=0;
	return(ret);
	}

void SSL_SESSION_free(SSL_SESSION *ss)
	{
	int i;

	if(ss == NULL)
	    return;

	i=CRYPTO_add(&ss->references,-1,CRYPTO_LOCK_SSL_SESSION);
#ifdef REF_PRINT
	REF_PRINT("SSL_SESSION",ss);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"SSL_SESSION_free, bad reference count\n");
		abort(); /* ok */
		}
#endif

	CRYPTO_free_ex_data(ssl_session_meth,ss,&ss->ex_data);

	memset(ss->key_arg,0,SSL_MAX_KEY_ARG_LENGTH);
	memset(ss->master_key,0,SSL_MAX_MASTER_KEY_LENGTH);
	memset(ss->session_id,0,SSL_MAX_SSL_SESSION_ID_LENGTH);
	if (ss->sess_cert != NULL) ssl_sess_cert_free(ss->sess_cert);
	if (ss->peer != NULL) X509_free(ss->peer);
	if (ss->ciphers != NULL) sk_SSL_CIPHER_free(ss->ciphers);
	memset(ss,0,sizeof(*ss));
	OPENSSL_free(ss);
	}

int SSL_set_session(SSL *s, SSL_SESSION *session)
	{
	int ret=0;
	SSL_METHOD *meth;

	if (session != NULL)
		{
		meth=s->ctx->method->get_ssl_method(session->ssl_version);
		if (meth == NULL)
			meth=s->method->get_ssl_method(session->ssl_version);
		if (meth == NULL)
			{
			SSLerr(SSL_F_SSL_SET_SESSION,SSL_R_UNABLE_TO_FIND_SSL_METHOD);
			return(0);
			}

		if (meth != s->method)
			{
			if (!SSL_set_ssl_method(s,meth))
				return(0);
			if (s->ctx->session_timeout == 0)
				session->timeout=SSL_get_default_timeout(s);
			else
				session->timeout=s->ctx->session_timeout;
			}

		/* CRYPTO_w_lock(CRYPTO_LOCK_SSL);*/
		CRYPTO_add(&session->references,1,CRYPTO_LOCK_SSL_SESSION);
		if (s->session != NULL)
			SSL_SESSION_free(s->session);
		s->session=session;
		s->verify_result = s->session->verify_result;
		/* CRYPTO_w_unlock(CRYPTO_LOCK_SSL);*/
		ret=1;
		}
	else
		{
		if (s->session != NULL)
			{
			SSL_SESSION_free(s->session);
			s->session=NULL;
			}

		meth=s->ctx->method;
		if (meth != s->method)
			{
			if (!SSL_set_ssl_method(s,meth))
				return(0);
			}
		ret=1;
		}
	return(ret);
	}

long SSL_SESSION_set_timeout(SSL_SESSION *s, long t)
	{
	if (s == NULL) return(0);
	s->timeout=t;
	return(1);
	}

long SSL_SESSION_get_timeout(SSL_SESSION *s)
	{
	if (s == NULL) return(0);
	return(s->timeout);
	}

long SSL_SESSION_get_time(SSL_SESSION *s)
	{
	if (s == NULL) return(0);
	return(s->time);
	}

long SSL_SESSION_set_time(SSL_SESSION *s, long t)
	{
	if (s == NULL) return(0);
	s->time=t;
	return(t);
	}

long SSL_CTX_set_timeout(SSL_CTX *s, long t)
	{
	long l;
	if (s == NULL) return(0);
	l=s->session_timeout;
	s->session_timeout=t;
	return(l);
	}

long SSL_CTX_get_timeout(SSL_CTX *s)
	{
	if (s == NULL) return(0);
	return(s->session_timeout);
	}

typedef struct timeout_param_st
	{
	SSL_CTX *ctx;
	long time;
	LHASH *cache;
	} TIMEOUT_PARAM;

static void timeout(SSL_SESSION *s, TIMEOUT_PARAM *p)
	{
	if ((p->time == 0) || (p->time > (s->time+s->timeout))) /* timeout */
		{
		/* The reason we don't call SSL_CTX_remove_session() is to
		 * save on locking overhead */
		lh_delete(p->cache,s);
		SSL_SESSION_list_remove(p->ctx,s);
		s->not_resumable=1;
		if (p->ctx->remove_session_cb != NULL)
			p->ctx->remove_session_cb(p->ctx,s);
		SSL_SESSION_free(s);
		}
	}

void SSL_CTX_flush_sessions(SSL_CTX *s, long t)
	{
	unsigned long i;
	TIMEOUT_PARAM tp;

	tp.ctx=s;
	tp.cache=s->sessions;
	if (tp.cache == NULL) return;
	tp.time=t;
	CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
	i=tp.cache->down_load;
	tp.cache->down_load=0;
	lh_doall_arg(tp.cache,(void (*)())timeout,&tp);
	tp.cache->down_load=i;
	CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
	}

int ssl_clear_bad_session(SSL *s)
	{
	if (	(s->session != NULL) &&
		!(s->shutdown & SSL_SENT_SHUTDOWN) &&
		!(SSL_in_init(s) || SSL_in_before(s)))
		{
		SSL_CTX_remove_session(s->ctx,s->session);
		return(1);
		}
	else
		return(0);
	}

/* locked by SSL_CTX in the calling function */
static void SSL_SESSION_list_remove(SSL_CTX *ctx, SSL_SESSION *s)
	{
	if ((s->next == NULL) || (s->prev == NULL)) return;

	if (s->next == (SSL_SESSION *)&(ctx->session_cache_tail))
		{ /* last element in list */
		if (s->prev == (SSL_SESSION *)&(ctx->session_cache_head))
			{ /* only one element in list */
			ctx->session_cache_head=NULL;
			ctx->session_cache_tail=NULL;
			}
		else
			{
			ctx->session_cache_tail=s->prev;
			s->prev->next=(SSL_SESSION *)&(ctx->session_cache_tail);
			}
		}
	else
		{
		if (s->prev == (SSL_SESSION *)&(ctx->session_cache_head))
			{ /* first element in list */
			ctx->session_cache_head=s->next;
			s->next->prev=(SSL_SESSION *)&(ctx->session_cache_head);
			}
		else
			{ /* middle of list */
			s->next->prev=s->prev;
			s->prev->next=s->next;
			}
		}
	s->prev=s->next=NULL;
	}

static void SSL_SESSION_list_add(SSL_CTX *ctx, SSL_SESSION *s)
	{
	if ((s->next != NULL) && (s->prev != NULL))
		SSL_SESSION_list_remove(ctx,s);

	if (ctx->session_cache_head == NULL)
		{
		ctx->session_cache_head=s;
		ctx->session_cache_tail=s;
		s->prev=(SSL_SESSION *)&(ctx->session_cache_head);
		s->next=(SSL_SESSION *)&(ctx->session_cache_tail);
		}
	else
		{
		s->next=ctx->session_cache_head;
		s->next->prev=s;
		s->prev=(SSL_SESSION *)&(ctx->session_cache_head);
		ctx->session_cache_head=s;
		}
	}

