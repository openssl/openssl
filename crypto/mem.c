/* crypto/mem.c */
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
#include <stdlib.h>
#include <openssl/crypto.h>
#ifdef CRYPTO_MDEBUG_TIME
# include <time.h>	
#endif
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/lhash.h>
#include "cryptlib.h"

/* #ifdef CRYPTO_MDEBUG */
/* static int mh_mode=CRYPTO_MEM_CHECK_ON; */
/* #else */
static int mh_mode=CRYPTO_MEM_CHECK_OFF;
static unsigned long disabling_thread = 0;
/* #endif */
/* State CRYPTO_MEM_CHECK_ON exists only temporarily when the library
 * thinks that certain allocations should not be checked (e.g. the data
 * structures used for memory checking).  It is not suitable as an initial
 * state: the library will unexpectedly enable memory checking when it
 * executes one of those sections that want to disable checking
 * temporarily.
 *
 * State CRYPTO_MEM_CHECK_ENABLE without ..._ON makes no sense whatsoever.
 */

static unsigned long order=0;

static LHASH *amih=NULL;

typedef struct app_mem_info_st
	{	
	unsigned long thread;
	const char *file;
	int line;
	const char *info;
	struct app_mem_info_st *next;
	int references;
	} APP_INFO;

static LHASH *mh=NULL;

typedef struct mem_st
	{
	char *addr;
	int num;
	const char *file;
	int line;
#ifdef CRYPTO_MDEBUG_THREAD
	unsigned long thread;
#endif
	unsigned long order;
#ifdef CRYPTO_MDEBUG_TIME
	time_t time;
#endif
	APP_INFO *app_info;
	} MEM;

int CRYPTO_mem_ctrl(int mode)
	{
	int ret=mh_mode;

	CRYPTO_w_lock(CRYPTO_LOCK_MALLOC);
	switch (mode)
		{
	/* for applications: */
	case CRYPTO_MEM_CHECK_ON: /* aka MemCheck_start() */
		mh_mode = CRYPTO_MEM_CHECK_ON|CRYPTO_MEM_CHECK_ENABLE;
		disabling_thread = 0;
		break;
	case CRYPTO_MEM_CHECK_OFF: /* aka MemCheck_stop() */
		mh_mode = 0;
		disabling_thread = 0;
		break;

	/* switch off temporarily (for library-internal use): */
	case CRYPTO_MEM_CHECK_DISABLE: /* aka MemCheck_off() */
		if (mh_mode & CRYPTO_MEM_CHECK_ON)
			{
			mh_mode&= ~CRYPTO_MEM_CHECK_ENABLE;
			if (disabling_thread != CRYPTO_thread_id())
				{
				CRYPTO_w_lock(CRYPTO_LOCK_MALLOC2);
				disabling_thread=CRYPTO_thread_id();
				}
			}
		break;
	case CRYPTO_MEM_CHECK_ENABLE: /* aka MemCheck_on() */
		if (mh_mode & CRYPTO_MEM_CHECK_ON)
			{
			mh_mode|=CRYPTO_MEM_CHECK_ENABLE;
			if (disabling_thread != 0)
				{
				disabling_thread=0;
				CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC2);
				}
			}
		break;

	default:
		break;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC);
	return(ret);
	}

static int is_MemCheck_On()
	{
	int ret = 0;

	if (mh_mode & CRYPTO_MEM_CHECK_ON)
		{
		CRYPTO_w_lock(CRYPTO_LOCK_MALLOC);

		ret = (mh_mode & CRYPTO_MEM_CHECK_ENABLE)
			&& disabling_thread != CRYPTO_thread_id();

		CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC);
		}
	return(ret);
	}	

static int mem_cmp(MEM *a, MEM *b)
	{
	return(a->addr - b->addr);
	}

static unsigned long mem_hash(MEM *a)
	{
	unsigned long ret;

	ret=(unsigned long)a->addr;

	ret=ret*17851+(ret>>14)*7+(ret>>4)*251;
	return(ret);
	}

static int app_info_cmp(APP_INFO *a, APP_INFO *b)
	{
	return(a->thread - b->thread);
	}

static unsigned long app_info_hash(APP_INFO *a)
	{
	unsigned long ret;

	ret=(unsigned long)a->thread;

	ret=ret*17851+(ret>>14)*7+(ret>>4)*251;
	return(ret);
	}

static APP_INFO *free_info(APP_INFO *app_info)
	{
	APP_INFO *next;

	if (app_info == NULL)
		return NULL;

	if (--(app_info->references) > 0)
		return app_info;

	app_info->references = 0;

	next = app_info->next;
	app_info->next = NULL;	/* Just to make sure */

	Free(app_info);
	if (next != app_info)
		return free_info(next);
	return NULL;
	}
		
static APP_INFO *remove_info()
	{
	APP_INFO tmp;
	APP_INFO *ret = NULL;

	if (amih != NULL)
		{
		tmp.thread=CRYPTO_thread_id();
		if ((ret=(APP_INFO *)lh_delete(amih,(char *)&tmp)) != NULL)
			{
			APP_INFO *next=ret->next;
#ifdef LEVITTE_DEBUG
			if (ret->thread != tmp.thread)
				{
				fprintf(stderr, "remove_info(): deleted info has other thread ID (%lu) than the current thread (%lu)!!!!\n",
					ret->thread, tmp.thread);
				abort();
				}
#endif
			if (next != NULL)
				{
				lh_insert(amih,(char *)next);
				}
			free_info(ret);
			}
		}
	return(ret);
	}

int CRYPTO_add_info(const char *file, int line, const char *info)
	{
	APP_INFO *ami, *amim;
	int ret=0;

	if (is_MemCheck_On())
		{
		MemCheck_off();

		if ((ami = (APP_INFO *)Malloc(sizeof(APP_INFO))) == NULL)
			{
			ret=0;
			goto err;
			}
		if (amih == NULL)
			{
			if ((amih=lh_new(app_info_hash,app_info_cmp)) == NULL)
				{
				Free(ami);
				ret=0;
				goto err;
				}
			}

		ami->thread=CRYPTO_thread_id();
		ami->file=file;
		ami->line=line;
		ami->info=info;
		ami->references=1;
		ami->next=NULL;

		if ((amim=(APP_INFO *)lh_insert(amih,(char *)ami)) != NULL)
			{
#ifdef LEVITTE_DEBUG
			if (ami->thread != amim->thread)
				{
				fprintf(stderr, "CRYPTO_add_info(): previous info has other thread ID (%lu) than the current thread (%lu)!!!!\n",
					amim->thread, ami->thread);
				abort();
				}
#endif
			ami->next=amim;
			}
 err:
		MemCheck_on();
		}

	return(ret);
	}

int CRYPTO_remove_info()
	{
	int ret=0;

	if (is_MemCheck_On())
		{
		MemCheck_off();

		ret=(remove_info() != NULL);

		MemCheck_on();
		}
	return(ret);
	}

static char *(*malloc_locked_func)()=(char *(*)())malloc;
static void (*free_locked_func)()=(void (*)())free;
static char *(*malloc_func)()=	(char *(*)())malloc;
static char *(*realloc_func)()=	(char *(*)())realloc;
static void (*free_func)()=	(void (*)())free;

void CRYPTO_set_mem_functions(char *(*m)(), char *(*r)(), void (*f)())
	{
	if ((m == NULL) || (r == NULL) || (f == NULL)) return;
	malloc_func=m;
	realloc_func=r;
	free_func=f;
	malloc_locked_func=m;
	free_locked_func=f;
	}

void CRYPTO_set_locked_mem_functions(char *(*m)(), void (*f)())
	{
	if ((m == NULL) || (f == NULL)) return;
	malloc_locked_func=m;
	free_locked_func=f;
	}

void CRYPTO_get_mem_functions(char *(**m)(), char *(**r)(), void (**f)())
	{
	if (m != NULL) *m=malloc_func;
	if (r != NULL) *r=realloc_func;
	if (f != NULL) *f=free_func;
	}

void CRYPTO_get_locked_mem_functions(char *(**m)(), void (**f)())
	{
	if (m != NULL) *m=malloc_locked_func;
	if (f != NULL) *f=free_locked_func;
	}

void *CRYPTO_malloc_locked(int num)
	{
	return(malloc_locked_func(num));
	}

void CRYPTO_free_locked(void *str)
	{
	free_locked_func(str);
	}

void *CRYPTO_malloc(int num)
	{
	return(malloc_func(num));
	}

void *CRYPTO_realloc(void *str, int num)
	{
	return(realloc_func(str,num));
	}

void CRYPTO_free(void *str)
	{
	free_func(str);
	}

static unsigned long break_order_num=0;
void *CRYPTO_dbg_malloc(int num, const char *file, int line)
	{
	char *ret;
	MEM *m,*mm;
	APP_INFO tmp,*amim;

	if ((ret=malloc_func(num)) == NULL)
		return(NULL);

	if (is_MemCheck_On())
		{
		MemCheck_off();
		if ((m=(MEM *)Malloc(sizeof(MEM))) == NULL)
			{
			Free(ret);
			MemCheck_on();
			return(NULL);
			}
		if (mh == NULL)
			{
			if ((mh=lh_new(mem_hash,mem_cmp)) == NULL)
				{
				Free(ret);
				Free(m);
				ret=NULL;
				goto err;
				}
			}

		m->addr=ret;
		m->file=file;
		m->line=line;
		m->num=num;
#ifdef CRYPTO_MDEBUG_THREAD
		m->thread=CRYPTO_thread_id();
#endif
		if (order == break_order_num)
			{
			/* BREAK HERE */
			m->order=order;
			}
		m->order=order++;
#ifdef CRYPTO_MDEBUG_TIME
		m->time=time(NULL);
#endif

		tmp.thread=CRYPTO_thread_id();
		m->app_info=NULL;
		if (amih != NULL
		    && (amim=(APP_INFO *)lh_retrieve(amih,(char *)&tmp)) != NULL)
			{
			m->app_info = amim;
			amim->references++;
			}

		if ((mm=(MEM *)lh_insert(mh,(char *)m)) != NULL)
			{
			/* Not good, but don't sweat it */
			if (mm->app_info != NULL)
				{
				mm->app_info->references--;
				}
			Free(mm);
			}
err:
		MemCheck_on();
		}
	return(ret);
	}

void CRYPTO_dbg_free(void *addr)
	{
	MEM m,*mp;

	if (is_MemCheck_On() && (mh != NULL))
		{
		MemCheck_off();

		m.addr=addr;
		mp=(MEM *)lh_delete(mh,(char *)&m);
		if (mp != NULL)
			{
			if (mp->app_info != NULL)
				{
				mp->app_info->references--;
				}
			Free(mp);
			}

		MemCheck_on();
		}
	free_func(addr);
	}

void *CRYPTO_dbg_realloc(void *addr, int num, const char *file, int line)
	{
	char *ret;
	MEM m,*mp;

	ret=realloc_func(addr,num);
	if (ret == addr) return(ret);

	if (is_MemCheck_On())
		{
		if (ret == NULL) return(NULL);

		MemCheck_off();

		m.addr=addr;
		mp=(MEM *)lh_delete(mh,(char *)&m);
		if (mp != NULL)
			{
			mp->addr=ret;
			lh_insert(mh,(char *)mp);
			}

		MemCheck_on();
		}
	return(ret);
	}

void *CRYPTO_remalloc(void *a, int n)
	{
	if (a != NULL) Free(a);
	a=(char *)Malloc(n);
	return(a);
	}

void *CRYPTO_dbg_remalloc(void *a, int n, const char *file, int line)
	{
	if (a != NULL) CRYPTO_dbg_free(a);
	a=(char *)CRYPTO_dbg_malloc(n,file,line);
	return(a);
	}


typedef struct mem_leak_st
	{
	BIO *bio;
	int chunks;
	long bytes;
	} MEM_LEAK;

static void print_leak(MEM *m, MEM_LEAK *l)
	{
	char buf[128];
	APP_INFO *amip;
	int ami_cnt;
#ifdef CRYPTO_MDEBUG_TIME
	struct tm *lcl;
#endif
	unsigned long ti;

	if(m->addr == (char *)l->bio)
	    return;

#ifdef CRYPTO_MDEBUG_TIME
	lcl = localtime(&m->time);
#endif

	sprintf(buf,
#ifdef CRYPTO_MDEBUG_TIME
		"[%02d:%02d:%02d] "
#endif
		"%5lu file=%s, line=%d, "
#ifdef CRYPTO_MDEBUG_THREAD
		"thread=%lu, "
#endif
		"number=%d, address=%08lX\n",
#ifdef CRYPTO_MDEBUG_TIME
		lcl->tm_hour,lcl->tm_min,lcl->tm_sec,
#endif
		m->order,m->file,m->line,
#ifdef CRYPTO_MDEBUG_THREAD
		m->thread,
#endif
		m->num,(unsigned long)m->addr);

	BIO_puts(l->bio,buf);
	
	l->chunks++;
	l->bytes+=m->num;

	amip=m->app_info;
	ami_cnt=0;
	if (amip)
		ti=amip->thread;
	while(amip && amip->thread == ti)
		{
		int buf_len;
		int info_len;

		ami_cnt++;
		memset(buf,'>',ami_cnt);
		sprintf(buf + ami_cnt,
			"thread=%lu, file=%s, line=%d, info=\"",
			amip->thread, amip->file, amip->line);
		buf_len=strlen(buf);
		info_len=strlen(amip->info);
		if (128 - buf_len - 3 < info_len)
			{
			memcpy(buf + buf_len, amip->info, 128 - buf_len - 3);
			buf_len = 128 - 3;
			}
		else
			{
			strcpy(buf + buf_len, amip->info);
			buf_len = strlen(buf);
			}
		sprintf(buf + buf_len, "\"\n");
		
		BIO_puts(l->bio,buf);

		amip = amip->next;
		}
#ifdef LEVITTE_DEBUG
	if (amip)
		{
		fprintf(stderr, "Thread switch detected i backtrace!!!!\n");
		abort();
		}
#endif
	}

void CRYPTO_mem_leaks(BIO *b)
	{
	MEM_LEAK ml;
	char buf[80];

	if (mh == NULL) return;
	ml.bio=b;
	ml.bytes=0;
	ml.chunks=0;
	CRYPTO_w_lock(CRYPTO_LOCK_MALLOC2);
	lh_doall_arg(mh,(void (*)())print_leak,(char *)&ml);
	CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC2);
	if (ml.chunks != 0)
		{
		sprintf(buf,"%ld bytes leaked in %d chunks\n",
			ml.bytes,ml.chunks);
		BIO_puts(b,buf);
		}

#if 0
	lh_stats_bio(mh,b);
	lh_node_stats_bio(mh,b);
	lh_node_usage_stats_bio(mh,b);
#endif
	}

static void (*mem_cb)()=NULL;

static void cb_leak(MEM *m, char *cb)
	{
	void (*mem_callback)()=(void (*)())cb;
	mem_callback(m->order,m->file,m->line,m->num,m->addr);
	}

void CRYPTO_mem_leaks_cb(void (*cb)())
	{
	if (mh == NULL) return;
	CRYPTO_w_lock(CRYPTO_LOCK_MALLOC2);
	mem_cb=cb;
	lh_doall_arg(mh,(void (*)())cb_leak,(char *)mem_cb);
	mem_cb=NULL;
	CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC2);
	}

#ifndef NO_FP_API
void CRYPTO_mem_leaks_fp(FILE *fp)
	{
	BIO *b;

	if (mh == NULL) return;
	if ((b=BIO_new(BIO_s_file())) == NULL)
		return;
	BIO_set_fp(b,fp,BIO_NOCLOSE);
	CRYPTO_mem_leaks(b);
	BIO_free(b);
	}
#endif

