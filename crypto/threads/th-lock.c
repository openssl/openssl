/* crypto/threads/th-lock.c */
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
#include <string.h>
#include <errno.h>
#ifdef LINUX
#include <typedefs.h>
#endif
#ifdef WIN32
#include <windows.h>
#endif
#ifdef SOLARIS
#include <synch.h>
#include <thread.h>
#endif
#ifdef IRIX
#include <ulocks.h>
#include <sys/prctl.h>
#endif
#include "lhash.h"
#include "crypto.h"
#include "buffer.h"
#include "e_os.h"
#include "x509.h"
#include "ssl.h"
#include "err.h"

#ifndef NOPROTO
int CRYPTO_thread_setup(void);
void CRYPTO_thread_cleanup(void);

static void irix_locking_callback(int mode,int type,char *file,int line);
static void solaris_locking_callback(int mode,int type,char *file,int line);
static void win32_locking_callback(int mode,int type,char *file,int line);
static void pthreads_locking_callback(int mode,int type,char *file,int line);

static unsigned long irix_thread_id(void );
static unsigned long solaris_thread_id(void );
static unsigned long pthreads_thread_id(void );

#else
int CRYPOTO_thread_setup();
void CRYPTO_cleanup();

static void irix_locking_callback();
static void solaris_locking_callback();
static void win32_locking_callback();
static void pthreads_locking_callback();

static unsigned long irix_thread_id();
static unsigned long solaris_thread_id();
static unsigned long pthreads_thread_id();

#endif

/* usage:
 * CRYPTO_thread_setup();
 * applicaion code
 * CRYPTO_thread_cleanup();
 */

#define THREAD_STACK_SIZE (16*1024)

#ifdef WIN32

static HANDLE lock_cs[CRYPTO_NUM_LOCKS];

int CRYPTO_thread_setup()
	{
	int i;

	for (i=0; i<CRYPTO_NUM_LOCKS; i++)
		{
		lock_cs[i]=CreateMutex(NULL,FALSE,NULL);
		}

	CRYPTO_set_locking_callback((void (*)(int,int,char *,int))win32_locking_callback);
	/* id callback defined */
	return(1);
	}

static void CRYPTO_thread_cleanup()
	{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_NUM_LOCKS; i++)
		CloseHandle(lock_cs[i]);
	}

void win32_locking_callback(mode,type,file,line)
int mode;
int type;
char *file;
int line;
	{
	if (mode & CRYPTO_LOCK)
		{
		WaitForSingleObject(lock_cs[type],INFINITE);
		}
	else
		{
		ReleaseMutex(lock_cs[type]);
		}
	}

#endif /* WIN32 */

#ifdef SOLARIS

#define USE_MUTEX

static mutex_t lock_cs[CRYPTO_NUM_LOCKS];
#ifdef USE_MUTEX
static long lock_count[CRYPTO_NUM_LOCKS];
#else
static rwlock_t lock_cs[CRYPTO_NUM_LOCKS];
#endif

void CRYPTO_thread_setup()
	{
	int i;

	for (i=0; i<CRYPTO_NUM_LOCKS; i++)
		{
		lock_count[i]=0;
#ifdef USE_MUTEX
		mutex_init(&(lock_cs[i]),USYNC_THREAD,NULL);
#else
		rwlock_init(&(lock_cs[i]),USYNC_THREAD,NULL);
#endif
		}

	CRYPTO_set_id_callback((unsigned long (*)())solaris_thread_id);
	CRYPTO_set_locking_callback((void (*)())solaris_locking_callback);
	}

void CRYPTO_thread_cleanup()
	{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_NUM_LOCKS; i++)
		{
#ifdef USE_MUTEX
		mutex_destroy(&(lock_cs[i]));
#else
		rwlock_destroy(&(lock_cs[i]));
#endif
		}
	}

void solaris_locking_callback(mode,type,file,line)
int mode;
int type;
char *file;
int line;
	{
#if 0
	fprintf(stderr,"thread=%4d mode=%s lock=%s %s:%d\n",
		CRYPTO_thread_id(),
		(mode&CRYPTO_LOCK)?"l":"u",
		(type&CRYPTO_READ)?"r":"w",file,line);
#endif

#if 0
	if (CRYPTO_LOCK_SSL_CERT == type)
		fprintf(stderr,"(t,m,f,l) %ld %d %s %d\n",
			CRYPTO_thread_id(),
			mode,file,line);
#endif
	if (mode & CRYPTO_LOCK)
		{
#ifdef USE_MUTEX
		mutex_lock(&(lock_cs[type]));
#else
		if (mode & CRYPTO_READ)
			rw_rdlock(&(lock_cs[type]));
		else
			rw_wrlock(&(lock_cs[type]));
#endif
		lock_count[type]++;
		}
	else
		{
#ifdef USE_MUTEX
		mutex_unlock(&(lock_cs[type]));
#else
		rw_unlock(&(lock_cs[type]));
#endif
		}
	}

unsigned long solaris_thread_id()
	{
	unsigned long ret;

	ret=(unsigned long)thr_self();
	return(ret);
	}
#endif /* SOLARIS */

#ifdef IRIX
/* I don't think this works..... */

static usptr_t *arena;
static usema_t *lock_cs[CRYPTO_NUM_LOCKS];

void CRYPTO_thread_setup()
	{
	int i;
	char filename[20];

	strcpy(filename,"/tmp/mttest.XXXXXX");
	mktemp(filename);

	usconfig(CONF_STHREADIOOFF);
	usconfig(CONF_STHREADMALLOCOFF);
	usconfig(CONF_INITUSERS,100);
	usconfig(CONF_LOCKTYPE,US_DEBUGPLUS);
	arena=usinit(filename);
	unlink(filename);

	for (i=0; i<CRYPTO_NUM_LOCKS; i++)
		{
		lock_cs[i]=usnewsema(arena,1);
		}

	CRYPTO_set_id_callback((unsigned long (*)())irix_thread_id);
	CRYPTO_set_locking_callback((void (*)())irix_locking_callback);
	}

void CRYPTO_thread_cleanup()
	{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_NUM_LOCKS; i++)
		{
		char buf[10];

		sprintf(buf,"%2d:",i);
		usdumpsema(lock_cs[i],stdout,buf);
		usfreesema(lock_cs[i],arena);
		}
	}

void irix_locking_callback(mode,type,file,line)
int mode;
int type;
char *file;
int line;
	{
	if (mode & CRYPTO_LOCK)
		{
		uspsema(lock_cs[type]);
		}
	else
		{
		usvsema(lock_cs[type]);
		}
	}

unsigned long irix_thread_id()
	{
	unsigned long ret;

	ret=(unsigned long)getpid();
	return(ret);
	}
#endif /* IRIX */

/* Linux and a few others */
#ifdef PTHREADS

static pthread_mutex_t lock_cs[CRYPTO_NUM_LOCKS];
static long lock_count[CRYPTO_NUM_LOCKS];

void CRYPTO_thread_setup()
	{
	int i;

	for (i=0; i<CRYPTO_NUM_LOCKS; i++)
		{
		lock_count[i]=0;
		pthread_mutex_init(&(lock_cs[i]),NULL);
		}

	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
	}

void thread_cleanup()
	{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_NUM_LOCKS; i++)
		{
		pthread_mutex_destroy(&(lock_cs[i]));
		}
	}

void pthreads_locking_callback(mode,type,file,line)
int mode;
int type;
char *file;
int line;
      {
#if 0
	fprintf(stderr,"thread=%4d mode=%s lock=%s %s:%d\n",
		CRYPTO_thread_id(),
		(mode&CRYPTO_LOCK)?"l":"u",
		(type&CRYPTO_READ)?"r":"w",file,line);
#endif
#if 0
	if (CRYPTO_LOCK_SSL_CERT == type)
		fprintf(stderr,"(t,m,f,l) %ld %d %s %d\n",
		CRYPTO_thread_id(),
		mode,file,line);
#endif
	if (mode & CRYPTO_LOCK)
		{
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
		}
	else
		{
		pthread_mutex_unlock(&(lock_cs[type]));
		}
	}

unsigned long pthreads_thread_id()
	{
	unsigned long ret;

	ret=(unsigned long)pthread_self();
	return(ret);
	}

#endif /* PTHREADS */

