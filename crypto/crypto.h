/* crypto/crypto.h */
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

#ifndef HEADER_CRYPTO_H
#define HEADER_CRYPTO_H

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef NO_FP_API
#include <stdio.h>
#endif

#include <openssl/stack.h>
#include <openssl/opensslv.h>

#ifdef CHARSET_EBCDIC
#include <openssl/ebcdic.h>
#endif

/* Backward compatibility to SSLeay */
/* This is more to be used to check the correct DLL is being used
 * in the MS world. */
#define SSLEAY_VERSION_NUMBER	OPENSSL_VERSION_NUMBER
#define SSLEAY_VERSION		0
/* #define SSLEAY_OPTIONS	1 no longer supported */
#define SSLEAY_CFLAGS		2
#define SSLEAY_BUILT_ON		3
#define SSLEAY_PLATFORM		4

/* When changing the CRYPTO_LOCK_* list, be sure to maintin the text lock
 * names in cryptlib.c
 */

#define	CRYPTO_LOCK_ERR			1
#define	CRYPTO_LOCK_ERR_HASH		2
#define	CRYPTO_LOCK_X509		3
#define	CRYPTO_LOCK_X509_INFO		4
#define	CRYPTO_LOCK_X509_PKEY		5
#define CRYPTO_LOCK_X509_CRL		6
#define CRYPTO_LOCK_X509_REQ		7
#define CRYPTO_LOCK_DSA			8
#define CRYPTO_LOCK_RSA			9
#define CRYPTO_LOCK_EVP_PKEY		10
#define	CRYPTO_LOCK_X509_STORE		11
#define	CRYPTO_LOCK_SSL_CTX		12
#define	CRYPTO_LOCK_SSL_CERT		13
#define	CRYPTO_LOCK_SSL_SESSION		14
#define	CRYPTO_LOCK_SSL_SESS_CERT	15
#define	CRYPTO_LOCK_SSL			16
#define	CRYPTO_LOCK_RAND		17
#define	CRYPTO_LOCK_MALLOC		18
#define	CRYPTO_LOCK_BIO			19
#define	CRYPTO_LOCK_GETHOSTBYNAME	20
#define	CRYPTO_LOCK_GETSERVBYNAME	21
#define	CRYPTO_LOCK_READDIR		22
#define	CRYPTO_LOCK_RSA_BLINDING	23
#define	CRYPTO_NUM_LOCKS		24

#define CRYPTO_LOCK		1
#define CRYPTO_UNLOCK		2
#define CRYPTO_READ		4
#define CRYPTO_WRITE		8

#ifndef NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_w_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_w_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_r_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#define CRYPTO_r_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#define CRYPTO_add(addr,amount,type)	\
	CRYPTO_add_lock(addr,amount,type,__FILE__,__LINE__)
#endif
#else
#define CRYPTO_w_lock(a)
#define	CRYPTO_w_unlock(a)
#define CRYPTO_r_lock(a)
#define CRYPTO_r_unlock(a)
#define CRYPTO_add(a,b,c)	((*(a))+=(b))
#endif

/* The following can be used to detect memory leaks in the SSLeay library.
 * It used, it turns on malloc checking */

#define CRYPTO_MEM_CHECK_OFF	0x0	/* an enume */
#define CRYPTO_MEM_CHECK_ON	0x1	/* a bit */
#define CRYPTO_MEM_CHECK_ENABLE	0x2	/* a bit */
#define CRYPTO_MEM_CHECK_DISABLE 0x3	/* an enume */

/*
typedef struct crypto_mem_st
	{
	char *(*malloc_func)();
	char *(*realloc_func)();
	void (*free_func)();
	} CRYPTO_MEM_FUNC;
*/

/* predec of the BIO type */
typedef struct bio_st BIO_dummy;

typedef struct crypto_ex_data_st
	{
	STACK *sk;
	int dummy; /* gcc is screwing up this data structure :-( */
	} CRYPTO_EX_DATA;

/* This stuff is basically class callback functions
 * The current classes are SSL_CTX, SSL, SSL_SESION, and a few more */
typedef struct crypto_ex_data_func_st
	{
	long argl;	/* Arbitary long */
	char *argp;	/* Arbitary char * */
	/* Called when a new object is created */
	int (*new_func)(/*char *obj,
			char *item,int index,long argl,char *argp*/);
	/* Called when this object is free()ed */
	void (*free_func)(/*char *obj,
			char *item,int index,long argl,char *argp*/);

	/* Called when we need to dup this one */
	int (*dup_func)(/*char *obj_to,char *obj_from,
			char **new,int index,long argl,char *argp*/);
	} CRYPTO_EX_DATA_FUNCS;

/* Per class, we have a STACK of CRYPTO_EX_DATA_FUNCS for each CRYPTO_EX_DATA
 * entry.
 */

#define CRYPTO_EX_INDEX_BIO		0
#define CRYPTO_EX_INDEX_SSL		1
#define CRYPTO_EX_INDEX_SSL_CTX		2
#define CRYPTO_EX_INDEX_SSL_SESSION	3
#define CRYPTO_EX_INDEX_X509_STORE	4
#define CRYPTO_EX_INDEX_X509_STORE_CTX	5

/* Use this for win32 DLL's */
#define CRYPTO_malloc_init()	CRYPTO_set_mem_functions(\
	(char *(*)())malloc,\
	(char *(*)())realloc,\
	(void (*)())free)

#ifdef CRYPTO_MDEBUG_ALL
# ifndef CRYPTO_MDEBUG_TIME
#  define CRYPTO_MDEBUG_TIME
# endif
# ifndef CRYPTO_MDEBUG_THREAD
#  define CRYPTO_MDEBUG_THREAD
# endif
#endif

#if defined CRYPTO_MDEBUG_TIME || defined CRYPTO_MDEBUG_THREAD
# ifndef CRYPTO_MDEBUG /* avoid duplicate #define */
#  define CRYPTO_MDEBUG
# endif
#endif

#ifdef CRYPTO_MDEBUG
#define MemCheck_start() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON)
#define MemCheck_stop()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF)
#define MemCheck_on()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE)
#define MemCheck_off()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE)
#define Malloc(num)	CRYPTO_dbg_malloc((int)num,__FILE__,__LINE__)
#define Realloc(addr,num) \
	CRYPTO_dbg_realloc((char *)addr,(int)num,__FILE__,__LINE__)
#define Remalloc(addr,num) \
	CRYPTO_dbg_remalloc((char **)addr,(int)num,__FILE__,__LINE__)
#define FreeFunc	CRYPTO_dbg_free
#define Free(addr)	CRYPTO_dbg_free(addr)
#define Malloc_locked(num) CRYPTO_malloc_locked((int)num)
#define Free_locked(addr) CRYPTO_free_locked(addr)
#else
#define MemCheck_start()
#define MemCheck_stop()
#define MemCheck_on()
#define MemCheck_off()
#define Remalloc	CRYPTO_remalloc
#if defined(WIN32) || defined(MFUNC)
#define Malloc		CRYPTO_malloc
#define Realloc(a,n)	CRYPTO_realloc(a,(n))
#define FreeFunc	CRYPTO_free
#define Free(addr)	CRYPTO_free(addr)
#define Malloc_locked	CRYPTO_malloc_locked
#define Free_locked(addr) CRYPTO_free_locked(addr)
#else
#define Malloc		malloc
#define Realloc		realloc
#define FreeFunc	free
#define Free(addr)	free(addr)
#define Malloc_locked	malloc
#define Free_locked(addr) free(addr)
#endif /* WIN32 || MFUNC */
#endif /* MDEBUG */

/* Case insensiteve linking causes problems.... */
#if defined(WIN16) || defined(VMS)
#define ERR_load_CRYPTO_strings	ERR_load_CRYPTOlib_strings
#endif


const char *SSLeay_version(int type);
unsigned long SSLeay(void);

int CRYPTO_get_ex_new_index(int idx,STACK **sk,long argl,char *argp,
	int (*new_func)(),int (*dup_func)(),void (*free_func)());
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad,int idx,char *val);
char *CRYPTO_get_ex_data(CRYPTO_EX_DATA *ad,int idx);
int CRYPTO_dup_ex_data(STACK *meth,CRYPTO_EX_DATA *from,CRYPTO_EX_DATA *to);
void CRYPTO_free_ex_data(STACK *meth,char *obj,CRYPTO_EX_DATA *ad);
void CRYPTO_new_ex_data(STACK *meth, char *obj, CRYPTO_EX_DATA *ad);

int CRYPTO_mem_ctrl(int mode);
int CRYPTO_get_new_lockid(char *name);

int CRYPTO_num_locks(void); /* return CRYPTO_NUM_LOCKS (shared libs!) */
void CRYPTO_lock(int mode, int type,const char *file,int line);
void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
					      const char *file,int line));
void (*CRYPTO_get_locking_callback(void))(int mode,int type,const char *file,
		int line);
void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,int type,
					      const char *file, int line));
int (*CRYPTO_get_add_lock_callback(void))(int *num,int mount,int type,
					  const char *file,int line);
void CRYPTO_set_id_callback(unsigned long (*func)(void));
unsigned long (*CRYPTO_get_id_callback(void))(void);
unsigned long CRYPTO_thread_id(void);
const char *CRYPTO_get_lock_name(int type);
int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file,
		    int line);

void CRYPTO_set_mem_functions(char *(*m)(),char *(*r)(), void (*free_func)());
void CRYPTO_get_mem_functions(char *(**m)(),char *(**r)(), void (**f)());
void CRYPTO_set_locked_mem_functions(char *(*m)(), void (*free_func)());
void CRYPTO_get_locked_mem_functions(char *(**m)(), void (**f)());

void *CRYPTO_malloc_locked(int num);
void CRYPTO_free_locked(void *);
void *CRYPTO_malloc(int num);
void CRYPTO_free(void *);
void *CRYPTO_realloc(void *addr,int num);
void *CRYPTO_remalloc(void *addr,int num);

void *CRYPTO_dbg_malloc(int num,const char *file,int line);
void *CRYPTO_dbg_realloc(void *addr,int num,const char *file,int line);
void CRYPTO_dbg_free(void *);
void *CRYPTO_dbg_remalloc(void *addr,int num,const char *file,int line);
#ifndef NO_FP_API
void CRYPTO_mem_leaks_fp(FILE *);
#endif
void CRYPTO_mem_leaks(struct bio_st *bio);
/* unsigned long order, char *file, int line, int num_bytes, char *addr */
void CRYPTO_mem_leaks_cb(void (*cb)());

void ERR_load_CRYPTO_strings(void );

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

/* Error codes for the CRYPTO functions. */

/* Function codes. */
#define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX		 100
#define CRYPTO_F_CRYPTO_GET_NEW_LOCKID			 101
#define CRYPTO_F_CRYPTO_SET_EX_DATA			 102

/* Reason codes. */

#ifdef  __cplusplus
}
#endif
#endif

