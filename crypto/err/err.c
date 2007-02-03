/* crypto/err/err.c */
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
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/lhash.h>
#include <openssl/crypto.h>
#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>

static void err_load_strings(int lib, ERR_STRING_DATA *str);

static void ERR_STATE_free(ERR_STATE *s);

/* Define the predeclared (but externally opaque) "ERR_FNS" type */
struct st_ERR_FNS
	{
	/* Works on the "error_hash" string table */
	LHASH *(*cb_err_get)(int create);
	void (*cb_err_del)(void);
	ERR_STRING_DATA *(*cb_err_get_item)(const ERR_STRING_DATA *);
	ERR_STRING_DATA *(*cb_err_set_item)(ERR_STRING_DATA *);
	ERR_STRING_DATA *(*cb_err_del_item)(ERR_STRING_DATA *);
	/* Works on the "thread_hash" error-state table */
	LHASH *(*cb_thread_get)(int create);
	void (*cb_thread_release)(LHASH **hash);
	ERR_STATE *(*cb_thread_get_item)(const ERR_STATE *);
	ERR_STATE *(*cb_thread_set_item)(ERR_STATE *);
	void (*cb_thread_del_item)(const ERR_STATE *);
	/* Returns the next available error "library" numbers */
	int (*cb_get_next_lib)(void);
	};

/* Predeclarations of the "err_defaults" functions */
static LHASH *int_err_get(int create);
static void int_err_del(void);
static ERR_STRING_DATA *int_err_get_item(const ERR_STRING_DATA *);
static ERR_STRING_DATA *int_err_set_item(ERR_STRING_DATA *);
static ERR_STRING_DATA *int_err_del_item(ERR_STRING_DATA *);
static LHASH *int_thread_get(int create);
static void int_thread_release(LHASH **hash);
static ERR_STATE *int_thread_get_item(const ERR_STATE *);
static ERR_STATE *int_thread_set_item(ERR_STATE *);
static void int_thread_del_item(const ERR_STATE *);
static int int_err_get_next_lib(void);
/* The static ERR_FNS table using these defaults functions */
static const ERR_FNS err_defaults =
	{
	int_err_get,
	int_err_del,
	int_err_get_item,
	int_err_set_item,
	int_err_del_item,
	int_thread_get,
	int_thread_release,
	int_thread_get_item,
	int_thread_set_item,
	int_thread_del_item,
	int_err_get_next_lib
	};

/* The replacable table of ERR_FNS functions we use at run-time */
static const ERR_FNS *err_fns = NULL;

/* Eg. rather than using "err_get()", use "ERRFN(err_get)()". */
#define ERRFN(a) err_fns->cb_##a

/* The internal state used by "err_defaults" - as such, the setting, reading,
 * creating, and deleting of this data should only be permitted via the
 * "err_defaults" functions. This way, a linked module can completely defer all
 * ERR state operation (together with requisite locking) to the implementations
 * and state in the loading application. */
static LHASH *int_error_hash = NULL;
static LHASH *int_thread_hash = NULL;
static int int_thread_hash_references = 0;
static int int_err_library_number= ERR_LIB_USER;

/* Internal function that checks whether "err_fns" is set and if not, sets it to
 * the defaults. */
static void err_fns_check(void)
	{
	if (err_fns) return;
	
	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	if (!err_fns)
		err_fns = &err_defaults;
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
	}

/* API functions to get or set the underlying ERR functions. */

const ERR_FNS *ERR_get_implementation(void)
	{
	err_fns_check();
	return err_fns;
	}

int ERR_set_implementation(const ERR_FNS *fns)
	{
	int ret = 0;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	/* It's too late if 'err_fns' is non-NULL. BTW: not much point setting
	 * an error is there?! */
	if (!err_fns)
		{
		err_fns = fns;
		ret = 1;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
	return ret;
	}

/* These are the callbacks provided to "lh_new()" when creating the LHASH tables
 * internal to the "err_defaults" implementation. */

/* static unsigned long err_hash(ERR_STRING_DATA *a); */
static unsigned long err_hash(const void *a_void);
/* static int err_cmp(ERR_STRING_DATA *a, ERR_STRING_DATA *b); */
static int err_cmp(const void *a_void, const void *b_void);
/* static unsigned long pid_hash(ERR_STATE *pid); */
static unsigned long pid_hash(const void *pid_void);
/* static int pid_cmp(ERR_STATE *a,ERR_STATE *pid); */
static int pid_cmp(const void *a_void,const void *pid_void);
static unsigned long get_error_values(int inc,int top,const char **file,int *line,
				      const char **data,int *flags);

/* The internal functions used in the "err_defaults" implementation */

static LHASH *int_err_get(int create)
	{
	LHASH *ret = NULL;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	if (!int_error_hash && create)
		{
		CRYPTO_push_info("int_err_get (err.c)");
		int_error_hash = lh_new(err_hash, err_cmp);
		CRYPTO_pop_info();
		}
	if (int_error_hash)
		ret = int_error_hash;
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

	return ret;
	}

static void int_err_del(void)
	{
	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	if (int_error_hash)
		{
		lh_free(int_error_hash);
		int_error_hash = NULL;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
	}

static ERR_STRING_DATA *int_err_get_item(const ERR_STRING_DATA *d)
	{
	ERR_STRING_DATA *p;
	LHASH *hash;

	err_fns_check();
	hash = ERRFN(err_get)(0);
	if (!hash)
		return NULL;

	CRYPTO_r_lock(CRYPTO_LOCK_ERR);
	p = (ERR_STRING_DATA *)lh_retrieve(hash, d);
	CRYPTO_r_unlock(CRYPTO_LOCK_ERR);

	return p;
	}

static ERR_STRING_DATA *int_err_set_item(ERR_STRING_DATA *d)
	{
	ERR_STRING_DATA *p;
	LHASH *hash;

	err_fns_check();
	hash = ERRFN(err_get)(1);
	if (!hash)
		return NULL;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	p = (ERR_STRING_DATA *)lh_insert(hash, d);
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

	return p;
	}

static ERR_STRING_DATA *int_err_del_item(ERR_STRING_DATA *d)
	{
	ERR_STRING_DATA *p;
	LHASH *hash;

	err_fns_check();
	hash = ERRFN(err_get)(0);
	if (!hash)
		return NULL;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	p = (ERR_STRING_DATA *)lh_delete(hash, d);
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

	return p;
	}

static LHASH *int_thread_get(int create)
	{
	LHASH *ret = NULL;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	if (!int_thread_hash && create)
		{
		CRYPTO_push_info("int_thread_get (err.c)");
		int_thread_hash = lh_new(pid_hash, pid_cmp);
		CRYPTO_pop_info();
		}
	if (int_thread_hash)
		{
		int_thread_hash_references++;
		ret = int_thread_hash;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
	return ret;
	}

static void int_thread_release(LHASH **hash)
	{
	int i;

	if (hash == NULL || *hash == NULL)
		return;

	i = CRYPTO_add(&int_thread_hash_references, -1, CRYPTO_LOCK_ERR);

#ifdef REF_PRINT
	fprintf(stderr,"%4d:%s\n",int_thread_hash_references,"ERR");
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"int_thread_release, bad reference count\n");
		abort(); /* ok */
		}
#endif
	*hash = NULL;
	}

static ERR_STATE *int_thread_get_item(const ERR_STATE *d)
	{
	ERR_STATE *p;
	LHASH *hash;

	err_fns_check();
	hash = ERRFN(thread_get)(0);
	if (!hash)
		return NULL;

	CRYPTO_r_lock(CRYPTO_LOCK_ERR);
	p = (ERR_STATE *)lh_retrieve(hash, d);
	CRYPTO_r_unlock(CRYPTO_LOCK_ERR);

	ERRFN(thread_release)(&hash);
	return p;
	}

static ERR_STATE *int_thread_set_item(ERR_STATE *d)
	{
	ERR_STATE *p;
	LHASH *hash;

	err_fns_check();
	hash = ERRFN(thread_get)(1);
	if (!hash)
		return NULL;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	p = (ERR_STATE *)lh_insert(hash, d);
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

	ERRFN(thread_release)(&hash);
	return p;
	}

static void int_thread_del_item(const ERR_STATE *d)
	{
	ERR_STATE *p;
	LHASH *hash;

	err_fns_check();
	hash = ERRFN(thread_get)(0);
	if (!hash)
		return;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	p = (ERR_STATE *)lh_delete(hash, d);
	/* make sure we don't leak memory */
	if (int_thread_hash_references == 1
		&& int_thread_hash && (lh_num_items(int_thread_hash) == 0))
		{
		lh_free(int_thread_hash);
		int_thread_hash = NULL;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

	ERRFN(thread_release)(&hash);
	if (p)
		ERR_STATE_free(p);
	}

static int int_err_get_next_lib(void)
	{
	int ret;

	CRYPTO_w_lock(CRYPTO_LOCK_ERR);
	ret = int_err_library_number++;
	CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

	return ret;
	}


#define err_clear_data(p,i) \
	if (((p)->err_data[i] != NULL) && \
		(p)->err_data_flags[i] & ERR_TXT_MALLOCED) \
		{  \
		OPENSSL_free((p)->err_data[i]); \
		(p)->err_data[i]=NULL; \
		} \
	(p)->err_data_flags[i]=0;

static void ERR_STATE_free(ERR_STATE *s)
	{
	int i;

	if (s == NULL)
	    return;

	for (i=0; i<ERR_NUM_ERRORS; i++)
		{
		err_clear_data(s,i);
		}
	OPENSSL_free(s);
	}

static void err_load_strings(int lib, ERR_STRING_DATA *str)
	{
	while (str->error)
		{
		if (lib)
			str->error|=ERR_PACK(lib,0,0);
		ERRFN(err_set_item)(str);
		str++;
		}
	}

void ERR_load_strings(int lib, ERR_STRING_DATA *str)
	{
	err_fns_check();
	err_load_strings(lib, str);
	}

void ERR_unload_strings(int lib, ERR_STRING_DATA *str)
	{
	while (str->error)
		{
		if (lib)
			str->error|=ERR_PACK(lib,0,0);
		ERRFN(err_del_item)(str);
		str++;
		}
	}

void ERR_free_strings(void)
	{
	err_fns_check();
	ERRFN(err_del)();
	}

/********************************************************/

void ERR_put_error(int lib, int func, int reason, const char *file,
	     int line)
	{
	ERR_STATE *es;

#ifdef _OSD_POSIX
	/* In the BS2000-OSD POSIX subsystem, the compiler generates
	 * path names in the form "*POSIX(/etc/passwd)".
	 * This dirty hack strips them to something sensible.
	 * @@@ We shouldn't modify a const string, though.
	 */
	if (strncmp(file,"*POSIX(", sizeof("*POSIX(")-1) == 0) {
		char *end;

		/* Skip the "*POSIX(" prefix */
		file += sizeof("*POSIX(")-1;
		end = &file[strlen(file)-1];
		if (*end == ')')
			*end = '\0';
		/* Optional: use the basename of the path only. */
		if ((end = strrchr(file, '/')) != NULL)
			file = &end[1];
	}
#endif
	es=ERR_get_state();

	es->top=(es->top+1)%ERR_NUM_ERRORS;
	if (es->top == es->bottom)
		es->bottom=(es->bottom+1)%ERR_NUM_ERRORS;
	es->err_buffer[es->top]=ERR_PACK(lib,func,reason);
	es->err_file[es->top]=file;
	es->err_line[es->top]=line;
	err_clear_data(es,es->top);
	}

void ERR_clear_error(void)
	{
	int i;
	ERR_STATE *es;

	es=ERR_get_state();

	for (i=0; i<ERR_NUM_ERRORS; i++)
		{
		es->err_buffer[i]=0;
		err_clear_data(es,i);
		es->err_file[i]=NULL;
		es->err_line[i]= -1;
		}
	es->top=es->bottom=0;
	}


unsigned long ERR_get_error(void)
	{ return(get_error_values(1,0,NULL,NULL,NULL,NULL)); }

unsigned long ERR_get_error_line(const char **file,
	     int *line)
	{ return(get_error_values(1,0,file,line,NULL,NULL)); }

unsigned long ERR_get_error_line_data(const char **file, int *line,
	     const char **data, int *flags)
	{ return(get_error_values(1,0,file,line,data,flags)); }


unsigned long ERR_peek_error(void)
	{ return(get_error_values(0,0,NULL,NULL,NULL,NULL)); }

unsigned long ERR_peek_error_line(const char **file, int *line)
	{ return(get_error_values(0,0,file,line,NULL,NULL)); }

unsigned long ERR_peek_error_line_data(const char **file, int *line,
	     const char **data, int *flags)
	{ return(get_error_values(0,0,file,line,data,flags)); }


unsigned long ERR_peek_last_error(void)
	{ return(get_error_values(0,1,NULL,NULL,NULL,NULL)); }

unsigned long ERR_peek_last_error_line(const char **file, int *line)
	{ return(get_error_values(0,1,file,line,NULL,NULL)); }

unsigned long ERR_peek_last_error_line_data(const char **file, int *line,
	     const char **data, int *flags)
	{ return(get_error_values(0,1,file,line,data,flags)); }


static unsigned long get_error_values(int inc, int top, const char **file, int *line,
	     const char **data, int *flags)
	{	
	int i=0;
	ERR_STATE *es;
	unsigned long ret;

	es=ERR_get_state();

	if (inc && top)
		{
		if (file) *file = "";
		if (line) *line = 0;
		if (data) *data = "";
		if (flags) *flags = 0;
			
		return ERR_R_INTERNAL_ERROR;
		}

	if (es->bottom == es->top) return 0;
	if (top)
		i=es->top;			 /* last error */
	else
		i=(es->bottom+1)%ERR_NUM_ERRORS; /* first error */

	ret=es->err_buffer[i];
	if (inc)
		{
		es->bottom=i;
		es->err_buffer[i]=0;
		}

	if ((file != NULL) && (line != NULL))
		{
		if (es->err_file[i] == NULL)
			{
			*file="NA";
			if (line != NULL) *line=0;
			}
		else
			{
			*file=es->err_file[i];
			if (line != NULL) *line=es->err_line[i];
			}
		}

	if (data == NULL)
		{
		if (inc)
			{
			err_clear_data(es, i);
			}
		}
	else
		{
		if (es->err_data[i] == NULL)
			{
			*data="";
			if (flags != NULL) *flags=0;
			}
		else
			{
			*data=es->err_data[i];
			if (flags != NULL) *flags=es->err_data_flags[i];
			}
		}
	return ret;
	}

void ERR_error_string_n(unsigned long e, char *buf, size_t len)
	{
	char lsbuf[64], fsbuf[64], rsbuf[64];
	const char *ls,*fs,*rs;
	unsigned long l,f,r;

	l=ERR_GET_LIB(e);
	f=ERR_GET_FUNC(e);
	r=ERR_GET_REASON(e);

	ls=ERR_lib_error_string(e);
	fs=ERR_func_error_string(e);
	rs=ERR_reason_error_string(e);

	if (ls == NULL) 
		BIO_snprintf(lsbuf, sizeof(lsbuf), "lib(%lu)", l);
	if (fs == NULL)
		BIO_snprintf(fsbuf, sizeof(fsbuf), "func(%lu)", f);
	if (rs == NULL)
		BIO_snprintf(rsbuf, sizeof(rsbuf), "reason(%lu)", r);

	BIO_snprintf(buf, len,"error:%08lX:%s:%s:%s", e, ls?ls:lsbuf, 
		fs?fs:fsbuf, rs?rs:rsbuf);
	if (strlen(buf) == len-1)
		{
		/* output may be truncated; make sure we always have 5 
		 * colon-separated fields, i.e. 4 colons ... */
#define NUM_COLONS 4
		if (len > NUM_COLONS) /* ... if possible */
			{
			int i;
			char *s = buf;
			
			for (i = 0; i < NUM_COLONS; i++)
				{
				char *colon = strchr(s, ':');
				if (colon == NULL || colon > &buf[len-1] - NUM_COLONS + i)
					{
					/* set colon no. i at last possible position
					 * (buf[len-1] is the terminating 0)*/
					colon = &buf[len-1] - NUM_COLONS + i;
					*colon = ':';
					}
				s = colon + 1;
				}
			}
		}
	}

/* BAD for multi-threading: uses a local buffer if ret == NULL */
/* ERR_error_string_n should be used instead for ret != NULL
 * as ERR_error_string cannot know how large the buffer is */
char *ERR_error_string(unsigned long e, char *ret)
	{
	static char buf[256];

	if (ret == NULL) ret=buf;
	ERR_error_string_n(e, ret, 256);

	return ret;
	}

LHASH *ERR_get_string_table(void)
	{
	err_fns_check();
	return ERRFN(err_get)(0);
	}

LHASH *ERR_get_err_state_table(void)
	{
	err_fns_check();
	return ERRFN(thread_get)(0);
	}

void ERR_release_err_state_table(LHASH **hash)
	{
	err_fns_check();
	ERRFN(thread_release)(hash);
	}

const char *ERR_lib_error_string(unsigned long e)
	{
	ERR_STRING_DATA d,*p;
	unsigned long l;

	err_fns_check();
	l=ERR_GET_LIB(e);
	d.error=ERR_PACK(l,0,0);
	p=ERRFN(err_get_item)(&d);
	return((p == NULL)?NULL:p->string);
	}

const char *ERR_func_error_string(unsigned long e)
	{
	ERR_STRING_DATA d,*p;
	unsigned long l,f;

	err_fns_check();
	l=ERR_GET_LIB(e);
	f=ERR_GET_FUNC(e);
	d.error=ERR_PACK(l,f,0);
	p=ERRFN(err_get_item)(&d);
	return((p == NULL)?NULL:p->string);
	}

const char *ERR_reason_error_string(unsigned long e)
	{
	ERR_STRING_DATA d,*p=NULL;
	unsigned long l,r;

	err_fns_check();
	l=ERR_GET_LIB(e);
	r=ERR_GET_REASON(e);
	d.error=ERR_PACK(l,0,r);
	p=ERRFN(err_get_item)(&d);
	if (!p)
		{
		d.error=ERR_PACK(0,0,r);
		p=ERRFN(err_get_item)(&d);
		}
	return((p == NULL)?NULL:p->string);
	}

/* static unsigned long err_hash(ERR_STRING_DATA *a) */
static unsigned long err_hash(const void *a_void)
	{
	unsigned long ret,l;

	l=((ERR_STRING_DATA *)a_void)->error;
	ret=l^ERR_GET_LIB(l)^ERR_GET_FUNC(l);
	return(ret^ret%19*13);
	}

/* static int err_cmp(ERR_STRING_DATA *a, ERR_STRING_DATA *b) */
static int err_cmp(const void *a_void, const void *b_void)
	{
	return((int)(((ERR_STRING_DATA *)a_void)->error -
			((ERR_STRING_DATA *)b_void)->error));
	}

/* static unsigned long pid_hash(ERR_STATE *a) */
static unsigned long pid_hash(const void *a_void)
	{
	return(((ERR_STATE *)a_void)->pid*13);
	}

/* static int pid_cmp(ERR_STATE *a, ERR_STATE *b) */
static int pid_cmp(const void *a_void, const void *b_void)
	{
	return((int)((long)((ERR_STATE *)a_void)->pid -
			(long)((ERR_STATE *)b_void)->pid));
	}

void ERR_remove_state(unsigned long pid)
	{
	ERR_STATE tmp;

	err_fns_check();
	if (pid == 0)
		pid=(unsigned long)CRYPTO_thread_id();
	tmp.pid=pid;
	/* thread_del_item automatically destroys the LHASH if the number of
	 * items reaches zero. */
	ERRFN(thread_del_item)(&tmp);
	}

ERR_STATE *ERR_get_state(void)
	{
	static ERR_STATE fallback;
	ERR_STATE *ret,tmp,*tmpp=NULL;
	int i;
	unsigned long pid;

	err_fns_check();
	pid=(unsigned long)CRYPTO_thread_id();
	tmp.pid=pid;
	ret=ERRFN(thread_get_item)(&tmp);

	/* ret == the error state, if NULL, make a new one */
	if (ret == NULL)
		{
		ret=(ERR_STATE *)OPENSSL_malloc(sizeof(ERR_STATE));
		if (ret == NULL) return(&fallback);
		ret->pid=pid;
		ret->top=0;
		ret->bottom=0;
		for (i=0; i<ERR_NUM_ERRORS; i++)
			{
			ret->err_data[i]=NULL;
			ret->err_data_flags[i]=0;
			}
		tmpp = ERRFN(thread_set_item)(ret);
		/* To check if insertion failed, do a get. */
		if (ERRFN(thread_get_item)(ret) != ret)
			{
			ERR_STATE_free(ret); /* could not insert it */
			return(&fallback);
			}
		/* If a race occured in this function and we came second, tmpp
		 * is the first one that we just replaced. */
		if (tmpp)
			ERR_STATE_free(tmpp);
		}
	return ret;
	}

int ERR_get_next_error_library(void)
	{
	err_fns_check();
	return ERRFN(get_next_lib)();
	}

void ERR_set_error_data(char *data, int flags)
	{
	ERR_STATE *es;
	int i;

	es=ERR_get_state();

	i=es->top;
	if (i == 0)
		i=ERR_NUM_ERRORS-1;

	err_clear_data(es,i);
	es->err_data[i]=data;
	es->err_data_flags[i]=flags;
	}

void ERR_add_error_data(int num, ...)
	{
	va_list args;
	int i,n,s;
	char *str,*p,*a;

	s=80;
	str=OPENSSL_malloc(s+1);
	if (str == NULL) return;
	str[0]='\0';

	va_start(args, num);
	n=0;
	for (i=0; i<num; i++)
		{
		a=va_arg(args, char*);
		/* ignore NULLs, thanks to Bob Beck <beck@obtuse.com> */
		if (a != NULL)
			{
			n+=strlen(a);
			if (n > s)
				{
				s=n+20;
				p=OPENSSL_realloc(str,s+1);
				if (p == NULL)
					{
					OPENSSL_free(str);
					goto err;
					}
				else
					str=p;
				}
			BUF_strlcat(str,a,s+1);
			}
		}
	ERR_set_error_data(str,ERR_TXT_MALLOCED|ERR_TXT_STRING);

err:
	va_end(args);
	}
