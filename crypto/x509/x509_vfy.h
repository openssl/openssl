/* crypto/x509/x509_vfy.h */
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

#ifndef HEADER_X509_VFY_H
#define HEADER_X509_VFY_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "bio.h"
#include "crypto.h"

/* Outer object */
typedef struct x509_hash_dir_st
	{
	int num_dirs;
	char **dirs;
	int *dirs_type;
	int num_dirs_alloced;
	} X509_HASH_DIR_CTX;

typedef struct x509_file_st
	{
	int num_paths;	/* number of paths to files or directories */
	int num_alloced;
	char **paths;	/* the list of paths or directories */
	int *path_type;
	} X509_CERT_FILE_CTX;

/*******************************/
/*
SSL_CTX -> X509_STORE    
		-> X509_LOOKUP
			->X509_LOOKUP_METHOD
		-> X509_LOOKUP
			->X509_LOOKUP_METHOD
 
SSL	-> X509_STORE_CTX
		->X509_STORE    

The X509_STORE holds the tables etc for verification stuff.
A X509_STORE_CTX is used while validating a single certificate.
The X509_STORE has X509_LOOKUPs for looking up certs.
The X509_STORE then calls a function to actually verify the
certificate chain.
*/

#define X509_LU_RETRY		-1
#define X509_LU_FAIL		0
#define X509_LU_X509		1
#define X509_LU_CRL		2
#define X509_LU_PKEY		3

typedef struct x509_object_st
	{
	/* one of the above types */
	int type;
	union	{
		char *ptr;
		X509 *x509;
		X509_CRL *crl;
		EVP_PKEY *pkey;
		} data;
	} X509_OBJECT;

/* This is a static that defines the function interface */
typedef struct x509_lookup_method_st
	{
	char *name;
	int (*new_item)();
	void (*free)();
	int (*init)(/* meth, char ** */);
	int (*shutdown)( /* meth, char ** */);
	int (*ctrl)( /* meth, char **, int cmd, char *argp, int argi */);
	int (*get_by_subject)(/* meth, char **, XNAME *, X509 **ret */);
	int (*get_by_issuer_serial)();
	int (*get_by_fingerprint)();
	int (*get_by_alias)();
	} X509_LOOKUP_METHOD;

/* This is used to hold everything.  It is used for all certificate
 * validation.  Once we have a certificate chain, the 'verify'
 * function is then called to actually check the cert chain. */
typedef struct x509_store_st
	{
	/* The following is a cache of trusted certs */
	int cache; 	/* if true, stash any hits */
#ifdef HEADER_LHASH_H
	LHASH *certs;	/* cached certs; */ 
#else
	char *certs;
#endif

	/* These are external lookup methods */
	STACK *get_cert_methods;/* X509_LOOKUP */
	int (*verify)();	/* called to verify a certificate */
	int (*verify_cb)();	/* error callback */

	CRYPTO_EX_DATA ex_data;
	int references;
	int depth;		/* how deep to look */
	}  X509_STORE;

#define X509_STORE_set_depth(ctx,d)       ((ctx)->depth=(d))

#define X509_STORE_set_verify_cb_func(ctx,func) ((ctx)->verify_cb=(func))
#define X509_STORE_set_verify_func(ctx,func)	((ctx)->verify=(func))

/* This is the functions plus an instance of the local variables. */
typedef struct x509_lookup_st
	{
	int init;			/* have we been started */
	int skip;			/* don't use us. */
	X509_LOOKUP_METHOD *method;	/* the functions */
	char *method_data;		/* method data */

	X509_STORE *store_ctx;	/* who owns us */
	} X509_LOOKUP;

/* This is a temporary used when processing cert chains.  Since the
 * gathering of the cert chain can take some time (and have to be
 * 'retried', this needs to be kept and passed around. */
typedef struct x509_store_state_st
	{
	X509_STORE *ctx;
	int current_method;	/* used when looking up certs */

	/* The following are set by the caller */
	X509 *cert;		/* The cert to check */
	STACK *untrusted;	/* chain of X509s - untrusted - passed in */

	/* The following is built up */
	int depth;		/* how far to go looking up certs */
	int valid;		/* if 0, rebuild chain */
	int last_untrusted;	/* index of last untrusted cert */
	STACK *chain; 		/* chain of X509s - built up and trusted */

	/* When something goes wrong, this is why */
	int error_depth;
	int error;
	X509 *current_cert;

	CRYPTO_EX_DATA ex_data;
	} X509_STORE_CTX;

#define X509_STORE_CTX_set_app_data(ctx,data) \
	X509_STORE_CTX_set_ex_data(ctx,0,data)
#define X509_STORE_CTX_get_app_data(ctx) \
	X509_STORE_CTX_get_ex_data(ctx,0)

#define X509_L_FILE_LOAD	1
#define X509_L_ADD_DIR		2

X509_LOOKUP_METHOD *X509_LOOKUP_file();
#define X509_LOOKUP_load_file(x,name,type) \
		X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(long)(type),NULL)

X509_LOOKUP_METHOD *X509_LOOKUP_dir();
#define X509_LOOKUP_add_dir(x,name,type) \
		X509_LOOKUP_ctrl((x),X509_L_ADD_DIR,(name),(long)(type),NULL)

#define		X509_V_OK					0

#define		X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT		2
#define		X509_V_ERR_UNABLE_TO_GET_CRL			3
#define		X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE	4
#define		X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE	5
#define		X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY	6
#define		X509_V_ERR_CERT_SIGNATURE_FAILURE		7
#define		X509_V_ERR_CRL_SIGNATURE_FAILURE		8
#define		X509_V_ERR_CERT_NOT_YET_VALID			9	
#define		X509_V_ERR_CERT_HAS_EXPIRED			10
#define		X509_V_ERR_CRL_NOT_YET_VALID			11
#define		X509_V_ERR_CRL_HAS_EXPIRED			12
#define		X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD	13
#define		X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD	14
#define		X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD	15
#define		X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD	16
#define		X509_V_ERR_OUT_OF_MEM				17
#define		X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT		18
#define		X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN		19
#define		X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY	20
#define		X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE	21
#define		X509_V_ERR_CERT_CHAIN_TOO_LONG			22
#define		X509_V_ERR_CERT_REVOKED				23

/* The application is not happy */
#define		X509_V_ERR_APPLICATION_VERIFICATION		50

#ifndef NOPROTO
#ifdef HEADER_LHASH_H
X509_OBJECT *X509_OBJECT_retrive_by_subject(LHASH *h,int type,X509_NAME *name);
#endif
void X509_OBJECT_up_ref_count(X509_OBJECT *a);
void X509_OBJECT_free_contents(X509_OBJECT *a);
X509_STORE *X509_STORE_new(void );
void X509_STORE_free(X509_STORE *v);

void X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
	X509 *x509, STACK *chain);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m);

X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void);
X509_LOOKUP_METHOD *X509_LOOKUP_file(void);

int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x);

int X509_STORE_get_by_subject(X509_STORE_CTX *vs,int type,X509_NAME *name,
	X509_OBJECT *ret);

int X509_LOOKUP_ctrl(X509_LOOKUP *ctx,int cmd,char *argc,long argl,char **ret);

#ifndef NO_STDIO
int X509_load_cert_file(X509_LOOKUP *ctx, char *file, int type);
int X509_load_crl_file(X509_LOOKUP *ctx, char *file, int type);
#endif

void X509v3_cleanup_extensions(void );
int X509v3_add_extension(X509_EXTENSION_METHOD *x);
int X509v3_add_netscape_extensions(void );
int X509v3_add_standard_extensions(void );

X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method);
void X509_LOOKUP_free(X509_LOOKUP *ctx);
int X509_LOOKUP_init(X509_LOOKUP *ctx);
int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name,
	X509_OBJECT *ret);
int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, int type, X509_NAME *name,
	ASN1_INTEGER *serial, X509_OBJECT *ret);
int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, int type,
	unsigned char *bytes, int len, X509_OBJECT *ret);
int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, int type, char *str,
	int len, X509_OBJECT *ret);
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);

#ifndef NO_STDIO
int	X509_STORE_load_locations (X509_STORE *ctx,
		char *file, char *dir);
int	X509_STORE_set_default_paths(X509_STORE *ctx);
#endif

int X509_STORE_CTX_get_ex_new_index(long argl, char *argp, int (*new_func)(),
	int (*dup_func)(), void (*free_func)());
int	X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx,int idx,char *data);
char *	X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx,int idx);
int	X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
void	X509_STORE_CTX_set_error(X509_STORE_CTX *ctx,int s);
int	X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
X509 *	X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
STACK *	X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx);
void	X509_STORE_CTX_set_cert(X509_STORE_CTX *c,X509 *x);
void	X509_STORE_CTX_set_chain(X509_STORE_CTX *c,STACK /* X509 */ *sk);

#else

#ifdef HEADER_LHASH_H
X509_OBJECT *X509_OBJECT_retrive_by_subject();
#endif
void X509_OBJECT_up_ref_count();
void X509_OBJECT_free_contents();
X509_STORE *X509_STORE_new();
void X509_STORE_free();

void X509_STORE_CTX_init();
void X509_STORE_CTX_cleanup();

X509_LOOKUP *X509_STORE_add_lookup();

X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir();
X509_LOOKUP_METHOD *X509_LOOKUP_file();

int X509_STORE_add_cert();
int X509_STORE_add_crl();

int X509_STORE_get_by_subject();

int X509_LOOKUP_ctrl();

#ifndef NO_STDIO
int X509_load_cert_file();
int X509_load_crl_file();
#endif

void X509v3_cleanup_extensions();
int X509v3_add_extension();
int X509v3_add_netscape_extensions();
int X509v3_add_standard_extensions();

X509_LOOKUP *X509_LOOKUP_new();
void X509_LOOKUP_free();
int X509_LOOKUP_init();
int X509_LOOKUP_by_subject();
int X509_LOOKUP_by_issuer_serial();
int X509_LOOKUP_by_fingerprint();
int X509_LOOKUP_by_alias();
int X509_LOOKUP_shutdown();

#ifndef NO_STDIO
int	X509_STORE_load_locations ();
int	X509_STORE_set_default_paths();
#endif

int	X509_STORE_CTX_set_ex_data();
char *	X509_STORE_CTX_get_ex_data();
int	X509_STORE_CTX_get_error();
void	X509_STORE_CTX_set_error();
int	X509_STORE_CTX_get_error_depth();
X509 *	X509_STORE_CTX_get_current_cert();
STACK *	X509_STORE_CTX_get_chain();
void	X509_STORE_CTX_set_cert();
void	X509_STORE_CTX_set_chain();

#endif

#ifdef  __cplusplus
}
#endif
#endif

