/* crypto/rsa/rsa.h */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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

#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "bn.h"

typedef struct rsa_meth_st
	{
	char *name;
	int (*rsa_pub_enc)();
	int (*rsa_pub_dec)();
	int (*rsa_priv_enc)();
	int (*rsa_priv_dec)();
	int (*rsa_mod_exp)();
	int (*bn_mod_exp)();
	int (*init)(/* RSA * */);	/* called at new */
	int (*finish)(/* RSA * */);	/* called at free */
	} RSA_METHOD;

typedef struct rsa_st
	{
	/* The first parameter is used to pickup errors where
	 * this is passed instead of aEVP_PKEY, it is set to 0 */
	int pad;
	int version;
	RSA_METHOD *meth;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;
	/* be carefull using this if the RSA structure is shared */
	char *app_data;
	int references;
	} RSA;

#define RSA_3	0x3L
#define RSA_F4	0x10001L

#define RSA_PKCS1_PADDING	11
#define RSA_SSLV23_PADDING	12

#ifndef NOPROTO
RSA *	RSA_new(void);
RSA *	RSA_new_method(RSA_METHOD *method);
int	RSA_size(RSA *);
RSA *	RSA_generate_key(int bits, unsigned long e,void
		(*callback)(int,int));
	/* next 4 return -1 on error */
int	RSA_public_encrypt(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa,int padding);
int	RSA_private_encrypt(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa,int padding);
int	RSA_public_decrypt(int flen, unsigned char *from, 
		unsigned char *to, RSA *rsa,int padding);
int	RSA_private_decrypt(int flen, unsigned char *from, 
		unsigned char *to, RSA *rsa,int padding);
void	RSA_free (RSA *r);

void RSA_set_default_method(RSA_METHOD *meth);

/* If you have RSAref compiled in. */
/* RSA_METHOD *RSA_PKCS1_RSAref(void); */

/* these are the actual SSLeay RSA functions */
RSA_METHOD *RSA_PKCS1_SSLeay(void);

void	ERR_load_RSA_strings(void );

RSA *	d2i_RSAPublicKey(RSA **a, unsigned char **pp, long length);
int	i2d_RSAPublicKey(RSA *a, unsigned char **pp);
RSA *	d2i_RSAPrivateKey(RSA **a, unsigned char **pp, long length);
int 	i2d_RSAPrivateKey(RSA *a, unsigned char **pp);
#ifndef WIN16
int	RSA_print_fp(FILE *fp, RSA *r,int offset);
#endif

#ifdef HEADER_BIO_H
int	RSA_print(BIO *bp, RSA *r,int offset);
#endif

int i2d_Netscape_RSA(RSA *a, unsigned char **pp, int (*cb)());
RSA *d2i_Netscape_RSA(RSA **a, unsigned char **pp, long length, int (*cb)());

/* The following 2 functions sign and verify a X509_SIG ASN1 object
 * inside PKCS#1 padded RSA encryption */
int RSA_sign(int type, unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify(int type, unsigned char *m, unsigned int m_len,
	unsigned char *sigbuf, unsigned int siglen, RSA *rsa);

/* The following 2 function sign and verify a ASN1_OCTET_STRING
 * object inside PKCS#1 padded RSA encryption */
int RSA_sign_ASN1_OCTET_STRING(int type, unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify_ASN1_OCTET_STRING(int type, unsigned char *m, unsigned int m_len,
	unsigned char *sigbuf, unsigned int siglen, RSA *rsa);

#else

RSA *	RSA_new();
RSA *	RSA_new_method();
int	RSA_size();
RSA *	RSA_generate_key();
int	RSA_public_encrypt();
int	RSA_private_encrypt();
int	RSA_public_decrypt();
int	RSA_private_decrypt();
void	RSA_free ();

void RSA_set_default_method();

/* RSA_METHOD *RSA_PKCS1_RSAref(); */
RSA_METHOD *RSA_PKCS1_SSLeay();

void	ERR_load_RSA_strings();

RSA *	d2i_RSAPublicKey();
int	i2d_RSAPublicKey();
RSA *	d2i_RSAPrivateKey();
int 	i2d_RSAPrivateKey();
#ifndef WIN16
int	RSA_print_fp();
#endif

int	RSA_print();

int i2d_Netscape_RSA();
RSA *d2i_Netscape_RSA();

int RSA_sign();
int RSA_verify();

int RSA_sign_ASN1_OCTET_STRING();
int RSA_verify_ASN1_OCTET_STRING();


#endif

/* BEGIN ERROR CODES */
/* Error codes for the RSA functions. */

/* Function codes. */
#define RSA_F_RSA_EAY_PRIVATE_DECRYPT			 100
#define RSA_F_RSA_EAY_PRIVATE_ENCRYPT			 101
#define RSA_F_RSA_EAY_PUBLIC_DECRYPT			 102
#define RSA_F_RSA_EAY_PUBLIC_ENCRYPT			 103
#define RSA_F_RSA_GENERATE_KEY				 104
#define RSA_F_RSA_NEW_METHOD				 105
#define RSA_F_RSA_PRINT					 106
#define RSA_F_RSA_PRINT_FP				 107
#define RSA_F_RSA_SIGN					 108
#define RSA_F_RSA_SIGN_ASN1_OCTET_STRING		 109
#define RSA_F_RSA_VERIFY				 110
#define RSA_F_RSA_VERIFY_ASN1_OCTET_STRING		 111

/* Reason codes. */
#define RSA_R_ALGORITHM_MISMATCH			 100
#define RSA_R_BAD_E_VALUE				 101
#define RSA_R_BAD_FIXED_HEADER_DECRYPT			 102
#define RSA_R_BAD_PAD_BYTE_COUNT			 103
#define RSA_R_BAD_SIGNATURE				 104
#define RSA_R_BLOCK_TYPE_IS_NOT_01			 105
#define RSA_R_BLOCK_TYPE_IS_NOT_02			 106
#define RSA_R_DATA_GREATER_THAN_MOD_LEN			 107
#define RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE		 108
#define RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY		 109
#define RSA_R_NULL_BEFORE_BLOCK_MISSING			 110
#define RSA_R_SSLV3_ROLLBACK_ATTACK			 111
#define RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 112
#define RSA_R_UNKNOWN_ALGORITHM_TYPE			 113
#define RSA_R_UNKNOWN_PADDING_TYPE			 114
#define RSA_R_WRONG_SIGNATURE_LENGTH			 115
 
#ifdef  __cplusplus
}
#endif
#endif

